//! Async TDLib client: one receive thread dispatches responses (by `@extra`),
//! message-send confirmations and authorization updates.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{oneshot, watch};

use super::ffi::TdJson;

#[derive(Debug, Clone)]
pub struct TdError {
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for TdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TDLib {}: {}", self.code, self.message)
    }
}

impl std::error::Error for TdError {}

impl TdError {
    fn from_value(v: &Value) -> Self {
        Self {
            code: v.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: v.get("message").and_then(Value::as_str).unwrap_or("TDLib request failed").to_string(),
        }
    }

    /// Seconds from "Too Many Requests: retry after N".
    pub fn retry_after(&self) -> Option<u64> {
        if self.code != 429 {
            return None;
        }
        self.message.rsplit(' ').next().and_then(|n| n.parse().ok()).or(Some(30))
    }
}

/// `runtime/telegram.json` (mode 0600).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub api_id: i64,
    pub api_hash: String,
    pub database_encryption_key: String,
    #[serde(default)]
    pub bot_token: Option<String>,
}

impl Credentials {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let creds: Self = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        anyhow::ensure!(creds.api_id > 0, "api_id missing");
        anyhow::ensure!(
            creds.api_hash.len() == 32 && creds.api_hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "api_hash must be 32 hex digits"
        );
        base64::engine::general_purpose::STANDARD
            .decode(&creds.database_encryption_key)
            .context("database_encryption_key must be base64")?;
        Ok(creds)
    }

    pub fn new_key() -> String {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("json.tmp");
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        file.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

type SendResult = std::result::Result<Value, TdError>;

#[derive(Default)]
struct SendTracker {
    waiters: HashMap<(i64, i64), oneshot::Sender<SendResult>>,
    /// Confirmations that arrived before anyone waited for them.
    early: HashMap<(i64, i64), SendResult>,
}

pub struct TdClient {
    td: &'static TdJson,
    client_id: i32,
    seq: AtomicU64,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    sends: Mutex<SendTracker>,
    auth: watch::Receiver<String>,
}

impl TdClient {
    pub fn start(library: &Path, verbosity: u8) -> Result<Arc<Self>> {
        // Loaded once and never unloaded: TDLib's threads outlive any client,
        // and dlclose() under them crashes the process.
        let td: &'static TdJson = Box::leak(Box::new(TdJson::load(library)?));
        td.execute(&json!({"@type": "setLogVerbosityLevel", "new_verbosity_level": verbosity}).to_string());
        let client_id = td.create_client_id();
        let (auth_tx, auth_rx) = watch::channel(String::new());
        let client = Arc::new(Self {
            td,
            client_id,
            seq: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
            sends: Mutex::new(SendTracker::default()),
            auth: auth_rx,
        });
        let weak = Arc::downgrade(&client);
        std::thread::Builder::new().name("tdlib-receive".into()).spawn(move || {
            loop {
                let Some(raw) = td.receive(1.0) else {
                    if weak.strong_count() == 0 {
                        return;
                    }
                    continue;
                };
                let Some(client) = weak.upgrade() else { return };
                let Ok(event) = serde_json::from_str::<Value>(&raw) else { continue };
                if event.get("@client_id").and_then(Value::as_i64) != Some(i64::from(client_id)) {
                    continue;
                }
                client.dispatch(event, &auth_tx);
            }
        })?;
        Ok(client)
    }

    fn dispatch(&self, event: Value, auth_tx: &watch::Sender<String>) {
        if let Some(extra) = event.get("@extra").and_then(Value::as_str) {
            if let Some(tx) = self.pending.lock().unwrap().remove(extra) {
                let _ = tx.send(event);
                return;
            }
        }
        match event.get("@type").and_then(Value::as_str).unwrap_or("") {
            "updateAuthorizationState" => {
                let state = event["authorization_state"]["@type"].as_str().unwrap_or("").to_string();
                tracing::debug!("TDLib authorization state: {state}");
                auth_tx.send_replace(state);
            }
            kind @ ("updateMessageSendSucceeded" | "updateMessageSendFailed") => {
                let chat_id = event["message"]["chat_id"].as_i64().unwrap_or(0);
                let old_id = event["old_message_id"].as_i64().unwrap_or(0);
                let result = if kind == "updateMessageSendSucceeded" {
                    Ok(event["message"].clone())
                } else {
                    Err(TdError::from_value(&event["error"]))
                };
                let mut sends = self.sends.lock().unwrap();
                match sends.waiters.remove(&(chat_id, old_id)) {
                    Some(tx) => {
                        let _ = tx.send(result);
                    }
                    None => {
                        if sends.early.len() > 256 {
                            sends.early.clear();
                        }
                        sends.early.insert((chat_id, old_id), result);
                    }
                }
            }
            _ => {}
        }
    }

    pub async fn request(&self, request: Value) -> std::result::Result<Value, TdError> {
        self.request_timeout(request, Duration::from_secs(60)).await
    }

    pub async fn request_timeout(&self, mut request: Value, timeout: Duration) -> std::result::Result<Value, TdError> {
        let extra = self.seq.fetch_add(1, Ordering::Relaxed).to_string();
        request["@extra"] = Value::String(extra.clone());
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(extra.clone(), tx);
        self.td.send(self.client_id, &request.to_string());
        let result = tokio::time::timeout(timeout, rx).await;
        self.pending.lock().unwrap().remove(&extra);
        match result {
            Ok(Ok(v)) if v["@type"] == "error" => Err(TdError::from_value(&v)),
            Ok(Ok(v)) => Ok(v),
            Ok(Err(_)) => Err(TdError { code: -1, message: "TDLib receiver closed".into() }),
            Err(_) => Err(TdError { code: -2, message: "TDLib request timed out".into() }),
        }
    }

    /// Wait for the final state of an outgoing message (TDLib returns a
    /// temporary message immediately and confirms after the upload).
    pub async fn wait_sent(&self, chat_id: i64, temp_id: i64, timeout: Duration) -> std::result::Result<Value, TdError> {
        let rx = {
            let mut sends = self.sends.lock().unwrap();
            if let Some(result) = sends.early.remove(&(chat_id, temp_id)) {
                return result;
            }
            let (tx, rx) = oneshot::channel();
            sends.waiters.insert((chat_id, temp_id), tx);
            rx
        };
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(TdError { code: -1, message: "TDLib receiver closed".into() }),
            Err(_) => {
                self.sends.lock().unwrap().waiters.remove(&(chat_id, temp_id));
                Err(TdError { code: -2, message: "upload confirmation timed out".into() })
            }
        }
    }

    pub fn auth_state(&self) -> watch::Receiver<String> {
        self.auth.clone()
    }

    /// Drive the authorization state machine to `authorizationStateReady`.
    pub async fn authorize(&self, creds: &Credentials, database_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(database_dir)?;
        let mut auth = self.auth.clone();
        // TDLib only starts emitting updates once it receives a request.
        let _ = self.request(json!({"@type": "getOption", "name": "version"})).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let state = auth.borrow_and_update().clone();
            match state.as_str() {
                "" => {}
                "authorizationStateWaitTdlibParameters" => {
                    let files: PathBuf = database_dir.join("files");
                    self.request(json!({
                        "@type": "setTdlibParameters",
                        "use_test_dc": false,
                        "database_directory": database_dir,
                        "files_directory": files,
                        "database_encryption_key": creds.database_encryption_key,
                        // No message/chat/file databases: TDLib would otherwise
                        // resend unconfirmed messages after a restart, while the
                        // job sidecars already make posting resumable.
                        "use_file_database": false,
                        "use_chat_info_database": false,
                        "use_message_database": false,
                        "use_secret_chats": false,
                        "api_id": creds.api_id,
                        "api_hash": creds.api_hash,
                        "system_language_code": "en",
                        "device_model": "fwdonor",
                        "system_version": "Linux",
                        "application_version": env!("CARGO_PKG_VERSION"),
                    }))
                    .await
                    .map_err(|e| anyhow!("setTdlibParameters: {e}"))?;
                }
                "authorizationStateWaitPhoneNumber" => {
                    let token = creds
                        .bot_token
                        .as_deref()
                        .filter(|t| !t.is_empty())
                        .ok_or_else(|| anyhow!("not logged in: run `fwdonor login`"))?;
                    self.request(json!({"@type": "checkAuthenticationBotToken", "token": token}))
                        .await
                        .map_err(|e| anyhow!("bot token rejected: {e}"))?;
                }
                "authorizationStateReady" => return Ok(()),
                "authorizationStateClosed" | "authorizationStateClosing" | "authorizationStateLoggingOut" => {
                    bail!("TDLib session closed ({state})")
                }
                other => bail!("unexpected authorization state {other}: fwdonor only supports bot logins"),
            }
            if tokio::time::timeout_at(deadline, auth.changed()).await.is_err() {
                bail!("timed out waiting for TDLib authorization (state {state})");
            }
        }
    }

    /// If `chat_id` is a basic group Telegram upgraded to a supergroup (this
    /// happens e.g. when a bot is made admin), the supergroup's chat id.
    pub async fn follow_upgrade(&self, chat_id: i64) -> Option<i64> {
        let chat = self.request(json!({"@type": "getChat", "chat_id": chat_id})).await.ok()?;
        if chat["type"]["@type"] != "chatTypeBasicGroup" {
            return None;
        }
        let id = chat["type"]["basic_group_id"].as_i64()?;
        let group = self.request(json!({"@type": "getBasicGroup", "basic_group_id": id})).await.ok()?;
        let upgraded = group["upgraded_to_supergroup_id"].as_i64().filter(|s| *s != 0)?;
        Some(-1_000_000_000_000 - upgraded)
    }

    /// Check the bot can post documents to `chat_id` (following a group
    /// upgrade); returns the chat title and the chat id to post to.
    pub async fn check_chat(&self, chat_id: i64) -> Result<(String, i64)> {
        let chat_id = match self.follow_upgrade(chat_id).await {
            Some(new) => {
                tracing::warn!("chat {chat_id} was upgraded to a supergroup; posting to {new}. Set telegram.chat_id = {new} in fwdonor.toml");
                new
            }
            None => chat_id,
        };
        let me = self.request(json!({"@type": "getMe"})).await.map_err(|e| anyhow!("getMe: {e}"))?;
        let bot = me["usernames"]["active_usernames"][0].as_str().unwrap_or("?").to_string();
        let chat = self
            .request(json!({"@type": "getChat", "chat_id": chat_id}))
            .await
            .map_err(|e| anyhow!("bot @{bot} cannot see chat {chat_id} ({e}); add it to the group"))?;
        let title = chat["title"].as_str().unwrap_or("").to_string();
        let can_send_documents = chat["permissions"]["can_send_documents"].as_bool().unwrap_or(false);
        let kind = chat["type"]["@type"].as_str().unwrap_or("");
        let status = match kind {
            "chatTypeBasicGroup" => {
                let id = chat["type"]["basic_group_id"].as_i64().unwrap_or(0);
                let group = self
                    .request(json!({"@type": "getBasicGroup", "basic_group_id": id}))
                    .await
                    .map_err(|e| anyhow!("getBasicGroup: {e}"))?;
                let upgraded = group["upgraded_to_supergroup_id"].as_i64().unwrap_or(0);
                if upgraded != 0 {
                    bail!("group was upgraded to a supergroup; set telegram.chat_id = -100{upgraded}");
                }
                if group["is_active"] != true {
                    bail!("basic group {id} is not active");
                }
                group["status"].clone()
            }
            "chatTypeSupergroup" => {
                let id = chat["type"]["supergroup_id"].as_i64().unwrap_or(0);
                let group = self
                    .request(json!({"@type": "getSupergroup", "supergroup_id": id}))
                    .await
                    .map_err(|e| anyhow!("getSupergroup: {e}"))?;
                group["status"].clone()
            }
            other => bail!("chat {chat_id} is a {other}, expected a group"),
        };
        let allowed = match status["@type"].as_str().unwrap_or("") {
            "chatMemberStatusCreator" | "chatMemberStatusAdministrator" => true,
            "chatMemberStatusMember" => can_send_documents,
            "chatMemberStatusRestricted" => {
                status["is_member"] == true && status["permissions"]["can_send_documents"] == true
            }
            other => bail!("bot @{bot} is not a member of \"{title}\" ({other})"),
        };
        if !allowed {
            bail!("bot @{bot} may not send documents in \"{title}\"");
        }
        tracing::info!("posting as @{bot} to \"{title}\" ({chat_id})");
        Ok((title, chat_id))
    }

    pub async fn close(&self) {
        let _ = self.request_timeout(json!({"@type": "close"}), Duration::from_secs(10)).await;
        let mut auth = self.auth.clone();
        let _ = tokio::time::timeout(Duration::from_secs(10), async {
            while auth.borrow_and_update().as_str() != "authorizationStateClosed" {
                if auth.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_parsing() {
        let e = TdError { code: 429, message: "Too Many Requests: retry after 17".into() };
        assert_eq!(e.retry_after(), Some(17));
        let e = TdError { code: 400, message: "Bad Request".into() };
        assert_eq!(e.retry_after(), None);
    }
}
