//! Bring images that were posted before the firmware store existed back
//! from the group. Runs in the background at every start and skips whatever
//! the store already has, so it simply continues after a restart.
//!
//! For each ledger entry: fetch the message by its id (in the supergroup,
//! else in the basic group it was upgraded from), download the document
//! through TDLib, check its SHA-256 against the ledger, copy it into the
//! store with a record, and delete TDLib's own copy.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use super::client::{TdClient, TdError};
use crate::analyze::{zrax_label, Analyzer, Outcome, Verdict};
use crate::firmwares::{Checked, Firmwares, Posted, Record, Unclassified};
use crate::ledger::{Entry, Ledger};
use crate::uploads::unix_now;

/// The largest image (512 MiB) at a slow pace.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_FAILURES: u32 = 6;
const MAX_BACKOFF: Duration = Duration::from_secs(20);
const PROGRESS_EVERY: Duration = Duration::from_secs(60);
/// This many failures in a row means something systematic (no access, no
/// downloads for bots…): stop until the next start instead of trying them all.
const GIVE_UP_AFTER: usize = 25;

/// How far the backfill is, for the dashboard.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Progress {
    /// off (no Telegram), waiting, running, finished or failed.
    pub state: &'static str,
    /// Posted images in the ledger, and those missing from the store.
    pub total: usize,
    pub todo: usize,
    pub todo_bytes: u64,
    pub done: usize,
    pub restored: usize,
    pub missing: usize,
    pub bytes: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    /// The chats searched, newest first.
    pub chats: Vec<i64>,
    /// An era given up on after too many failures in a row.
    pub skipped_era: Option<usize>,
}

pub type Status = Arc<Mutex<Progress>>;

pub fn status(state: &'static str) -> Status {
    Arc::new(Mutex::new(Progress { state, ..Default::default() }))
}

pub struct Backfill {
    pub client: Arc<TdClient>,
    /// The group the poster posts to (the supergroup).
    pub chat_id: i64,
    pub ledger: Arc<Ledger>,
    pub firmwares: Arc<Firmwares>,
    pub analyzer: Analyzer,
    /// Chats the group had before (`telegram.previous_chat_ids`), newest first.
    pub previous_chats: Vec<i64>,
    pub status: Status,
}

/// Why an entry couldn't be restored from one chat.
enum Miss {
    /// Not there (or a different file): try the next chat.
    NotHere(String),
    /// Telegram keeps failing: give up on this entry for now.
    Failed(String),
}

impl Backfill {
    fn update(&self, f: impl FnOnce(&mut Progress)) {
        f(&mut self.status.lock().unwrap());
    }

    pub async fn run(self) {
        self.update(|p| {
            p.state = "running";
            p.started_at = Some(unix_now());
        });
        let entries = match self.ledger.entries() {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("backfill: reading the ledger failed: {e:#}");
                self.update(|p| p.state = "failed");
                return;
            }
        };
        let total = entries.len();
        self.update(|p| p.total = total);
        // Which chat each post went to: message ids start again from 1 in
        // the supergroup a basic group is upgraded to, so every drop in the
        // ledger's ids is one upgrade. Era 0 is the current chat, era 1 the
        // one before it, and so on.
        let eras = eras(&entries);
        let mut todo: Vec<(usize, Entry)> =
            eras.into_iter().zip(entries).filter(|(_, e)| !self.firmwares.has(&e.sha256)).collect();
        if todo.is_empty() {
            tracing::info!("backfill: all {total} posted images are in the firmware store");
            self.update(|p| {
                p.state = "finished";
                p.finished_at = Some(unix_now());
            });
            return;
        }
        // The current chat first: trouble with an older one mustn't hold up the rest.
        todo.sort_by_key(|(era, _)| *era);
        let todo_bytes: u64 = todo.iter().map(|(_, e)| e.size).sum();
        tracing::info!(
            "backfill: {} of {total} posted images ({:.1} GB) are missing from the firmware store; fetching them from Telegram",
            todo.len(),
            todo_bytes as f64 / 1e9
        );
        self.update(|p| {
            p.todo = todo.len();
            p.todo_bytes = todo_bytes;
        });
        let mut chats = vec![self.chat_id];
        chats.extend(self.earlier_chats().await);
        tracing::info!("backfill: chats, newest first: {chats:?}");
        self.update(|p| p.chats = chats.clone());

        let started = Instant::now();
        let mut last_report = Instant::now();
        let (mut restored, mut missing, mut bytes) = (0usize, 0usize, 0u64);
        let (mut failing, mut skipped_era) = (0usize, None);
        for (n, (era, entry)) in todo.iter().enumerate() {
            self.update(|p| p.done = n);
            if skipped_era == Some(*era) || self.firmwares.has(&entry.sha256) {
                continue;
            }
            // Its own chat first, then the others.
            let order: Vec<i64> = chats.get(*era).into_iter().chain(chats.iter().filter(|c| chats.get(*era) != Some(c))).copied().collect();
            match self.restore(entry, &order).await {
                Ok(()) => {
                    restored += 1;
                    bytes += entry.size;
                    failing = 0;
                    self.update(|p| {
                        p.restored = restored;
                        p.bytes = bytes;
                    });
                }
                Err(reason) => {
                    missing += 1;
                    failing += 1;
                    tracing::warn!(sha256 = %entry.sha256, name = %entry.name, message_id = entry.message_id, era, "backfill: {reason}");
                    self.firmwares.catalog().unrecovered(&entry.sha256, &reason);
                    self.update(|p| p.missing = missing);
                    if failing >= GIVE_UP_AFTER {
                        let left = todo.iter().filter(|(e, _)| e == era).count();
                        tracing::error!(
                            "backfill: the last {failing} images all failed; skipping the other posts of that chat (era {era}, {left} images in all) until the next start"
                        );
                        skipped_era = Some(*era);
                        failing = 0;
                        self.update(|p| p.skipped_era = skipped_era);
                    }
                }
            }
            if last_report.elapsed() >= PROGRESS_EVERY {
                last_report = Instant::now();
                let secs = started.elapsed().as_secs_f64().max(1.0);
                tracing::info!(
                    "backfill: {}/{} done, {restored} restored ({:.1} GB, {:.1} MB/s), {missing} not restored",
                    n + 1,
                    todo.len(),
                    bytes as f64 / 1e9,
                    bytes as f64 / 1e6 / secs
                );
            }
        }
        self.update(|p| {
            p.done = todo.len();
            p.state = "finished";
            p.finished_at = Some(unix_now());
        });
        tracing::info!(
            "backfill finished in {:.0} min: {restored} restored ({:.1} GB), {missing} not restored (they are tried again at the next start)",
            started.elapsed().as_secs_f64() / 60.0,
            bytes as f64 / 1e9
        );
    }

    /// The chats the group used before (basic groups it was upgraded from),
    /// newest first: what TDLib reports, then the configured ones.
    async fn earlier_chats(&self) -> Vec<i64> {
        let mut out = Vec::new();
        match self.reported_upgrade().await {
            Ok(Some(chat)) => out.push(chat),
            Ok(None) => tracing::info!("backfill: TDLib reports no basic group this supergroup was upgraded from"),
            Err(e) => tracing::warn!("backfill: asking TDLib which group this was upgraded from failed: {e}"),
        }
        // The supergroup's first message is Telegram's "upgraded from" notice.
        // Fetching it also makes TDLib load the old group, which it otherwise
        // doesn't know after a restart (no chat database, and bots can't list
        // their chats).
        match self.call(json!({"@type": "getMessage", "chat_id": self.chat_id, "message_id": 1i64 << 20}), REQUEST_TIMEOUT).await {
            Ok(m) if m["content"]["@type"] == "messageChatUpgradeFrom" => {
                if let Some(id) = m["content"]["basic_group_id"].as_i64().filter(|id| *id != 0) {
                    if !out.contains(&-id) {
                        out.push(-id);
                    }
                }
            }
            Ok(m) => tracing::info!("backfill: the supergroup's first message is a {}", m["content"]["@type"]),
            Err(e) => tracing::warn!("backfill: fetching the supergroup's first message failed: {e}"),
        }
        for &chat in &self.previous_chats {
            if !out.contains(&chat) {
                out.push(chat);
            }
        }
        // TDLib needs to know a chat before its messages can be fetched.
        for &chat in &out {
            if chat < 0 && chat > -1_000_000_000_000 {
                let made = self
                    .call(json!({"@type": "createBasicGroupChat", "basic_group_id": -chat, "force": true}), REQUEST_TIMEOUT)
                    .await;
                match made {
                    Ok(_) => tracing::info!("backfill: earlier chat {chat} is open"),
                    Err(e) => tracing::warn!("backfill: opening the earlier chat {chat} failed: {e}"),
                }
            }
        }
        out
    }

    async fn reported_upgrade(&self) -> Result<Option<i64>, TdError> {
        let chat = self.call(json!({"@type": "getChat", "chat_id": self.chat_id}), REQUEST_TIMEOUT).await?;
        let Some(supergroup) = chat["type"]["supergroup_id"].as_i64() else { return Ok(None) };
        let full = self.call(json!({"@type": "getSupergroupFullInfo", "supergroup_id": supergroup}), REQUEST_TIMEOUT).await?;
        Ok(full["upgraded_from_basic_group_id"].as_i64().filter(|id| *id != 0).map(|id| -id))
    }

    async fn restore(&self, entry: &Entry, chats: &[i64]) -> Result<(), String> {
        let mut reasons = Vec::new();
        for &chat in chats {
            match self.restore_from(entry, chat).await {
                Ok(()) => return Ok(()),
                Err(Miss::NotHere(r)) => reasons.push(format!("chat {chat}: {r}")),
                Err(Miss::Failed(r)) => return Err(format!("chat {chat}: {r}")),
            }
        }
        Err(format!("not restored ({})", reasons.join("; ")))
    }

    async fn restore_from(&self, entry: &Entry, chat: i64) -> Result<(), Miss> {
        let message = match self
            .call(json!({"@type": "getMessage", "chat_id": chat, "message_id": entry.message_id}), REQUEST_TIMEOUT)
            .await
        {
            Ok(m) => m,
            Err(e) if definitive(&e) => return Err(Miss::NotHere(e.message)),
            Err(e) => return Err(Miss::Failed(e.to_string())),
        };
        if message["content"]["@type"] != "messageDocument" {
            return Err(Miss::NotHere("that message has no document".into()));
        }
        let file = &message["content"]["document"]["document"];
        let Some(file_id) = file["id"].as_i64() else {
            return Err(Miss::NotHere("the document has no file".into()));
        };
        let size = file["size"].as_u64().filter(|s| *s > 0).or(file["expected_size"].as_u64()).unwrap_or(0);
        if size != entry.size {
            return Err(Miss::NotHere(format!("the document has {size} bytes, the ledger {}", entry.size)));
        }

        let downloaded = self
            .call(
                json!({"@type": "downloadFile", "file_id": file_id, "priority": 1, "offset": 0, "limit": 0, "synchronous": true}),
                DOWNLOAD_TIMEOUT,
            )
            .await
            .map_err(|e| Miss::Failed(format!("download: {e}")))?;
        let path = match downloaded["local"]["path"].as_str() {
            Some(p) if !p.is_empty() && downloaded["local"]["is_downloading_completed"] == true => PathBuf::from(p),
            _ => return Err(Miss::Failed("the download did not complete".into())),
        };
        let result = self.keep(entry, chat, &path).await;
        // TDLib's copy is not needed either way.
        let _ = self.call(json!({"@type": "deleteFile", "file_id": file_id}), REQUEST_TIMEOUT).await;
        result
    }

    async fn keep(&self, entry: &Entry, chat: i64, path: &std::path::Path) -> Result<(), Miss> {
        let hashed = {
            let path = path.to_owned();
            tokio::task::spawn_blocking(move || crate::uploads::sha256_file(&path)).await
        };
        match hashed {
            Ok(Ok(sha)) if sha == entry.sha256 => {}
            Ok(Ok(sha)) => return Err(Miss::NotHere(format!("the document's sha256 is {sha}"))),
            Ok(Err(e)) => return Err(Miss::Failed(format!("reading the download: {e}"))),
            Err(e) => return Err(Miss::Failed(format!("hashing panicked: {e}"))),
        }
        // What the current zrax makes of it, for the record (the ledger only
        // has the format and ISA). One it rejects is kept, but hidden.
        let now = unix_now();
        let (zrax, unclassified, error) = match self.analyzer.analyze_file_outcome(path.to_owned()).await {
            Outcome::Verdict(Verdict::Accepted(summary)) => (Some(summary), None, None),
            Outcome::Verdict(Verdict::Rejected { reason }) => {
                tracing::info!(sha256 = %entry.sha256, %reason, "backfill: the current zrax no longer accepts this image; keeping it, hidden");
                (None, Some(Unclassified { zrax: zrax_label(), since: now, reason }), None)
            }
            Outcome::Failed(reason) => {
                tracing::warn!(sha256 = %entry.sha256, %reason, "backfill: zrax came to no answer on this image; keeping it");
                (None, None, Some(reason))
            }
        };
        let record = Record {
            sha256: entry.sha256.clone(),
            size: entry.size,
            name: entry.username.clone(),
            original_name: entry.name.clone(),
            zrax,
            unclassified,
            checked: Some(Checked { zrax: zrax_label(), at: now, error }),
            received_at: entry.posted_at,
            source: "telegram".into(),
            telegram: Some(Posted::new(chat, entry.message_id, entry.posted_at)),
        };
        let (store, path) = (self.firmwares.clone(), path.to_owned());
        match tokio::task::spawn_blocking(move || store.keep(&path, &record)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(Miss::Failed(format!("storing: {e}"))),
            Err(e) => Err(Miss::Failed(format!("storing panicked: {e}"))),
        }
    }

    /// A TDLib request, waiting out flood limits and retrying transient
    /// errors (at most MAX_BACKOFF apart).
    async fn call(&self, request: Value, timeout: Duration) -> Result<Value, TdError> {
        let mut failures = 0;
        loop {
            match self.client.request_timeout(request.clone(), timeout).await {
                Ok(v) => return Ok(v),
                Err(e) if definitive(&e) => return Err(e),
                Err(e) => {
                    if let Some(wait) = e.retry_after() {
                        tracing::info!("backfill: flood wait {wait}s");
                        tokio::time::sleep(Duration::from_secs(wait + 1)).await;
                        continue;
                    }
                    failures += 1;
                    if failures >= MAX_FAILURES {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_secs(1 << failures).min(MAX_BACKOFF)).await;
                }
            }
        }
    }
}

/// The chat era of each ledger entry (see `Backfill::run`).
pub fn eras(entries: &[Entry]) -> Vec<usize> {
    let mut out = vec![0; entries.len()];
    let mut era = 0;
    for i in (0..entries.len()).rev() {
        out[i] = era;
        if i > 0 && (entries[i].message_id >> 20) < (entries[i - 1].message_id >> 20) {
            era += 1;
        }
    }
    out
}

/// Answers that retrying won't change (no such message, no access).
fn definitive(e: &TdError) -> bool {
    matches!(e.code, 400 | 403 | 404)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(server_id: i64) -> Entry {
        Entry {
            sha256: String::new(),
            name: String::new(),
            size: 0,
            username: String::new(),
            format: String::new(),
            isa: None,
            isas: Vec::new(),
            message_id: server_id << 20,
            posted_at: 0,
        }
    }

    #[test]
    fn eras_follow_the_message_id_resets() {
        let ids = [2, 3, 4, 435, 2, 3, 5, 6, 2, 3];
        let entries: Vec<Entry> = ids.iter().map(|&i| entry(i)).collect();
        assert_eq!(eras(&entries), [2, 2, 2, 2, 1, 1, 1, 1, 0, 0]);
        assert_eq!(eras(&[]), Vec::<usize>::new());
    }
}
