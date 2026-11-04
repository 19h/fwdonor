//! The fwdonor HTTP API (src/http.rs) as seen by a client.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Longest wait between retries, Retry-After included (as on the page).
pub const MAX_BACKOFF: Duration = Duration::from_secs(20);

/// A failed request: no response at all, or the server's JSON error.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// None: the request never got a response (connection refused, timeout…).
    pub status: Option<StatusCode>,
    /// The `error` code of the server's JSON body.
    pub code: Option<String>,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl ApiError {
    /// Worth retrying as is: the server is away, busy, limiting or paused.
    pub fn transient(&self) -> bool {
        match self.status {
            None => true,
            Some(s) => s.is_server_error() || s == StatusCode::REQUEST_TIMEOUT || s == StatusCode::TOO_MANY_REQUESTS,
        }
    }

    /// The proxy answered instead of fwdonor: it is (re)starting.
    pub fn server_down(&self) -> bool {
        match self.status {
            None => true,
            Some(s) => self.code.is_none() && matches!(s.as_u16(), 502..=504),
        }
    }

    pub fn is(&self, code: &str) -> bool {
        self.code.as_deref() == Some(code)
    }

    pub fn not_found(&self) -> bool {
        self.status == Some(StatusCode::NOT_FOUND)
    }

    /// This address is banned for a while (repeated server-side rejections).
    pub fn banned(&self) -> bool {
        self.status == Some(StatusCode::FORBIDDEN) && self.is("limited")
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            None => write!(f, "{}", self.message),
            Some(s) => write!(f, "{} ({})", self.message, s.as_u16()),
        }
    }
}

impl std::error::Error for ApiError {}

/// 1, 2, 4, 8, 16, 20, 20… seconds, or the server's Retry-After; at most
/// MAX_BACKOFF either way.
pub fn backoff(attempt: u32, retry_after: Option<u64>) -> Duration {
    let wait = match retry_after {
        Some(secs) => Duration::from_secs(secs.max(1)),
        None => Duration::from_secs(1 << attempt.min(5)),
    };
    wait.min(MAX_BACKOFF)
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyResponse {
    /// The zrax revision this client must have to upload (its own while the
    /// server still accepts it).
    pub zrax_rev: String,
    /// The server's own zrax revision.
    #[serde(default)]
    pub zrax_latest: Option<String>,
    pub max_file_bytes: u64,
    pub min_file_bytes: u64,
    pub paused: bool,
    pub policy: fwdonor::config::Policy,
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    pub token: String,
    pub bits: u8,
}

/// A hash the server knows: posted (with when), or else being received or
/// posted right now (`in_progress`).
#[derive(Debug, Clone, Deserialize)]
pub struct Known {
    #[serde(default)]
    pub posted_at: Option<u64>,
    #[serde(default)]
    pub date: Option<String>,
}

#[derive(Deserialize)]
struct KnownResponse {
    known: HashMap<String, Known>,
}

#[derive(Debug, Serialize)]
pub struct InitRequest<'a> {
    pub name: &'a str,
    pub size: u64,
    pub sha256: &'a str,
    pub username: &'a str,
    pub token: &'a str,
    pub nonce: u64,
    pub zrax_rev: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct InitResponse {
    pub id: String,
    pub chunk_size: u64,
    pub chunks: u64,
}

/// `receiving`, `verifying`, `rejected`, `queued`, `posting`, `posted` or
/// `failed`, with `reason` for rejected and failed uploads.
#[derive(Debug, Deserialize)]
pub struct Status {
    pub state: String,
    #[serde(default)]
    pub reason: Option<String>,
    /// Place in the Telegram queue (1 = next).
    #[serde(default)]
    pub position: Option<usize>,
}

#[derive(Clone)]
pub struct Api {
    http: Client,
    base: String,
}

/// Most requests are small; a 4 MiB chunk over a slow link gets longer (the
/// proxy in front of the server allows 120 s per request).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CHUNK_TIMEOUT: Duration = Duration::from_secs(150);

impl Api {
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let http = Client::builder()
            .user_agent(concat!("fwdonate/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self { http, base: base.trim_end_matches('/').to_string() })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn send(&self, req: RequestBuilder) -> Result<reqwest::Response, ApiError> {
        let res = req.send().await.map_err(|e| ApiError {
            status: None,
            code: None,
            message: describe(&e),
            retry_after: None,
        })?;
        let status = res.status();
        if status.is_success() {
            return Ok(res);
        }
        let retry_after = res
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok());
        #[derive(Deserialize)]
        struct Body {
            error: String,
            message: String,
        }
        let text = res.text().await.unwrap_or_default();
        Err(match serde_json::from_str::<Body>(&text) {
            Ok(b) => ApiError { status: Some(status), code: Some(b.error), message: b.message, retry_after },
            Err(_) => ApiError {
                status: Some(status),
                code: None,
                message: status.canonical_reason().unwrap_or("HTTP error").to_lowercase(),
                retry_after,
            },
        })
    }

    async fn json<T: DeserializeOwned>(&self, req: RequestBuilder) -> Result<T, ApiError> {
        let res = self.send(req).await?;
        let status = res.status();
        let text = res.text().await.map_err(|e| ApiError {
            status: None,
            code: None,
            message: describe(&e),
            retry_after: None,
        })?;
        serde_json::from_str(&text).map_err(|e| ApiError {
            status: Some(status),
            code: Some("unexpected_response".into()),
            message: format!("unexpected response from the server: {e}"),
            retry_after: None,
        })
    }

    pub async fn policy(&self, rev: &str) -> Result<PolicyResponse, ApiError> {
        // Revisions are hex commit ids: nothing to escape.
        self.json(self.http.get(self.url(&format!("/api/policy?rev={rev}"))).timeout(REQUEST_TIMEOUT)).await
    }

    pub async fn challenge(&self) -> Result<Challenge, ApiError> {
        self.json(self.http.get(self.url("/api/challenge")).timeout(REQUEST_TIMEOUT)).await
    }

    /// Which of these hashes (at most 1000) the server already has or is
    /// receiving right now.
    pub async fn known(&self, sha256: &[&str]) -> Result<HashMap<String, Known>, ApiError> {
        let body = serde_json::json!({ "sha256": sha256 });
        let res: KnownResponse =
            self.json(self.http.post(self.url("/api/known")).json(&body).timeout(REQUEST_TIMEOUT)).await?;
        Ok(res.known)
    }

    pub async fn init(&self, req: &InitRequest<'_>) -> Result<InitResponse, ApiError> {
        self.json(self.http.post(self.url("/api/uploads")).json(req).timeout(REQUEST_TIMEOUT)).await
    }

    pub async fn put_chunk(&self, id: &str, index: u64, data: Bytes) -> Result<(), ApiError> {
        let req = self
            .http
            .put(self.url(&format!("/api/uploads/{id}/{index}")))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data)
            .timeout(CHUNK_TIMEOUT);
        self.send(req).await.map(|_| ())
    }

    pub async fn complete(&self, id: &str) -> Result<Status, ApiError> {
        self.json(self.http.post(self.url(&format!("/api/uploads/{id}/complete"))).timeout(REQUEST_TIMEOUT)).await
    }

    pub async fn status(&self, id: &str) -> Result<Status, ApiError> {
        self.json(self.http.get(self.url(&format!("/api/uploads/{id}"))).timeout(REQUEST_TIMEOUT)).await
    }

    pub async fn cancel(&self, id: &str) -> Result<(), ApiError> {
        self.send(self.http.delete(self.url(&format!("/api/uploads/{id}"))).timeout(Duration::from_secs(5)))
            .await
            .map(|_| ())
    }
}

/// reqwest's error plus its causes (e.g. "connection refused").
fn describe(e: &reqwest::Error) -> String {
    let mut text = if e.is_timeout() { "timed out".to_string() } else { e.to_string() };
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_cap_and_honors_retry_after() {
        let secs: Vec<u64> = (0..8).map(|a| backoff(a, None).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 20, 20, 20]);
        assert_eq!(backoff(0, Some(5)), Duration::from_secs(5));
        assert_eq!(backoff(0, Some(600)), MAX_BACKOFF);
        assert_eq!(backoff(3, Some(0)), Duration::from_secs(1));
    }

    #[test]
    fn classifies_errors() {
        let err = |status: Option<u16>, code: Option<&str>| ApiError {
            status: status.map(|s| StatusCode::from_u16(s).unwrap()),
            code: code.map(str::to_string),
            message: String::new(),
            retry_after: None,
        };
        assert!(err(None, None).transient() && err(None, None).server_down());
        assert!(err(Some(502), None).server_down());
        assert!(!err(Some(503), Some("paused")).server_down() && err(Some(503), Some("paused")).transient());
        assert!(err(Some(429), Some("limited")).transient());
        assert!(err(Some(403), Some("limited")).banned() && !err(Some(403), Some("pow")).banned());
        assert!(!err(Some(409), Some("duplicate")).transient());
        assert!(!err(Some(404), Some("not_found")).transient() && err(Some(404), Some("not_found")).not_found());
    }
}
