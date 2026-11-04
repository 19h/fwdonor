//! Chunked upload sessions: admission, chunk writes, server-side
//! verification, status, cancellation, and spool housekeeping.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::StatusCode;
use futures_util::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::analyze::{Analyzer, Summary, Verdict};
use crate::config::Config;
use crate::firmwares::{Firmwares, Posted, Record};
use crate::revisions::Revisions;
use crate::error::ApiError;
use crate::jobs::{Job, PostQueue};
use crate::ledger::Ledger;
use crate::limits::{ClientKey, Limiter};
use crate::pow::PowGate;

/// How long finished uploads stay visible to status polling.
const FINISHED_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UploadState {
    Receiving,
    Verifying,
    Rejected { reason: String },
    Queued,
    Posting,
    Posted,
    Failed { reason: String },
}

impl UploadState {
    fn is_final(&self) -> bool {
        matches!(self, UploadState::Rejected { .. } | UploadState::Posted | UploadState::Failed { .. })
    }
}

struct Session {
    key: Option<ClientKey>,
    name: String,
    size: u64,
    sha256: String,
    username: String,
    chunks: Vec<bool>,
    file: PathBuf,
    last_activity: Instant,
    state: UploadState,
    summary: Option<Summary>,
    /// The page classified this file with an older zrax than ours.
    older_zrax: bool,
    holds_slot: bool,
    /// Bytes counted against the spool cap until the file is deleted.
    reserved: u64,
}

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub username: String,
    pub token: String,
    pub nonce: u64,
    pub zrax_rev: String,
}

#[derive(Debug, Serialize)]
pub struct InitResponse {
    pub id: String,
    pub chunk_size: u64,
    pub chunks: u64,
    pub name: String,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    #[serde(flatten)]
    pub state: UploadState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<usize>,
    pub received: usize,
    pub chunks: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
}

pub struct Uploads {
    config: Arc<Config>,
    pow: Arc<PowGate>,
    limiter: Arc<Limiter>,
    ledger: Arc<Ledger>,
    analyzer: Analyzer,
    queue: Arc<PostQueue>,
    revisions: Arc<Revisions>,
    firmwares: Arc<Firmwares>,
    sessions: Mutex<HashMap<String, Session>>,
    reserved: AtomicU64,
    /// Unix time of the last donation-related request (or of the start).
    activity: AtomicU64,
}

/// Keep only the final path component, drop control characters and
/// separators, and bound the length (keeping the extension).
pub fn sanitize_filename(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| match c {
            c if c.is_control() => '_',
            '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => '_',
            ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim().trim_start_matches(['.', ' ']).to_string();
    let limited = if trimmed.len() > 120 {
        let (stem, ext) = match trimmed.rfind('.') {
            Some(dot) if trimmed.len() - dot <= 16 => (&trimmed[..dot], &trimmed[dot..]),
            _ => (trimmed.as_str(), ""),
        };
        let mut end = 120 - ext.len();
        while !stem.is_char_boundary(end.min(stem.len())) {
            end -= 1;
        }
        format!("{}{}", &stem[..end.min(stem.len())], ext)
    } else {
        trimmed
    };
    if limited.is_empty() {
        "firmware.bin".into()
    } else {
        limited
    }
}

/// Donor names are restricted so they cannot become mentions, links or
/// commands in the Telegram post.
pub fn sanitize_username(raw: &str) -> String {
    let name = raw.trim().trim_start_matches('@');
    let valid = !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if valid {
        name.to_string()
    } else {
        "anonymous".into()
    }
}

fn parse_sha256(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    bytes.try_into().ok()
}

pub(crate) fn new_id() -> String {
    let mut id = [0u8; 12];
    rand::rng().fill_bytes(&mut id);
    hex::encode(id)
}

fn valid_id(id: &str) -> bool {
    id.len() == 24 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub(crate) fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

impl Uploads {
    pub fn new(
        config: Arc<Config>,
        pow: Arc<PowGate>,
        limiter: Arc<Limiter>,
        ledger: Arc<Ledger>,
        analyzer: Analyzer,
        queue: Arc<PostQueue>,
        revisions: Arc<Revisions>,
        firmwares: Arc<Firmwares>,
    ) -> Self {
        Self {
            config,
            pow,
            limiter,
            ledger,
            analyzer,
            queue,
            revisions,
            firmwares,
            sessions: Mutex::new(HashMap::new()),
            reserved: AtomicU64::new(0),
            activity: AtomicU64::new(unix_now()),
        }
    }

    pub fn revisions(&self) -> &Revisions {
        &self.revisions
    }

    fn spool(&self) -> &Path {
        &self.config.spool_dir
    }

    fn chunk_count(&self, size: u64) -> u64 {
        size.div_ceil(self.config.limits.chunk_bytes)
    }

    fn chunk_len(&self, size: u64, index: u64) -> u64 {
        let chunk = self.config.limits.chunk_bytes;
        chunk.min(size - index * chunk)
    }

    pub fn init(&self, req: InitRequest, key: ClientKey) -> Result<InitResponse, ApiError> {
        self.touch();
        let limits = &self.config.limits;
        if self.config.is_paused() {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "paused", "donations are paused right now")
                .retry_after(600));
        }
        if !self.revisions.accepts(&req.zrax_rev, unix_now()) {
            return Err(ApiError::conflict("stale_client", "the page is out of date, please reload"));
        }
        let sha = parse_sha256(&req.sha256).ok_or_else(|| ApiError::bad_request("sha256 must be 64 hex digits"))?;
        let sha_hex = hex::encode(sha);
        if let Err(e) = self.pow.redeem(&req.token, &sha, req.nonce) {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "pow", e.to_string()));
        }
        if req.size < limits.min_file_bytes || req.size > limits.max_file_bytes {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "size",
                format!("files must be between {} bytes and {} MiB", limits.min_file_bytes, limits.max_file_bytes >> 20),
            ));
        }
        if let Some(at) = self.ledger.posted_at(&sha_hex) {
            return Err(ApiError::conflict("duplicate", format!("already donated on {}", crate::ledger::date(at))));
        }
        let name = sanitize_filename(&req.name);
        let username = sanitize_username(&req.username);

        let mut sessions = self.sessions.lock().unwrap();
        if sessions.values().any(|s| s.sha256 == sha_hex && !s.state.is_final()) {
            return Err(ApiError::conflict("duplicate", "this image is already being donated"));
        }
        let reserved = self.reserved.load(Ordering::SeqCst);
        if reserved + req.size > limits.spool_cap_bytes {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy, retrying shortly")
                .retry_after(30));
        }
        if let Err(denied) = self.limiter.admit(key, req.size) {
            let status = match denied {
                crate::limits::Denied::Banned { .. } => StatusCode::FORBIDDEN,
                _ => StatusCode::TOO_MANY_REQUESTS,
            };
            let mut err = ApiError::new(status, "limited", denied.message());
            if let Some(secs) = denied.retry_after() {
                err = err.retry_after(secs);
            }
            return Err(err);
        }

        let id = new_id();
        let dir = Job::dir(self.spool(), &id);
        let file = dir.join(&name);
        let created = std::fs::create_dir(&dir)
            .and_then(|_| std::fs::File::create(&file))
            .and_then(|f| f.set_len(req.size));
        if let Err(e) = created {
            self.limiter.release(key);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(ApiError::internal(format!("creating spool file: {e}")));
        }
        self.reserved.fetch_add(req.size, Ordering::SeqCst);
        let chunks = self.chunk_count(req.size);
        sessions.insert(
            id.clone(),
            Session {
                key: Some(key),
                name: name.clone(),
                size: req.size,
                sha256: sha_hex,
                username: username.clone(),
                chunks: vec![false; chunks as usize],
                file,
                last_activity: Instant::now(),
                state: UploadState::Receiving,
                summary: None,
                older_zrax: req.zrax_rev != self.revisions.current(),
                holds_slot: true,
                reserved: req.size,
            },
        );
        tracing::info!(%id, %name, size = req.size, %username, "upload admitted");
        Ok(InitResponse { id, chunk_size: limits.chunk_bytes, chunks, name, username })
    }

    pub async fn put_chunk(&self, id: &str, index: u64, body: Body) -> Result<(), ApiError> {
        self.touch();
        if !valid_id(id) {
            return Err(ApiError::not_found());
        }
        let (file, offset, expected) = {
            let mut sessions = self.sessions.lock().unwrap();
            let session = sessions.get_mut(id).ok_or_else(ApiError::not_found)?;
            if session.state != UploadState::Receiving {
                return Err(ApiError::conflict("state", "upload is no longer accepting data"));
            }
            if index >= session.chunks.len() as u64 {
                return Err(ApiError::bad_request("chunk index out of range"));
            }
            session.last_activity = Instant::now();
            let offset = index * self.config.limits.chunk_bytes;
            (session.file.clone(), offset, self.chunk_len(session.size, index))
        };

        let mut out = tokio::fs::OpenOptions::new().write(true).open(&file).await.map_err(ApiError::internal)?;
        out.seek(SeekFrom::Start(offset)).await.map_err(ApiError::internal)?;
        let mut written = 0u64;
        let mut stream = body.into_data_stream();
        while let Some(frame) = stream.next().await {
            let data = frame.map_err(|e| ApiError::bad_request(format!("upload interrupted: {e}")))?;
            written += data.len() as u64;
            if written > expected {
                return Err(ApiError::bad_request("chunk larger than expected"));
            }
            out.write_all(&data).await.map_err(ApiError::internal)?;
        }
        if written != expected {
            return Err(ApiError::bad_request(format!("chunk has {written} bytes, expected {expected}")));
        }
        out.flush().await.map_err(ApiError::internal)?;

        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(id) {
            if session.state == UploadState::Receiving {
                session.chunks[index as usize] = true;
                session.last_activity = Instant::now();
            }
        }
        Ok(())
    }

    pub fn complete(self: &Arc<Self>, id: &str) -> Result<(), ApiError> {
        self.touch();
        if !valid_id(id) {
            return Err(ApiError::not_found());
        }
        let (file, sha, key, classifier_strikes) = {
            let mut sessions = self.sessions.lock().unwrap();
            let session = sessions.get_mut(id).ok_or_else(ApiError::not_found)?;
            match session.state {
                UploadState::Receiving => {}
                // Repeated completion requests (client retries) are harmless.
                _ => return Ok(()),
            }
            let missing = session.chunks.iter().filter(|c| !**c).count();
            if missing > 0 {
                return Err(ApiError::conflict("incomplete", format!("{missing} chunks missing")));
            }
            session.state = UploadState::Verifying;
            if std::mem::take(&mut session.holds_slot) {
                if let Some(key) = session.key {
                    self.limiter.release(key);
                }
            }
            // A page on an older zrax may disagree with our verdict without
            // doing anything wrong: that must not count towards a ban.
            let classifier_strikes = !session.older_zrax;
            (session.file.clone(), session.sha256.clone(), session.key, classifier_strikes)
        };

        let this = Arc::clone(self);
        let id = id.to_string();
        tokio::spawn(async move {
            let path = file.clone();
            let actual = tokio::task::spawn_blocking(move || sha256_file(&path)).await;
            let (verdict, key) = match actual {
                Ok(Ok(actual)) if actual == sha => {
                    (this.analyzer.analyze_file(file).await, key.filter(|_| classifier_strikes))
                }
                Ok(Ok(_)) => (Verdict::Rejected { reason: "checksum mismatch".into() }, key),
                Ok(Err(e)) => (Verdict::Rejected { reason: format!("read failed: {e}") }, key),
                Err(e) => (Verdict::Rejected { reason: format!("hashing failed: {e}") }, key),
            };
            this.finish_verification(&id, verdict, key).await;
        });
        Ok(())
    }

    async fn finish_verification(&self, id: &str, verdict: Verdict, key: Option<ClientKey>) {
        match verdict {
            Verdict::Accepted(summary) => {
                let job = {
                    let mut sessions = self.sessions.lock().unwrap();
                    let Some(session) = sessions.get_mut(id) else { return };
                    Job {
                        id: id.to_string(),
                        name: session.name.clone(),
                        size: session.size,
                        sha256: session.sha256.clone(),
                        username: session.username.clone(),
                        summary: {
                            session.summary = Some(summary.clone());
                            summary
                        },
                        file: session.file.clone(),
                        created_at: unix_now(),
                    }
                };
                // Keep a copy before posting, so the image stays even if
                // posting fails. A storage error here must not cost the
                // donation, so it is only logged.
                let (store, file, record) = (self.firmwares.clone(), job.file.clone(), Record::for_upload(&job));
                match tokio::task::spawn_blocking(move || store.keep(&file, &record)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::error!(%id, sha256 = %job.sha256, "keeping the firmware failed: {e}"),
                    Err(e) => tracing::error!(%id, sha256 = %job.sha256, "keeping the firmware panicked: {e}"),
                }
                if let Err(e) = job.write_sidecar(self.spool()) {
                    tracing::error!(%id, "sidecar write failed: {e:#}");
                    self.finish(id, UploadState::Failed { reason: "server storage error".into() });
                    return;
                }
                tracing::info!(%id, name = %job.name, format = %job.summary.format, isa = ?job.summary.isa, "verified, queued");
                self.set_state(id, UploadState::Queued);
                self.queue.push(job);
            }
            Verdict::Rejected { reason } => {
                tracing::info!(%id, %reason, "rejected by server verification");
                if let Some(key) = key {
                    if self.limiter.record_rejection(key) {
                        tracing::warn!("client banned after repeated rejections");
                    }
                }
                self.finish(id, UploadState::Rejected { reason });
            }
        }
    }

    pub fn set_state(&self, id: &str, state: UploadState) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(id) {
            session.state = state;
            session.last_activity = Instant::now();
        }
    }

    /// Enter a final state and delete everything spooled for the upload.
    pub fn finish(&self, id: &str, state: UploadState) {
        let reserved = {
            let mut sessions = self.sessions.lock().unwrap();
            let Some(session) = sessions.get_mut(id) else { return };
            session.state = state;
            session.last_activity = Instant::now();
            if std::mem::take(&mut session.holds_slot) {
                if let Some(key) = session.key {
                    self.limiter.release(key);
                }
            }
            std::mem::take(&mut session.reserved)
        };
        let _ = std::fs::remove_file(Job::sidecar(self.spool(), id));
        let _ = std::fs::remove_dir_all(Job::dir(self.spool(), id));
        self.reserved.fetch_sub(reserved, Ordering::SeqCst);
    }

    pub fn status(&self, id: &str) -> Result<StatusResponse, ApiError> {
        self.touch();
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(id).ok_or_else(ApiError::not_found)?;
        let position = match session.state {
            UploadState::Queued => self.queue.position(id),
            _ => None,
        };
        Ok(StatusResponse {
            state: session.state.clone(),
            position,
            received: session.chunks.iter().filter(|c| **c).count(),
            chunks: session.chunks.len(),
            summary: session.summary.clone(),
        })
    }

    /// Abandon an upload that is still receiving data.
    pub fn cancel(&self, id: &str) -> Result<(), ApiError> {
        self.touch();
        let receiving = {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions.get(id).ok_or_else(ApiError::not_found)?;
            session.state == UploadState::Receiving
        };
        if receiving {
            self.finish(id, UploadState::Failed { reason: "cancelled".into() });
            self.sessions.lock().unwrap().remove(id);
        }
        Ok(())
    }

    /// Expire idle uploads and forget old finished ones.
    pub fn sweep(&self) {
        let idle = Duration::from_secs(self.config.limits.idle_upload_secs);
        let now = Instant::now();
        let stale: Vec<String> = {
            let sessions = self.sessions.lock().unwrap();
            sessions
                .iter()
                .filter(|(_, s)| s.state == UploadState::Receiving && now.duration_since(s.last_activity) > idle)
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in stale {
            tracing::info!(%id, "upload idle, discarding");
            self.finish(&id, UploadState::Failed { reason: "upload timed out".into() });
        }
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, s| !(s.state.is_final() && now.duration_since(s.last_activity) > FINISHED_TTL));
    }

    /// Startup: re-queue verified jobs, delete everything else in the spool.
    pub fn recover(&self) -> anyhow::Result<usize> {
        let spool = self.spool().to_owned();
        std::fs::create_dir_all(&spool)?;
        let mut keep = HashMap::new();
        for entry in std::fs::read_dir(&spool)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if let Some(id) = name.strip_suffix(".job.json") {
                match std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Job>(&b).ok()) {
                    Some(job) if job.id == id && job.file.starts_with(Job::dir(&spool, id)) && job.file.exists() => {
                        keep.insert(id.to_string(), job);
                    }
                    _ => {
                        tracing::warn!("discarding unreadable job {}", path.display());
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
        for entry in std::fs::read_dir(&spool)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let id = name.strip_suffix(".job.json").unwrap_or(name);
            if !keep.contains_key(id) {
                let _ = if path.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
            }
        }
        let count = keep.len();
        let mut jobs: Vec<Job> = keep.into_values().collect();
        jobs.sort_by_key(|j| j.created_at);
        let mut posted_before_crash = HashMap::new();
        let mut sessions = self.sessions.lock().unwrap();
        for job in jobs {
            if self.ledger.contains(&job.sha256) {
                // Posted before a crash but not yet cleaned up. Its copy may
                // not know where it was posted yet (noted below).
                if let Err(e) = self.firmwares.keep(&job.file, &Record::for_upload(&job)) {
                    tracing::error!(id = %job.id, sha256 = %job.sha256, "keeping the firmware failed: {e}");
                }
                posted_before_crash.insert(job.sha256.clone(), ());
                let _ = std::fs::remove_file(Job::sidecar(&spool, &job.id));
                let _ = std::fs::remove_dir_all(Job::dir(&spool, &job.id));
                continue;
            }
            // Jobs queued by a version that didn't keep firmware yet.
            if let Err(e) = self.firmwares.keep(&job.file, &Record::for_upload(&job)) {
                tracing::error!(id = %job.id, sha256 = %job.sha256, "keeping the firmware failed: {e}");
            }
            self.reserved.fetch_add(job.size, Ordering::SeqCst);
            sessions.insert(
                job.id.clone(),
                Session {
                    key: None,
                    name: job.name.clone(),
                    size: job.size,
                    sha256: job.sha256.clone(),
                    username: job.username.clone(),
                    chunks: Vec::new(),
                    file: job.file.clone(),
                    last_activity: Instant::now(),
                    state: UploadState::Queued,
                    summary: Some(job.summary.clone()),
                    older_zrax: false,
                    holds_slot: false,
                    reserved: job.size,
                },
            );
            self.queue.push(job);
        }
        drop(sessions);
        if !posted_before_crash.is_empty() {
            for entry in self.ledger.entries()?.into_iter().filter(|e| posted_before_crash.contains_key(&e.sha256)) {
                let posted = Posted::new(self.config.telegram.chat_id, entry.message_id, entry.posted_at);
                if let Err(e) = self.firmwares.mark_posted(&entry.sha256, posted) {
                    tracing::error!(sha256 = %entry.sha256, "noting the post in the firmware record failed: {e}");
                }
            }
        }
        Ok(count)
    }

    /// Whether an upload of this hash is in progress (not yet posted/failed).
    pub fn in_flight(&self, sha256: &str) -> bool {
        self.sessions.lock().unwrap().values().any(|s| s.sha256 == sha256 && !s.state.is_final())
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.reserved.load(Ordering::SeqCst)
    }

    /// Note donation traffic (any upload, challenge or lookup request).
    pub fn touch(&self) {
        self.activity.store(unix_now(), Ordering::Relaxed);
    }

    /// Seconds since the last donation-related request.
    pub fn idle_secs(&self) -> u64 {
        unix_now().saturating_sub(self.activity.load(Ordering::Relaxed))
    }

    /// Donations in progress, for the dashboard: what, credited to whom, how
    /// far. Never the session id (it controls the upload) or the address.
    pub fn arriving(&self) -> Vec<serde_json::Value> {
        let sessions = self.sessions.lock().unwrap();
        let mut out: Vec<(u8, u64, serde_json::Value)> = sessions
            .values()
            .filter(|s| !s.state.is_final())
            .map(|s| {
                let (state, order) = match s.state {
                    UploadState::Posting => ("posting", 0),
                    UploadState::Queued => ("queued", 1),
                    UploadState::Verifying => ("verifying", 2),
                    _ => ("receiving", 3),
                };
                let idle = s.last_activity.elapsed().as_secs();
                let value = serde_json::json!({
                    "name": s.name,
                    "size": s.size,
                    "sha256": s.sha256,
                    "donor": s.username,
                    "state": state,
                    "received": s.chunks.iter().filter(|c| **c).count(),
                    "chunks": s.chunks.len(),
                    "idle_secs": idle,
                    "isa": s.summary.as_ref().and_then(|z| z.isa_name.clone()),
                    "format": s.summary.as_ref().map(|z| z.format_name.clone()),
                });
                (order, idle, value)
            })
            .collect();
        out.sort_by_key(|(order, idle, _)| (*order, *idle));
        out.into_iter().take(200).map(|(_, _, v)| v).collect()
    }

    /// Uploads that are not finished: receiving, verifying, queued or posting.
    pub fn active(&self) -> usize {
        self.sessions.lock().unwrap().values().filter(|s| !s.state.is_final()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("C:\\fw\\image.bin"), "image.bin");
        assert_eq!(sanitize_filename(".hidden"), "hidden");
        assert_eq!(sanitize_filename(""), "firmware.bin");
        assert_eq!(sanitize_filename("a\u{202e}b\n.bin"), "a_b_.bin");
        assert_eq!(sanitize_filename("router 🛜 v2.bin"), "router 🛜 v2.bin");
        let long = format!("{}.img", "é".repeat(100));
        let s = sanitize_filename(&long);
        assert!(s.len() <= 120 && s.ends_with(".img"), "{s}");
    }

    #[test]
    fn usernames() {
        assert_eq!(sanitize_username("  kenan_01 "), "kenan_01");
        assert_eq!(sanitize_username("@handle"), "handle");
        assert_eq!(sanitize_username("evil https://x"), "anonymous");
        assert_eq!(sanitize_username("/start"), "anonymous");
        assert_eq!(sanitize_username(&"a".repeat(33)), "anonymous");
        assert_eq!(sanitize_username(""), "anonymous");
    }
}
