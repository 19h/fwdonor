//! Chunked upload sessions: admission, chunk writes, server-side
//! verification, status, cancellation, and spool housekeeping.

use std::collections::{HashMap, HashSet};
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
use crate::jobs::{Job, Lane, PostQueue, Queued};
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
    /// The client classified this file with another zrax than ours: an
    /// older page, or a client with a classifier of its own.
    older_zrax: bool,
    holds_slot: bool,
    /// Bytes counted against the spool cap until the file is deleted.
    reserved: u64,
    lane: Lane,
    /// A background job being posted from the store (not from the spool).
    from_store: bool,
}

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub username: String,
    /// The proof of work; uploads with the import token need none.
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub nonce: u64,
    pub zrax_rev: String,
    #[serde(default)]
    pub lane: Lane,
    /// The client classifies with a zrax build of its own (the desktop
    /// workbench) instead of the one this server ships. Its revision is
    /// not checked: the server's own verdict decides, and a disagreement
    /// is not held against the sender.
    #[serde(default)]
    pub own_classifier: bool,
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
    /// `background` for fwdonate's uploads; the page's have none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lane: Option<Lane>,
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
    /// fwdonate's import token (`runtime/import.key`); None: no imports.
    import_key: Option<String>,
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
            import_key: None,
        }
    }

    pub fn with_import_key(mut self, key: String) -> Self {
        self.import_key = Some(key);
        self
    }

    /// Whether `presented` is the import token (compared in constant time).
    pub fn is_import_key(&self, presented: &str) -> bool {
        self.import_key.as_deref().is_some_and(|key| crate::bulk::grants::ct_eq(key, presented))
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

    /// Admit an upload. `ClientKey::IMPORT` (the import token, checked by
    /// the caller) needs no proof of work.
    pub fn init(&self, req: InitRequest, key: ClientKey) -> Result<InitResponse, ApiError> {
        self.touch();
        let limits = &self.config.limits;
        let import = key == ClientKey::IMPORT;
        if self.config.is_paused() {
            return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "paused", "donations are paused right now")
                .retry_after(600));
        }
        // A page or fwdonate runs the zrax this server shipped, so a revision
        // we don't accept means a stale copy. A client with a zrax of its own
        // has nothing to reload: it is admitted, and verification decides.
        if !req.own_classifier && !self.revisions.accepts(&req.zrax_rev, unix_now()) {
            return Err(ApiError::conflict("stale_client", "the page is out of date, please reload"));
        }
        let sha = parse_sha256(&req.sha256).ok_or_else(|| ApiError::bad_request("sha256 must be 64 hex digits"))?;
        let sha_hex = hex::encode(sha);
        if !import {
            if let Err(e) = self.pow.redeem(&req.token, &sha, req.nonce) {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "pow", e.to_string()));
            }
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
        if self.queue.contains_sha(&sha_hex) {
            return Err(ApiError::conflict("duplicate", "already received, waiting for its post"));
        }
        let reserved = self.reserved.load(Ordering::SeqCst);
        // An import leaves a quarter of the spool to donors on the page.
        let cap = if import { limits.spool_cap_bytes - limits.spool_cap_bytes / 4 } else { limits.spool_cap_bytes };
        if reserved + req.size > cap {
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
                // Either way the client's verdict may differ from ours.
                older_zrax: req.own_classifier || req.zrax_rev != self.revisions.current(),
                holds_slot: true,
                reserved: req.size,
                lane: req.lane,
                from_store: false,
            },
        );
        tracing::info!(%id, %name, size = req.size, %username, lane = ?req.lane, import, "upload admitted");
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
        let (file, sha, key, classifier_strikes, background) = {
            let mut sessions = self.sessions.lock().unwrap();
            let Some(session) = sessions.get_mut(id) else {
                // Verified and handed to the background lane (a client retry).
                if self.queue.has_background(id) {
                    return Ok(());
                }
                return Err(ApiError::not_found());
            };
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
            // A background upload keeps its slot until it is verified, so a
            // run can't pile up files waiting for verification.
            let background = session.lane == Lane::Background;
            if !background && std::mem::take(&mut session.holds_slot) {
                if let Some(key) = session.key {
                    self.limiter.release(key);
                }
            }
            // A page on an older zrax may disagree with our verdict without
            // doing anything wrong: that must not count towards a ban.
            let classifier_strikes = !session.older_zrax;
            (session.file.clone(), session.sha256.clone(), session.key, classifier_strikes, background)
        };

        let this = Arc::clone(self);
        let id = id.to_string();
        tokio::spawn(async move {
            let path = file.clone();
            let actual = tokio::task::spawn_blocking(move || sha256_file(&path)).await;
            let (verdict, key) = match actual {
                Ok(Ok(actual)) if actual == sha => {
                    (this.analyzer.analyze_donation(file, background).await, key.filter(|_| classifier_strikes))
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
                let (job, lane) = {
                    let mut sessions = self.sessions.lock().unwrap();
                    let Some(session) = sessions.get_mut(id) else { return };
                    let job = Job {
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
                    };
                    (job, session.lane)
                };
                // Keep a copy before posting, so the image stays even if
                // posting fails. For a web donation a storage error here must
                // not cost the donation, so it is only logged.
                let (store, file, record) = (self.firmwares.clone(), job.file.clone(), Record::for_upload(&job));
                let kept = match tokio::task::spawn_blocking(move || store.keep(&file, &record)).await {
                    Ok(Ok(())) => true,
                    Ok(Err(e)) => {
                        tracing::error!(%id, sha256 = %job.sha256, "keeping the firmware failed: {e}");
                        false
                    }
                    Err(e) => {
                        tracing::error!(%id, sha256 = %job.sha256, "keeping the firmware panicked: {e}");
                        false
                    }
                };
                // A background job is posted from the store's copy.
                if lane == Lane::Background {
                    if kept {
                        self.hand_off(job).await;
                    } else {
                        self.finish(id, UploadState::Failed { reason: "server storage error".into() });
                    }
                    return;
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

    /// A verified background upload goes to the background lane. From here
    /// on its file is the store's copy: the spool copy, the reservation, the
    /// client's slot and the session go.
    async fn hand_off(&self, job: Job) {
        let id = job.id.clone();
        let queued = Queued {
            id: job.id.clone(),
            sha256: job.sha256.clone(),
            name: job.name.clone(),
            size: job.size,
            username: job.username.clone(),
            created_at: job.created_at,
            attempts: 0,
        };
        let (dir, spool, sidecar) = (self.config.background_dir(), self.spool().to_owned(), queued.clone());
        let written = tokio::task::spawn_blocking(move || {
            sidecar.write(&dir)?;
            let _ = std::fs::remove_dir_all(Job::dir(&spool, &sidecar.id));
            Ok::<_, std::io::Error>(())
        })
        .await;
        if let Err(e) = written.map_err(std::io::Error::other).and_then(|r| r) {
            tracing::error!(%id, "writing the background job failed: {e}");
            self.finish(&id, UploadState::Failed { reason: "server storage error".into() });
            return;
        }
        // In one step for `init`: the hash is always either in a session or
        // in the lane.
        let session = {
            let mut sessions = self.sessions.lock().unwrap();
            let session = sessions.remove(&id);
            if !self.queue.push_background(queued) {
                tracing::warn!(%id, sha256 = %job.sha256, "already waiting in the background lane");
                let _ = std::fs::remove_file(Queued::sidecar(&self.config.background_dir(), &id));
            }
            session
        };
        if let Some(session) = session {
            self.reserved.fetch_sub(session.reserved, Ordering::SeqCst);
            if session.holds_slot {
                if let Some(key) = session.key {
                    self.limiter.release(key);
                }
            }
        }
        tracing::info!(%id, name = %job.name, format = %job.summary.format, isa = ?job.summary.isa, "verified, queued in the background");
    }

    /// The poster starts on a background job (staged from the store).
    pub fn begin_posting(&self, job: &Job) {
        self.sessions.lock().unwrap().insert(
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
                state: UploadState::Posting,
                summary: Some(job.summary.clone()),
                older_zrax: false,
                holds_slot: false,
                reserved: 0,
                lane: Lane::Background,
                from_store: true,
            },
        );
    }

    /// Blocking. A background post failed: back to the end of its donor's
    /// turn, one attempt more.
    pub fn requeue_background(&self, mut job: Queued) -> std::io::Result<()> {
        job.attempts += 1;
        job.write(&self.config.background_dir())?;
        self.firmwares.unstage(&job.id);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&job.id);
        self.queue.push_background(job);
        Ok(())
    }

    /// Blocking. A background job that won't be posted (it was posted
    /// already, or the stored copy is gone) before it had a session.
    pub fn drop_background(&self, id: &str) {
        let _ = std::fs::remove_file(Queued::sidecar(&self.config.background_dir(), id));
        self.firmwares.unstage(id);
        self.queue.release(id);
    }

    pub fn set_state(&self, id: &str, state: UploadState) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(id) {
            session.state = state;
            session.last_activity = Instant::now();
        }
    }

    /// Enter a final state and delete everything spooled for the upload.
    pub fn finish(&self, id: &str, state: UploadState) {
        let (reserved, from_store) = {
            let mut sessions = self.sessions.lock().unwrap();
            let Some(session) = sessions.get_mut(id) else { return };
            session.state = state;
            session.last_activity = Instant::now();
            if std::mem::take(&mut session.holds_slot) {
                if let Some(key) = session.key {
                    self.limiter.release(key);
                }
            }
            (std::mem::take(&mut session.reserved), session.from_store)
        };
        if from_store {
            let _ = std::fs::remove_file(Queued::sidecar(&self.config.background_dir(), id));
            self.firmwares.unstage(id);
        } else {
            let _ = std::fs::remove_file(Job::sidecar(self.spool(), id));
            let _ = std::fs::remove_dir_all(Job::dir(self.spool(), id));
        }
        self.reserved.fetch_sub(reserved, Ordering::SeqCst);
    }

    pub fn status(&self, id: &str) -> Result<StatusResponse, ApiError> {
        self.touch();
        let sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get(id) else {
            if self.queue.has_background(id) {
                return Ok(StatusResponse {
                    state: UploadState::Queued,
                    position: None,
                    received: 0,
                    chunks: 0,
                    summary: None,
                    lane: Some(Lane::Background),
                });
            }
            return Err(ApiError::not_found());
        };
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
            lane: (session.lane == Lane::Background).then_some(Lane::Background),
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
        let mut posted_before_crash = HashSet::new();
        let mut sessions = self.sessions.lock().unwrap();
        for job in jobs {
            if self.ledger.contains(&job.sha256) {
                // Posted before a crash but not yet cleaned up. Its copy may
                // not know where it was posted yet (noted below).
                if let Err(e) = self.firmwares.keep(&job.file, &Record::for_upload(&job)) {
                    tracing::error!(id = %job.id, sha256 = %job.sha256, "keeping the firmware failed: {e}");
                }
                posted_before_crash.insert(job.sha256.clone());
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
                    lane: Lane::Web,
                    from_store: false,
                },
            );
            self.queue.push(job);
        }
        drop(sessions);
        self.note_posts(&posted_before_crash)?;
        Ok(count)
    }

    /// Startup, after `recover`: the background lane from its sidecars.
    pub fn recover_background(&self) -> anyhow::Result<usize> {
        let dir = self.config.background_dir();
        std::fs::create_dir_all(&dir)?;
        let mut jobs = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let Some(id) = name.strip_suffix(".json") else {
                // A temporary file from a crash.
                let _ = std::fs::remove_file(&path);
                continue;
            };
            match std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Queued>(&b).ok()) {
                Some(job) if job.id == id && valid_id(id) => jobs.push(job),
                _ => {
                    tracing::warn!("discarding unreadable background job {}", path.display());
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        jobs.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        let (mut count, mut posted) = (0, HashSet::new());
        for job in jobs {
            let sidecar = Queued::sidecar(&dir, &job.id);
            if self.ledger.contains(&job.sha256) {
                // Posted just before a restart.
                posted.insert(job.sha256.clone());
                let _ = std::fs::remove_file(&sidecar);
            } else if !self.firmwares.has(&job.sha256) {
                tracing::warn!(id = %job.id, sha256 = %job.sha256, "the stored copy of a background job is gone; dropping it");
                let _ = std::fs::remove_file(&sidecar);
            } else if self.in_flight(&job.sha256) || !self.queue.push_background(job) {
                let _ = std::fs::remove_file(&sidecar);
            } else {
                count += 1;
            }
        }
        self.note_posts(&posted)?;
        Ok(count)
    }

    /// Note in the records where these (posted before a crash) went.
    fn note_posts(&self, shas: &HashSet<String>) -> anyhow::Result<()> {
        if shas.is_empty() {
            return Ok(());
        }
        for entry in self.ledger.entries()?.into_iter().filter(|e| shas.contains(&e.sha256)) {
            let posted = Posted::new(self.config.telegram.chat_id, entry.message_id, entry.posted_at);
            if let Err(e) = self.firmwares.mark_posted(&entry.sha256, posted) {
                tracing::error!(sha256 = %entry.sha256, "noting the post in the firmware record failed: {e}");
            }
        }
        Ok(())
    }

    /// Whether an upload of this hash is in progress (not yet posted/failed),
    /// the background lane included.
    pub fn in_flight(&self, sha256: &str) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions.values().any(|s| s.sha256 == sha256 && !s.state.is_final()) || self.queue.contains_sha(sha256)
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
    use crate::jobs::Next;

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

    struct Fixture {
        _dir: tempfile::TempDir,
        config: Arc<Config>,
        ledger: Arc<Ledger>,
        firmwares: Arc<Firmwares>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with(|_| {})
        }

        fn with(edit: impl FnOnce(&mut Config)) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mut config = Config::default();
            edit(&mut config);
            config.runtime_dir = dir.path().join("runtime");
            config.spool_dir = dir.path().join("spool");
            config.firmware_dir = dir.path().join("firmwares");
            for d in [&config.runtime_dir, &config.spool_dir] {
                std::fs::create_dir_all(d).unwrap();
            }
            let ledger = Arc::new(Ledger::open(&config.ledger_path()).unwrap());
            let catalog = Arc::new(crate::dashboard::catalog::Catalog::new());
            let firmwares = Arc::new(Firmwares::open(&config.firmware_dir, catalog).unwrap());
            Self { _dir: dir, config: Arc::new(config), ledger, firmwares }
        }

        /// A server as after a (re)start: its own queue, recovered.
        fn uploads(&self) -> (Arc<Uploads>, Arc<PostQueue>) {
            let queue = Arc::new(PostQueue::default());
            let uploads = Arc::new(Uploads::new(
                self.config.clone(),
                Arc::new(PowGate::new(0, 60)),
                Arc::new(Limiter::new(self.config.limits.clone())),
                self.ledger.clone(),
                Analyzer::new(1, Duration::from_secs(5), Arc::new(self.config.policy.clone())),
                queue.clone(),
                Arc::new(Revisions::open(&self.config.zrax_revs_path(), "rev", 0).unwrap()),
                self.firmwares.clone(),
            ));
            uploads.recover().unwrap();
            uploads.recover_background().unwrap();
            (uploads, queue)
        }
    }

    #[test]
    fn imports_need_no_proof_of_work_and_leave_spool_for_the_page() {
        let f = Fixture::with(|c| {
            c.limits.import_concurrent = 2;
            c.limits.spool_cap_bytes = 4000;
        });
        let (uploads, _) = f.uploads();
        let uploads = Arc::into_inner(uploads).unwrap().with_import_key("k".repeat(43));
        assert!(uploads.is_import_key(&"k".repeat(43)));
        assert!(!uploads.is_import_key(&"k".repeat(42)) && !uploads.is_import_key(""));
        let req = |n: u8, size: u64| InitRequest {
            name: "fw.bin".into(),
            size,
            sha256: format!("{n:02x}").repeat(32),
            username: "importer".into(),
            token: String::new(),
            nonce: 0,
            zrax_rev: "rev".into(),
            lane: Lane::Background,
            own_classifier: false,
        };
        let address = ClientKey::from_ip("10.0.0.9".parse().unwrap());
        assert_eq!(uploads.init(req(1, 1000), address).unwrap_err().code, "pow", "an address needs the proof of work");
        // An import may fill 3/4 of the spool (3000 of 4000 bytes)...
        assert!(uploads.init(req(2, 1400), ClientKey::IMPORT).is_ok());
        let busy = uploads.init(req(3, 1700), ClientKey::IMPORT).unwrap_err();
        assert_eq!((busy.code, uploads.reserved_bytes()), ("busy", 1400), "the last quarter is the page's");
        assert!(uploads.init(req(4, 1400), ClientKey::IMPORT).is_ok());
        // ... in `import_concurrent` uploads at once.
        assert_eq!(uploads.init(req(5, 100), ClientKey::IMPORT).unwrap_err().code, "limited");
    }

    fn summary() -> Summary {
        serde_json::from_value(serde_json::json!({
            "format": "elf", "format_name": "ELF", "bitwidth": 64, "endianness": "little", "confidence": 1.0,
            "source": "container", "basis": "isa", "zrax": "x", "slices": [], "metadata": []
        }))
        .unwrap()
    }

    /// A background upload as `complete` leaves it: verifying, spooled,
    /// holding its reservation.
    fn verifying(uploads: &Uploads, id: &str, sha: &str, donor: &str) {
        let dir = Job::dir(uploads.spool(), id);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{id}.bin"));
        std::fs::write(&file, sha.as_bytes()).unwrap();
        uploads.reserved.fetch_add(64, Ordering::SeqCst);
        uploads.sessions.lock().unwrap().insert(
            id.into(),
            Session {
                key: None,
                name: format!("{id}.bin"),
                size: 64,
                sha256: sha.into(),
                username: donor.into(),
                chunks: vec![true],
                file,
                last_activity: Instant::now(),
                state: UploadState::Verifying,
                summary: None,
                older_zrax: false,
                holds_slot: false,
                reserved: 64,
                lane: Lane::Background,
                from_store: false,
            },
        );
    }

    #[tokio::test]
    async fn background_uploads_wait_in_the_store_not_the_spool() {
        let f = Fixture::new();
        let (uploads, queue) = f.uploads();
        let (a, b, c) = ("a".repeat(24), "b".repeat(24), "c".repeat(24));
        let (sha_a, sha_b, sha_c) = ("1".repeat(64), "2".repeat(64), "3".repeat(64));
        for (id, sha) in [(&a, &sha_a), (&b, &sha_b), (&c, &sha_c)] {
            verifying(&uploads, id, sha, "cli_donor");
            uploads.finish_verification(id, Verdict::Accepted(summary()), None).await;
        }
        assert_eq!(uploads.reserved_bytes(), 0, "no spool space held");
        assert_eq!(std::fs::read_dir(uploads.spool()).unwrap().count(), 0, "spool is empty");
        assert_eq!(queue.background(), (3, 192));
        assert_eq!(queue.len(), 0, "nothing in the web lane");
        assert!(uploads.in_flight(&sha_a) && f.firmwares.has(&sha_a));
        let status = serde_json::to_value(uploads.status(&a).unwrap()).unwrap();
        assert_eq!((status["state"].as_str(), status["lane"].as_str()), (Some("queued"), Some("background")));
        assert!(uploads.complete(&a).is_ok(), "a retried completion is fine");
        assert_eq!(uploads.active(), 0, "waiting jobs don't hold deploys");

        // The poster takes `a` and posts it from the store.
        let Some(Next::Background(job)) = queue.pop() else { panic!("expected a background job") };
        let staged = f.firmwares.stage(&job.sha256, &job.id, &job.name).unwrap();
        let posting = Job {
            id: job.id.clone(),
            name: job.name.clone(),
            size: job.size,
            sha256: job.sha256.clone(),
            username: job.username.clone(),
            summary: summary(),
            file: staged.clone(),
            created_at: job.created_at,
        };
        uploads.begin_posting(&posting);
        queue.release(&job.id);
        assert!(uploads.in_flight(&sha_a) && uploads.active() == 1, "posting counts as active");
        uploads.finish(&job.id, UploadState::Posted);
        assert!(!staged.exists() && f.firmwares.has(&sha_a), "the staged name goes, the stored copy stays");
        assert!(!Queued::sidecar(&f.config.background_dir(), &a).exists());

        // `b` was posted just before a crash (ledger written, sidecar not yet
        // removed), `c` waits; a sidecar for a vanished image and debris.
        f.ledger
            .record(&crate::ledger::Entry {
                sha256: sha_b.clone(),
                name: "b.bin".into(),
                size: 64,
                username: "cli_donor".into(),
                format: "elf".into(),
                isa: None,
                isas: vec![],
                message_id: 9 << 20,
                posted_at: 5,
            })
            .unwrap();
        let gone = Queued { id: "d".repeat(24), sha256: "4".repeat(64), name: "d.bin".into(), size: 1, username: "x".into(), created_at: 0, attempts: 0 };
        gone.write(&f.config.background_dir()).unwrap();
        std::fs::write(f.config.background_dir().join("junk.json"), b"{").unwrap();
        std::fs::write(f.config.background_dir().join("e.json.tmp"), b"half").unwrap();
        drop((uploads, queue));

        let (uploads, queue) = f.uploads();
        assert_eq!(queue.background(), (1, 64), "only c is left to post");
        let mut left: Vec<String> = std::fs::read_dir(f.config.background_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, [format!("{c}.json")]);
        assert_eq!(f.firmwares.record(&sha_b).unwrap().unwrap().telegram.unwrap().message_id, 9 << 20, "b's record knows its post");
        assert!(uploads.in_flight(&sha_c) && !uploads.in_flight(&sha_b));
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
