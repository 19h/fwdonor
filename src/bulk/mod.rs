//! Bulk donations: grant links (`/r/<token>`) whose uploads are stored on this
//! server, named by their SHA-256, instead of going to Telegram. Grants have
//! a fixed donor name and a storage ceiling and are issued on the admin page
//! (`/g/<admin key>`). Uploads are chunked and survive anything, restarts of
//! the server included: the page sends what is missing when the same file is
//! dropped again.

pub mod grants;
pub mod hasher;
pub mod http;
mod upload;

pub use upload::sync_dir;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::http::StatusCode;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::Config;
use crate::error::ApiError;
use crate::uploads::unix_now;
use grants::{Grant, GrantFile};
use upload::{Finalized, Loaded, Meta, Record, Refusal, Upload};

/// Partial uploads live in here, inside the store (renames stay on one filesystem).
const PARTIAL_DIR: &str = ".partial";
/// Finished uploads stay visible to status polling this long.
const FINISHED_TTL: u64 = 24 * 3600;
/// Stored files listed per grant on its page.
const RECENT: usize = 100;
/// A sanity bound for one file.
const MAX_FILE_BYTES: u64 = 16 << 40;
/// Uploads that had a chunk this recently count as active in /api/health.
const ACTIVE_SECS: u64 = 120;

/// Write a small file so that it is either entirely old or entirely new
/// after a crash: tmp file, fsync, rename.
pub fn write_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(match path.extension() {
        Some(ext) => format!("{}.tmp", ext.to_string_lossy()),
        None => "tmp".into(),
    });
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Free and total bytes of the filesystem holding `path`.
pub fn disk_space(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let unit = s.f_frsize as u64;
    Some((s.f_bavail as u64 * unit, s.f_blocks as u64 * unit))
}

/// Keep a file name or relative path printable and bounded.
fn clean_text(raw: &str, max: usize) -> String {
    let cleaned: String = raw.chars().map(|c| if c.is_control() { '_' } else { c }).collect();
    let mut end = cleaned.len().min(max);
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    cleaned[..end].trim().to_string()
}

/// One line of `runtime/bulk.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub sha256: String,
    pub token: String,
    pub size: u64,
    pub original_name: String,
    #[serde(default)]
    pub original_path: String,
    /// When the upload was started and finished (`at`).
    #[serde(default)]
    pub started_at: u64,
    pub at: u64,
    /// The file's modification time (ms) as the browser reported it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<u64>,
}

#[derive(Default)]
struct Usage {
    used: u64,
    files: u64,
    recent: VecDeque<LedgerEntry>,
}

impl Usage {
    fn add(&mut self, entry: LedgerEntry) {
        self.used += entry.size;
        self.files += 1;
        if self.recent.len() == RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(entry);
    }
}

enum Outcome {
    Stored(String),
    Duplicate(String),
}

struct Finished {
    token: String,
    size: u64,
    chunks: u64,
    chunk_bytes: u64,
    outcome: Outcome,
    at: u64,
}

struct Inner {
    grants: GrantFile,
    usage: HashMap<String, Usage>,
    /// Every hash in the ledger.
    stored: HashSet<String>,
    /// Every stored file, oldest first (for the dashboard).
    all: Vec<LedgerEntry>,
    uploads: HashMap<String, Arc<Upload>>,
    finished: HashMap<String, Finished>,
    /// Chunk uploads in flight per grant.
    puts: HashMap<String, usize>,
}

impl Inner {
    fn grant(&self, token: &str) -> Result<&Grant, ApiError> {
        if !grants::valid_token(token) {
            return Err(invalid_link());
        }
        match self.grants.get(token) {
            None => Err(invalid_link()),
            Some(g) if !g.live() => Err(ApiError::new(StatusCode::FORBIDDEN, "revoked", "this link was revoked")),
            Some(g) => Ok(g),
        }
    }

    /// Bytes promised to the grant's unfinished uploads.
    fn reserved(&self, token: &str) -> u64 {
        self.uploads.values().filter(|u| u.meta.token == token).map(|u| u.meta.size).sum()
    }

    fn used(&self, token: &str) -> u64 {
        self.usage.get(token).map_or(0, |u| u.used)
    }
}

fn invalid_link() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "invalid_link", "this link is not valid")
}

fn no_upload() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such upload")
}

pub struct Bulk {
    config: Arc<Config>,
    store: PathBuf,
    partials: PathBuf,
    admin_key: String,
    inner: Mutex<Inner>,
    puts: Arc<Semaphore>,
    ledger: Mutex<File>,
    /// One upload moves into the store at a time (two of the same file
    /// finishing together must not both count).
    finalizing: Mutex<()>,
}

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub name: String,
    #[serde(default)]
    pub path: String,
    pub size: u64,
    #[serde(default)]
    pub last_modified: Option<u64>,
    /// Don't resume a matching unfinished upload (it held a different file).
    #[serde(default)]
    pub fresh: bool,
}

#[derive(Debug, Serialize)]
pub struct UploadView {
    pub id: String,
    /// receiving, hashing, stored or duplicate.
    pub state: &'static str,
    pub name: String,
    pub size: u64,
    pub chunks: u64,
    pub chunk_size: u64,
    /// Bitmap of received chunks (bit i of byte i/8, LSB first), base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received: Option<String>,
    pub received_count: u64,
    pub received_bytes: u64,
    pub hashed_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub resumed: bool,
    /// Hashes of a few received chunks (index → sha256) when resuming.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub samples: Vec<(u64, String)>,
}

/// Counts for /api/health.
pub struct Activity {
    pub unfinished: usize,
    pub active: usize,
}

/// Holds a grant's and the global chunk-upload slots.
struct PutSlot {
    bulk: Arc<Bulk>,
    token: String,
    _permit: OwnedSemaphorePermit,
}

impl Drop for PutSlot {
    fn drop(&mut self) {
        let mut inner = self.bulk.inner.lock().unwrap();
        if let Some(n) = inner.puts.get_mut(&self.token) {
            *n = n.saturating_sub(1);
        }
    }
}

/// Ends a chunk upload on every path out of `put_chunk`.
struct PutTicket<'a> {
    up: &'a Upload,
    index: u64,
    writing: bool,
}

impl Drop for PutTicket<'_> {
    fn drop(&mut self) {
        self.up.end_put(self.index, self.writing);
    }
}

impl Bulk {
    /// Load grants, totals and unfinished uploads, finish what a crash
    /// interrupted, and restart the hashers. Needs the tokio runtime.
    pub fn open(config: Arc<Config>) -> Result<Arc<Self>> {
        let store = config.bulk.dir.clone();
        let partials = store.join(PARTIAL_DIR);
        std::fs::create_dir_all(&partials).with_context(|| format!("creating {}", partials.display()))?;
        let admin_key = grants::load_or_create_admin_key(&config.admin_key_path())?;
        let grants = GrantFile::load(&config.bulk_grants_path())?;

        let ledger_path = config.bulk_ledger_path();
        let mut usage: HashMap<String, Usage> = HashMap::new();
        let mut stored = HashSet::new();
        let mut all = Vec::new();
        if let Ok(f) = File::open(&ledger_path) {
            for line in std::io::BufReader::new(f).lines() {
                let Ok(line) = line else { break };
                let Ok(entry) = serde_json::from_str::<LedgerEntry>(&line) else { continue };
                if stored.insert(entry.sha256.clone()) {
                    all.push(entry.clone());
                    usage.entry(entry.token.clone()).or_default().add(entry);
                }
            }
        }
        let ledger = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&ledger_path)
            .with_context(|| format!("opening {}", ledger_path.display()))?;

        let bulk = Arc::new(Self {
            puts: Arc::new(Semaphore::new(config.bulk.max_puts)),
            config,
            store,
            partials,
            admin_key,
            inner: Mutex::new(Inner {
                grants,
                usage,
                stored,
                all,
                uploads: HashMap::new(),
                finished: HashMap::new(),
                puts: HashMap::new(),
            }),
            ledger: Mutex::new(ledger),
            finalizing: Mutex::new(()),
        });
        bulk.recover()?;
        Ok(bulk)
    }

    fn recover(self: &Arc<Self>) -> Result<()> {
        let now = unix_now();
        let ttl = self.config.bulk.partial_ttl_days * 86400;
        let mut resumed = Vec::new();
        for entry in std::fs::read_dir(&self.partials)? {
            let dir = entry?.path();
            if !dir.is_dir() {
                let _ = std::fs::remove_file(&dir);
                continue;
            }
            let grant = |token: &str| {
                let inner = self.inner.lock().unwrap();
                inner.grants.get(token).filter(|g| g.live()).map(|g| g.name.clone())
            };
            match Upload::load(&dir) {
                Err(e) => {
                    tracing::warn!("discarding unreadable bulk upload {}: {e:#}", dir.display());
                    let _ = std::fs::remove_dir_all(&dir);
                }
                Ok(Loaded::Final { meta, sha256 }) => match grant(&meta.token) {
                    Some(name) => {
                        let record = Record::new(&meta, &name, &sha256, &[], now);
                        match self.move_into_store(&meta, &dir, &sha256, &record) {
                            Ok(_) => tracing::info!(id = %meta.id, %sha256, "finished storing an upload after a restart"),
                            Err(e) => tracing::error!(id = %meta.id, "could not finish storing {}: {e}", dir.display()),
                        }
                    }
                    None => {
                        let _ = std::fs::remove_dir_all(&dir);
                    }
                },
                Ok(Loaded::Partial(up)) => {
                    if grant(&up.meta.token).is_none() || now.saturating_sub(up.state().last_activity) > ttl {
                        let _ = std::fs::remove_dir_all(&dir);
                        continue;
                    }
                    resumed.push(Arc::new(up));
                }
            }
        }
        if !resumed.is_empty() {
            tracing::info!("{} unfinished bulk upload(s) resumed", resumed.len());
        }
        for up in resumed {
            self.inner.lock().unwrap().uploads.insert(up.meta.id.clone(), up.clone());
            self.spawn_hasher(up);
        }
        Ok(())
    }

    fn spawn_hasher(self: &Arc<Self>, up: Arc<Upload>) {
        let bulk = self.clone();
        tokio::spawn(async move {
            let Some(hasher) = up.clone().hash_all().await else { return };
            let sha256 = hex::encode(hasher.finalize());
            bulk.store_upload(up, sha256).await;
        });
    }

    /// Blocking: rename into the store, record in the ledger, drop the partial.
    fn move_into_store(&self, meta: &Meta, dir: &Path, sha256: &str, record: &Record) -> std::io::Result<Finalized> {
        let _one = self.finalizing.lock().unwrap();
        let outcome = upload::finalize(&self.store, dir, sha256, record)?;
        if let Finalized::Stored = outcome {
            let entry = LedgerEntry {
                sha256: sha256.to_string(),
                token: meta.token.clone(),
                size: meta.size,
                original_name: meta.original_name.clone(),
                original_path: meta.original_path.clone(),
                started_at: meta.started_at,
                at: record.completed_at,
                last_modified: meta.last_modified,
            };
            let mut inner = self.inner.lock().unwrap();
            if !inner.stored.contains(sha256) {
                let mut line = serde_json::to_string(&entry)?;
                line.push('\n');
                let ledger = self.ledger.lock().unwrap();
                (&*ledger).write_all(line.as_bytes())?;
                ledger.sync_data()?;
                inner.stored.insert(sha256.to_string());
                inner.all.push(entry.clone());
                inner.usage.entry(meta.token.clone()).or_default().add(entry);
            }
        }
        let _ = std::fs::remove_dir_all(dir);
        Ok(outcome)
    }

    /// The whole file is hashed: move it into the store (retrying on storage
    /// errors, which can be temporary) and tell status pollers.
    async fn store_upload(self: Arc<Self>, up: Arc<Upload>, sha256: String) {
        let grant_name = {
            let inner = self.inner.lock().unwrap();
            inner.grants.get(&up.meta.token).map(|g| g.name.clone()).unwrap_or_default()
        };
        loop {
            if up.state().gone {
                return;
            }
            let record = Record::new(&up.meta, &grant_name, &sha256, &up.state().ips, unix_now());
            let (bulk, u, sha) = (self.clone(), up.clone(), sha256.clone());
            let result =
                tokio::task::spawn_blocking(move || bulk.move_into_store(&u.meta, &u.dir, &sha, &record)).await;
            match result {
                Ok(Ok(outcome)) => {
                    let duplicate = matches!(outcome, Finalized::Duplicate);
                    tracing::info!(id = %up.meta.id, grant = %grant_name, name = %up.meta.original_name,
                        size = up.meta.size, %sha256, duplicate, "bulk upload stored");
                    let mut inner = self.inner.lock().unwrap();
                    inner.uploads.remove(&up.meta.id);
                    inner.finished.insert(
                        up.meta.id.clone(),
                        Finished {
                            token: up.meta.token.clone(),
                            size: up.meta.size,
                            chunks: up.meta.chunks(),
                            chunk_bytes: up.meta.chunk_bytes,
                            outcome: if duplicate { Outcome::Duplicate(sha256) } else { Outcome::Stored(sha256) },
                            at: unix_now(),
                        },
                    );
                    return;
                }
                Ok(Err(e)) => tracing::error!(id = %up.meta.id, "storing the upload failed (retrying in 30 s): {e}"),
                Err(e) => tracing::error!(id = %up.meta.id, "storing the upload panicked (retrying in 30 s): {e}"),
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    pub fn admin_ok(&self, key: &str) -> bool {
        grants::valid_admin_key(key) && grants::ct_eq(key, &self.admin_key)
    }

    /// Whether `/r/<token>` should show the upload page.
    pub fn grant_live(&self, token: &str) -> bool {
        self.inner.lock().unwrap().grant(token).is_ok()
    }

    fn view(up: &Upload, resumed: bool) -> UploadView {
        let (received_count, received_bytes) = {
            let st = up.state();
            (st.received, st.received_bytes)
        };
        UploadView {
            id: up.meta.id.clone(),
            state: up.phase(),
            name: up.meta.original_name.clone(),
            size: up.meta.size,
            chunks: up.meta.chunks(),
            chunk_size: up.meta.chunk_bytes,
            received: Some(up.received_bitmap()),
            received_count,
            received_bytes,
            hashed_bytes: up.hashed_bytes(),
            sha256: None,
            resumed,
            samples: if resumed { up.samples() } else { Vec::new() },
        }
    }

    /// The grant page's data: name, quota, unfinished uploads, recent files.
    pub fn grant_info(&self, token: &str) -> Result<serde_json::Value, ApiError> {
        let inner = self.inner.lock().unwrap();
        let grant = inner.grant(token)?;
        let mut unfinished: Vec<_> = inner
            .uploads
            .values()
            .filter(|u| u.meta.token == token)
            .map(|u| {
                let st = u.state();
                serde_json::json!({
                    "id": u.meta.id,
                    "name": u.meta.original_name,
                    "path": u.meta.original_path,
                    "size": u.meta.size,
                    "received_bytes": st.received_bytes,
                    "last_activity": st.last_activity,
                    "started_at": u.meta.started_at,
                })
            })
            .collect();
        unfinished.sort_by_key(|u| u["started_at"].as_u64());
        let usage = inner.usage.get(token);
        let recent: Vec<_> = usage.map(|u| u.recent.iter().rev().collect()).unwrap_or_default();
        Ok(serde_json::json!({
            "name": grant.name,
            "ceiling": grant.ceiling_bytes,
            "used": inner.used(token),
            "reserved": inner.reserved(token),
            "files": usage.map_or(0, |u| u.files),
            "chunk_size": self.config.bulk.chunk_bytes,
            "max_streams": self.config.bulk.max_puts_per_grant,
            "unfinished": unfinished,
            "recent": recent,
        }))
    }

    /// Start an upload, or resume the unfinished one holding this file.
    pub fn init(self: &Arc<Self>, token: &str, req: InitRequest, ip: IpAddr) -> Result<UploadView, ApiError> {
        let now = unix_now();
        let name = clean_text(&req.name, 255);
        let path = match clean_text(&req.path, 1024) {
            p if p.is_empty() => name.clone(),
            p => p,
        };
        if name.is_empty() {
            return Err(ApiError::bad_request("the file needs a name"));
        }
        if req.size == 0 {
            return Err(ApiError::bad_request("empty files are not uploaded"));
        }
        if req.size > MAX_FILE_BYTES {
            return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "size", "files can be at most 16 TiB"));
        }
        let mut inner = self.inner.lock().unwrap();
        let grant = inner.grant(token)?.clone();

        if !req.fresh {
            let score = |m: &Meta| {
                if m.original_path == path && m.last_modified == req.last_modified {
                    3
                } else if m.original_path == path {
                    2
                } else if m.original_name == name {
                    1
                } else {
                    0
                }
            };
            let best = inner
                .uploads
                .values()
                .filter(|u| u.meta.token == token && u.meta.size == req.size && !u.state().gone)
                .map(|u| (score(&u.meta), u.state().received_bytes, u.clone()))
                .filter(|(s, _, _)| *s > 0)
                .max_by_key(|(s, r, _)| (*s, *r));
            if let Some((_, _, up)) = best {
                up.touch(now);
                drop(inner);
                tracing::info!(id = %up.meta.id, grant = %grant.name, name = %name, "bulk upload resumed");
                return Ok(Self::view(&up, true));
            }
        }

        let (used, reserved) = (inner.used(token), inner.reserved(token));
        let left = grant.ceiling_bytes.saturating_sub(used + reserved);
        if req.size > left {
            return Err(ApiError::conflict(
                "quota",
                format!("{} doesn't fit: {} of this link's {} are left", gb(req.size), gb(left), gb(grant.ceiling_bytes)),
            ));
        }
        let unfinished = inner.uploads.values().filter(|u| u.meta.token == token).count();
        if unfinished >= self.config.bulk.max_unfinished {
            return Err(ApiError::conflict("too_many", "too many unfinished uploads; finish or discard some first"));
        }
        let outstanding: u64 = inner.uploads.values().map(|u| u.meta.size - u.state().received_bytes).sum();
        if let Some((free, _)) = disk_space(&self.store) {
            if free < outstanding + req.size + self.config.bulk.min_free_bytes {
                tracing::warn!(free, outstanding, size = req.size, "bulk upload refused: disk nearly full");
                return Err(ApiError::new(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "disk_full",
                    "the server is short of disk space right now",
                )
                .retry_after(300));
            }
        }
        let meta = Meta {
            id: crate::uploads::new_id(),
            token: token.to_string(),
            original_name: name,
            original_path: path,
            size: req.size,
            last_modified: req.last_modified,
            chunk_bytes: self.config.bulk.chunk_bytes,
            ip: ip.to_string(),
            started_at: now,
        };
        let up = Arc::new(Upload::create(&self.partials, meta, now).map_err(ApiError::internal)?);
        inner.uploads.insert(up.meta.id.clone(), up.clone());
        drop(inner);
        tracing::info!(id = %up.meta.id, grant = %grant.name, name = %up.meta.original_name, size = up.meta.size, "bulk upload started");
        self.spawn_hasher(up.clone());
        Ok(Self::view(&up, false))
    }

    fn find(&self, token: &str, id: &str) -> Result<Arc<Upload>, ApiError> {
        let inner = self.inner.lock().unwrap();
        inner.grant(token)?;
        match inner.uploads.get(id) {
            Some(up) if up.meta.token == token => Ok(up.clone()),
            _ => Err(no_upload()),
        }
    }

    pub fn status(&self, token: &str, id: &str) -> Result<UploadView, ApiError> {
        let inner = self.inner.lock().unwrap();
        inner.grant(token)?;
        if let Some(up) = inner.uploads.get(id).filter(|u| u.meta.token == token) {
            return Ok(Self::view(up, false));
        }
        let f = inner.finished.get(id).filter(|f| f.token == token).ok_or_else(no_upload)?;
        let (state, sha) = match &f.outcome {
            Outcome::Stored(sha) => ("stored", sha),
            Outcome::Duplicate(sha) => ("duplicate", sha),
        };
        Ok(UploadView {
            id: id.to_string(),
            state,
            name: String::new(),
            size: f.size,
            chunks: f.chunks,
            chunk_size: f.chunk_bytes,
            received: None,
            received_count: f.chunks,
            received_bytes: f.size,
            hashed_bytes: f.size,
            sha256: Some(sha.clone()),
            resumed: false,
            samples: Vec::new(),
        })
    }

    pub async fn put_chunk(
        self: &Arc<Self>,
        token: &str,
        id: &str,
        index: u64,
        sha256: Option<&str>,
        ip: IpAddr,
        body: Body,
    ) -> Result<(), ApiError> {
        let mut body = Some(body);
        let result = self.receive_chunk(token, id, index, sha256, ip, &mut body).await;
        if let (Err(_), Some(body)) = (&result, body.take()) {
            // Take in what the client is sending anyway, so the answer reaches
            // it intact instead of as a reset connection (which the page
            // would take for an outage and retry forever).
            let _ = tokio::time::timeout(Duration::from_secs(60), async {
                let mut stream = body.into_data_stream();
                while let Some(Ok(_)) = stream.next().await {}
            })
            .await;
        }
        result
    }

    async fn receive_chunk(
        self: &Arc<Self>,
        token: &str,
        id: &str,
        index: u64,
        sha256: Option<&str>,
        ip: IpAddr,
        body: &mut Option<Body>,
    ) -> Result<(), ApiError> {
        let up = self.find(token, id)?;
        if index >= up.meta.chunks() {
            return Err(ApiError::bad_request("chunk index out of range"));
        }
        let expected: [u8; 32] = sha256
            .and_then(|h| hex::decode(h.trim()).ok())
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| ApiError::bad_request("X-Chunk-Sha256 must be the chunk's SHA-256 in hex"))?;
        let busy = || ApiError::new(StatusCode::TOO_MANY_REQUESTS, "busy", "too many chunks at once").retry_after(1);
        let _slot = {
            let permit = self.puts.clone().try_acquire_owned().map_err(|_| busy())?;
            let mut inner = self.inner.lock().unwrap();
            let n = inner.puts.entry(token.to_string()).or_default();
            if *n >= self.config.bulk.max_puts_per_grant {
                return Err(busy());
            }
            *n += 1;
            PutSlot { bulk: self.clone(), token: token.to_string(), _permit: permit }
        };
        let already = up.begin_put(index, &expected).map_err(|r| match r {
            Refusal::Gone => no_upload(),
            Refusal::Closed => ApiError::conflict("state", "this upload is complete"),
            Refusal::Changed => ApiError::conflict(
                "changed",
                "this part of the file differs from what was received before; the file has changed",
            ),
            Refusal::Busy => busy(),
        })?;
        let _ticket = PutTicket { up: &up, index, writing: !already };

        let len = up.meta.chunk_len(index) as usize;
        let mut data = Vec::with_capacity(len);
        let mut hasher = Sha256::new();
        let mut stream = body.take().expect("body is read once").into_data_stream();
        while let Some(frame) = stream.next().await {
            let frame = frame.map_err(|e| ApiError::bad_request(format!("upload interrupted: {e}")))?;
            if data.len() + frame.len() > len {
                return Err(ApiError::bad_request(format!("chunk larger than {len} bytes")));
            }
            hasher.update(&frame);
            data.extend_from_slice(&frame);
        }
        if data.len() != len {
            return Err(ApiError::bad_request(format!("chunk has {} bytes, expected {len}", data.len())));
        }
        if hasher.finalize().as_slice() != expected {
            return Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "checksum",
                "the chunk arrived damaged (its SHA-256 differs); send it again",
            ));
        }
        let now = unix_now();
        if already {
            up.touch(now);
            return Ok(());
        }
        let writer = up.clone();
        let written = tokio::task::spawn_blocking(move || writer.write_chunk(index, &data))
            .await
            .map_err(ApiError::internal)?;
        if let Err(e) = written {
            if e.raw_os_error() == Some(libc::ENOSPC) {
                tracing::error!("bulk store is full");
                return Err(ApiError::new(StatusCode::INSUFFICIENT_STORAGE, "disk_full", "the server's disk is full")
                    .retry_after(300));
            }
            return Err(ApiError::internal(format!("writing chunk: {e}")));
        }
        up.record(index, expected, &ip.to_string(), now).map_err(|e| ApiError::internal(format!("chunk log: {e}")))?;
        Ok(())
    }

    /// Give up an unfinished upload and free its reservation.
    pub fn discard(&self, token: &str, id: &str) -> Result<(), ApiError> {
        let up = {
            let mut inner = self.inner.lock().unwrap();
            inner.grant(token)?;
            match inner.uploads.get(id) {
                Some(up) if up.meta.token == token => {}
                _ => return if inner.finished.contains_key(id) { Ok(()) } else { Err(no_upload()) },
            }
            if inner.uploads[id].state().finalizing {
                return Err(ApiError::conflict("state", "this upload is complete"));
            }
            inner.uploads.remove(id).unwrap()
        };
        tracing::info!(id, name = %up.meta.original_name, "bulk upload discarded");
        Self::remove(up);
        Ok(())
    }

    fn remove(up: Arc<Upload>) {
        up.discard();
        tokio::task::spawn_blocking(move || {
            let _ = std::fs::remove_dir_all(&up.dir);
        });
    }

    // ------------------------------------------------------------ admin

    pub fn list_grants(&self) -> serde_json::Value {
        let inner = self.inner.lock().unwrap();
        let mut claimable = 0u64;
        let grants: Vec<_> = inner
            .grants
            .grants
            .iter()
            .rev()
            .map(|g| {
                let (used, reserved) = (inner.used(&g.token), inner.reserved(&g.token));
                if g.live() {
                    claimable += g.ceiling_bytes.saturating_sub(used + reserved);
                }
                serde_json::json!({
                    "token": g.token,
                    "name": g.name,
                    "note": g.note,
                    "ceiling": g.ceiling_bytes,
                    "used": used,
                    "reserved": reserved,
                    "files": inner.usage.get(&g.token).map_or(0, |u| u.files),
                    "unfinished": inner.uploads.values().filter(|u| u.meta.token == g.token).count(),
                    "created_at": g.created_at,
                    "revoked_at": g.revoked_at,
                })
            })
            .collect();
        let (free, total) = disk_space(&self.store).unwrap_or((0, 0));
        serde_json::json!({
            "grants": grants,
            "disk": { "free": free, "total": total, "min_free": self.config.bulk.min_free_bytes },
            "claimable": claimable,
            "dir": self.store,
        })
    }

    pub fn create_grant(&self, name: &str, ceiling_bytes: u64, note: &str) -> Result<Grant, ApiError> {
        let name = name.trim();
        if !grants::valid_name(name) {
            return Err(ApiError::bad_request("names are 1 to 32 letters, digits, _ . or -"));
        }
        if ceiling_bytes == 0 {
            return Err(ApiError::bad_request("the storage ceiling must be more than 0"));
        }
        let grant = Grant {
            token: grants::new_token(),
            name: name.to_string(),
            ceiling_bytes,
            note: clean_text(note, 200),
            created_at: unix_now(),
            revoked_at: None,
        };
        let mut inner = self.inner.lock().unwrap();
        inner.grants.grants.push(grant.clone());
        if let Err(e) = inner.grants.save() {
            inner.grants.grants.pop();
            return Err(ApiError::internal(format!("saving grants: {e}")));
        }
        tracing::info!(name = %grant.name, ceiling = grant.ceiling_bytes, "bulk grant created");
        Ok(grant)
    }

    /// Stored files stay; unfinished uploads are discarded.
    pub fn revoke(&self, token: &str) -> Result<(), ApiError> {
        let gone: Vec<Arc<Upload>> = {
            let mut inner = self.inner.lock().unwrap();
            let Some(g) = inner.grants.grants.iter_mut().find(|g| grants::ct_eq(&g.token, token)) else {
                return Err(invalid_link());
            };
            if g.revoked_at.is_some() {
                return Ok(());
            }
            g.revoked_at = Some(unix_now());
            let name = g.name.clone();
            if let Err(e) = inner.grants.save() {
                return Err(ApiError::internal(format!("saving grants: {e}")));
            }
            tracing::info!(%name, "bulk grant revoked");
            let ids: Vec<String> = inner
                .uploads
                .iter()
                .filter(|(_, u)| u.meta.token == token && !u.state().finalizing)
                .map(|(id, _)| id.clone())
                .collect();
            ids.iter().filter_map(|id| inner.uploads.remove(id)).collect()
        };
        for up in gone {
            Self::remove(up);
        }
        Ok(())
    }

    // ------------------------------------------------------------ dashboard

    /// Everything about bulk donations the dashboard shows. No tokens (a
    /// grant is named by `grant_id`), no notes (the admin page promises
    /// they stay there) and no addresses.
    pub fn dashboard_view(&self) -> serde_json::Value {
        let inner = self.inner.lock().unwrap();
        let mut claimable = 0u64;
        let ids: HashMap<&str, (String, String)> =
            inner.grants.grants.iter().map(|g| (g.token.as_str(), (grant_id(&g.token), g.name.clone()))).collect();
        let grant_of = |token: &str| ids.get(token).cloned().unwrap_or_else(|| ("?".into(), "?".into()));
        let grants: Vec<_> = inner
            .grants
            .grants
            .iter()
            .rev()
            .map(|g| {
                let (used, reserved) = (inner.used(&g.token), inner.reserved(&g.token));
                if g.live() {
                    claimable += g.ceiling_bytes.saturating_sub(used + reserved);
                }
                let usage = inner.usage.get(&g.token);
                serde_json::json!({
                    "id": grant_id(&g.token),
                    "name": g.name,
                    "ceiling": g.ceiling_bytes,
                    "used": used,
                    "reserved": reserved,
                    "files": usage.map_or(0, |u| u.files),
                    "unfinished": inner.uploads.values().filter(|u| u.meta.token == g.token).count(),
                    "created_at": g.created_at,
                    "revoked_at": g.revoked_at,
                    "last_at": usage.and_then(|u| u.recent.back()).map(|e| e.at),
                })
            })
            .collect();
        let mut uploads: Vec<_> = inner
            .uploads
            .values()
            .map(|u| {
                let (received, received_bytes, last_activity, puts) = {
                    let st = u.state();
                    (st.received, st.received_bytes, st.last_activity, st.puts)
                };
                let (gid, gname) = grant_of(&u.meta.token);
                serde_json::json!({
                    "id": u.meta.id,
                    "grant": gid,
                    "grant_name": gname,
                    "name": u.meta.original_name,
                    "path": u.meta.original_path,
                    "size": u.meta.size,
                    "chunks": u.meta.chunks(),
                    "chunk_size": u.meta.chunk_bytes,
                    "received_count": received,
                    "received_bytes": received_bytes,
                    "hashed_bytes": u.hashed_bytes(),
                    "phase": u.phase(),
                    "started_at": u.meta.started_at,
                    "last_activity": last_activity,
                    "streams": puts,
                    "received": u.received_bitmap(),
                })
            })
            .collect();
        uploads.sort_by_key(|u| u["started_at"].as_u64());
        let files: Vec<_> = inner
            .all
            .iter()
            .map(|e| {
                let (gid, gname) = grant_of(&e.token);
                serde_json::json!({
                    "sha256": e.sha256,
                    "grant": gid,
                    "grant_name": gname,
                    "size": e.size,
                    "name": e.original_name,
                    "path": e.original_path,
                    "started_at": if e.started_at == 0 { None } else { Some(e.started_at) },
                    "completed_at": e.at,
                    "last_modified": e.last_modified,
                })
            })
            .collect();
        let (free, total) = disk_space(&self.store).unwrap_or((0, 0));
        serde_json::json!({
            "grants": grants,
            "uploads": uploads,
            "files": files,
            "disk": { "free": free, "total": total, "min_free": self.config.bulk.min_free_bytes },
            "claimable": claimable,
            "dir": self.store,
        })
    }

    /// Totals for the dashboard's header.
    pub fn brief(&self) -> serde_json::Value {
        let inner = self.inner.lock().unwrap();
        serde_json::json!({
            "links": inner.grants.grants.iter().filter(|g| g.live()).count(),
            "files": inner.all.len(),
            "bytes": inner.all.iter().map(|e| e.size).sum::<u64>(),
            "unfinished": inner.uploads.len(),
        })
    }

    /// A stored bulk file: its path and original name.
    pub fn stored_file(&self, sha256: &str) -> Option<(PathBuf, String)> {
        let inner = self.inner.lock().unwrap();
        let e = inner.all.iter().find(|e| e.sha256 == sha256)?;
        Some((self.store.join(&e.sha256), e.original_name.clone()))
    }

    // ------------------------------------------------------------ housekeeping

    /// Drop uploads untouched for the TTL and forget old finished ones.
    pub fn sweep(&self) {
        let now = unix_now();
        let ttl = self.config.bulk.partial_ttl_days * 86400;
        let stale: Vec<Arc<Upload>> = {
            let mut inner = self.inner.lock().unwrap();
            inner.finished.retain(|_, f| now.saturating_sub(f.at) < FINISHED_TTL);
            let ids: Vec<String> = inner
                .uploads
                .iter()
                .filter(|(_, u)| {
                    let st = u.state();
                    !st.finalizing && st.puts == 0 && now.saturating_sub(st.last_activity) > ttl
                })
                .map(|(id, _)| id.clone())
                .collect();
            ids.iter().filter_map(|id| inner.uploads.remove(id)).collect()
        };
        for up in stale {
            tracing::info!(id = %up.meta.id, name = %up.meta.original_name, "bulk upload expired");
            Self::remove(up);
        }
    }

    /// Blocking: save every hash state (on shutdown), so a restart doesn't
    /// re-read what was already hashed.
    pub fn checkpoint_all(&self) {
        let uploads: Vec<Arc<Upload>> = self.inner.lock().unwrap().uploads.values().cloned().collect();
        for up in uploads {
            if let Err(e) = up.checkpoint() {
                tracing::warn!(id = %up.meta.id, "hash checkpoint failed: {e}");
            }
        }
    }

    pub fn activity(&self) -> Activity {
        let now = unix_now();
        let inner = self.inner.lock().unwrap();
        Activity {
            unfinished: inner.uploads.len(),
            active: inner.uploads.values().filter(|u| now.saturating_sub(u.state().last_activity) < ACTIVE_SECS).count(),
        }
    }
}

/// A grant's name on the dashboard: a short hash of its token.
pub fn grant_id(token: &str) -> String {
    hex::encode(&Sha256::digest(token.as_bytes())[..4])
}

/// Sizes in messages, in the decimal units ceilings are given in.
fn gb(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_sizes() {
        assert_eq!(clean_text(" a\u{0}b\n.img ", 255), "a_b_.img");
        assert_eq!(clean_text(&"é".repeat(10), 5), "éé");
        assert_eq!(gb(500_000_000_000), "500.0 GB");
        assert_eq!(gb(999), "999 B");
    }

    #[test]
    fn durable_write_replaces_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.json");
        write_durably(&path, b"one").unwrap();
        write_durably(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "no tmp file left");
        assert!(disk_space(dir.path()).is_some_and(|(free, total)| free <= total && total > 0));
    }
}
