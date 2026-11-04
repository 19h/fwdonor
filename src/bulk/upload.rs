//! One bulk upload in progress: its partial directory, the chunks received so
//! far, and the rolling whole-file hash that follows the received prefix.
//!
//! ```text
//! .partial/<id>/data         the file, sparse until every chunk is written
//!               upload.json  Meta
//!               chunks.log   "<index> <sha256>" per received chunk, "-<index>" when one
//!                            is dropped again, "@<ip>" for every further sending address
//!               hash.state   SHA-256 over chunks 0..next (hasher.rs)
//!               final.json   the file's hash, written before it moves into the store
//!               record.json  its <sha256>.json, until that is in place
//! ```
//!
//! Durability: `hash.state` is written only after the data and the log it
//! covers are fsynced, so a checkpoint never vouches for data a crash lost.
//! Chunks past the checkpoint that were received before a restart are hashed
//! again as the hasher reads them; one that doesn't match its log entry (a
//! write lost to a power failure) is dropped and has to be sent again.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use super::hasher;
use super::write_durably;

pub const DATA: &str = "data";
const META: &str = "upload.json";
const LOG: &str = "chunks.log";
const STATE: &str = "hash.state";
const FINAL: &str = "final.json";
const RECORD: &str = "record.json";

/// Hash checkpoints are at most this far apart (each one fsyncs the data).
const CHECKPOINT_BYTES: u64 = 1 << 30;
/// ...and are also written when the hasher has been idle this long.
const IDLE_CHECKPOINT: Duration = Duration::from_secs(10);
/// Chunks the hasher reads per blocking batch.
const BATCH: usize = 16;
/// Sending addresses remembered per upload.
const MAX_IPS: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub id: String,
    pub token: String,
    pub original_name: String,
    pub original_path: String,
    pub size: u64,
    /// The file's modification time (ms) as the browser reported it.
    #[serde(default)]
    pub last_modified: Option<u64>,
    pub chunk_bytes: u64,
    /// The address that started the upload.
    pub ip: String,
    pub started_at: u64,
}

impl Meta {
    pub fn chunks(&self) -> u64 {
        self.size.div_ceil(self.chunk_bytes)
    }

    pub fn chunk_len(&self, index: u64) -> u64 {
        self.chunk_bytes.min(self.size - index * self.chunk_bytes)
    }
}

/// `<sha256>.json` next to a stored file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub sha256: String,
    pub size: u64,
    /// The grant's token and donor name.
    pub token: String,
    pub name: String,
    pub original_name: String,
    pub original_path: String,
    pub ip: String,
    /// Every address that sent chunks, when there was more than one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<u64>,
    pub started_at: u64,
    pub completed_at: u64,
}

impl Record {
    pub fn new(meta: &Meta, grant_name: &str, sha256: &str, ips: &[String], now: u64) -> Self {
        Self {
            sha256: sha256.to_string(),
            size: meta.size,
            token: meta.token.clone(),
            name: grant_name.to_string(),
            original_name: meta.original_name.clone(),
            original_path: meta.original_path.clone(),
            ip: meta.ip.clone(),
            ips: if ips.len() > 1 { ips.to_vec() } else { Vec::new() },
            last_modified: meta.last_modified,
            started_at: meta.started_at,
            completed_at: now,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FinalFile {
    sha256: String,
}

pub struct State {
    chunks: Vec<Option<[u8; 32]>>,
    /// Received by this process: on disk exactly as verified, no need to
    /// check it again when hashing.
    fresh: Vec<bool>,
    /// Chunk indices being written right now.
    writing: HashSet<u64>,
    pub received: u64,
    pub received_bytes: u64,
    pub ips: Vec<String>,
    pub last_activity: u64,
    /// Chunks 0..hashed are in `hasher`.
    pub hashed: u64,
    /// None while the hasher task works on a batch.
    hasher: Option<Sha256>,
    checkpointed: u64,
    /// Chunk uploads in flight.
    pub puts: usize,
    /// Discarded: everything about it is being deleted.
    pub gone: bool,
    /// Fully hashed and moving into the store.
    pub finalizing: bool,
}

pub struct Upload {
    pub meta: Meta,
    pub dir: PathBuf,
    file: File,
    log: File,
    st: Mutex<State>,
    wake: Notify,
    checkpointing: Mutex<()>,
}

/// Why a chunk upload can't go ahead.
pub enum Refusal {
    Gone,
    Closed,
    /// A different chunk was already received at this index.
    Changed,
    /// The same chunk is being written by another request.
    Busy,
}

pub enum Loaded {
    Partial(Upload),
    /// Fully hashed before a restart; the move into the store has to finish.
    Final { meta: Meta, sha256: String },
}

enum Problem {
    Io(io::Error),
    Mismatch(u64),
}

/// Apply a chunks.log: received chunks, dropped ones, sending addresses. An
/// unterminated last line (torn by a crash) is ignored.
fn parse_log(text: &[u8], chunks: &mut [Option<[u8; 32]>], ips: &mut Vec<String>) {
    let complete = match text.iter().rposition(|&b| b == b'\n') {
        Some(end) => &text[..end],
        None => return,
    };
    for line in complete.split(|&b| b == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else { continue };
        if let Some(ip) = line.strip_prefix('@') {
            if !ips.iter().any(|i| i == ip) && ips.len() < MAX_IPS {
                ips.push(ip.to_string());
            }
        } else if let Some(index) = line.strip_prefix('-') {
            if let Some(slot) = index.parse::<usize>().ok().and_then(|i| chunks.get_mut(i)) {
                *slot = None;
            }
        } else if let Some((index, hash)) = line.split_once(' ') {
            let hash = hex::decode(hash).ok().and_then(|h| <[u8; 32]>::try_from(h).ok());
            if let (Some(slot), Some(hash)) = (index.parse::<usize>().ok().and_then(|i| chunks.get_mut(i)), hash) {
                *slot = Some(hash);
            }
        }
    }
}

fn mtime_secs(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    modified.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// Bit i = chunk i received (LSB first), base64.
fn bitmap(chunks: &[Option<[u8; 32]>]) -> String {
    let mut bytes = vec![0u8; chunks.len().div_ceil(8)];
    for (i, c) in chunks.iter().enumerate() {
        if c.is_some() {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Fsync a directory so renames into it survive a crash (best effort: not
/// every platform allows it).
pub fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

impl Upload {
    fn assemble(meta: Meta, dir: PathBuf, file: File, log: File, state: State) -> Self {
        Self { meta, dir, file, log, st: Mutex::new(state), wake: Notify::new(), checkpointing: Mutex::new(()) }
    }

    /// A new partial directory under `root` with a sparse data file.
    pub fn create(root: &Path, meta: Meta, now: u64) -> io::Result<Self> {
        let dir = root.join(&meta.id);
        std::fs::create_dir(&dir)?;
        let made = (|| {
            let file = OpenOptions::new().read(true).write(true).create_new(true).open(dir.join(DATA))?;
            file.set_len(meta.size)?;
            // Not fsynced: if a crash loses it, the partial is simply dropped
            // and the page starts this file again.
            let tmp = dir.join(format!("{META}.tmp"));
            std::fs::write(&tmp, serde_json::to_vec(&meta)?)?;
            std::fs::rename(&tmp, dir.join(META))?;
            let log = OpenOptions::new().append(true).create(true).open(dir.join(LOG))?;
            Ok((file, log))
        })();
        let (file, log) = match made {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let count = meta.chunks() as usize;
        let state = State {
            chunks: vec![None; count],
            fresh: vec![false; count],
            writing: HashSet::new(),
            received: 0,
            received_bytes: 0,
            ips: vec![meta.ip.clone()],
            last_activity: now,
            hashed: 0,
            hasher: Some(Sha256::new()),
            checkpointed: 0,
            puts: 0,
            gone: false,
            finalizing: false,
        };
        Ok(Self::assemble(meta, dir, file, log, state))
    }

    /// Read a partial directory back after a restart.
    pub fn load(dir: &Path) -> anyhow::Result<Loaded> {
        let meta: Meta = serde_json::from_slice(&std::fs::read(dir.join(META))?)?;
        anyhow::ensure!(meta.chunk_bytes > 0 && meta.size > 0, "invalid upload.json");
        if let Ok(bytes) = std::fs::read(dir.join(FINAL)) {
            let f: FinalFile = serde_json::from_slice(&bytes)?;
            return Ok(Loaded::Final { meta, sha256: f.sha256 });
        }
        let count = meta.chunks() as usize;
        let mut chunks = vec![None; count];
        let mut ips = vec![meta.ip.clone()];
        let log_path = dir.join(LOG);
        let last_activity = mtime_secs(&log_path).into_iter().chain(mtime_secs(&dir.join(META))).max().unwrap_or(0);
        parse_log(&std::fs::read(&log_path).unwrap_or_default(), &mut chunks, &mut ips);
        // Rewrite it compactly, which also removes a torn last line that a
        // later append would otherwise glue onto.
        let mut compact = String::new();
        for ip in ips.iter().skip(1) {
            compact.push_str(&format!("@{ip}\n"));
        }
        for (i, hash) in chunks.iter().enumerate() {
            if let Some(hash) = hash {
                compact.push_str(&format!("{i} {}\n", hex::encode(hash)));
            }
        }
        write_durably(&log_path, compact.as_bytes())?;
        let file = OpenOptions::new().read(true).write(true).open(dir.join(DATA))?;
        anyhow::ensure!(file.metadata()?.len() == meta.size, "data file has the wrong size");
        let log = OpenOptions::new().append(true).open(&log_path)?;

        let (hashed, hasher) = match hasher::load(&dir.join(STATE)) {
            Some((next, h)) if next as usize <= count && chunks[..next as usize].iter().all(Option::is_some) => (next, h),
            _ => (0, Sha256::new()),
        };
        let received = chunks.iter().filter(|c| c.is_some()).count() as u64;
        let received_bytes = (0..count as u64).filter(|&i| chunks[i as usize].is_some()).map(|i| meta.chunk_len(i)).sum();
        let state = State {
            chunks,
            fresh: vec![false; count],
            writing: HashSet::new(),
            received,
            received_bytes,
            ips,
            last_activity,
            hashed,
            hasher: Some(hasher),
            checkpointed: hashed,
            puts: 0,
            gone: false,
            finalizing: false,
        };
        Ok(Loaded::Partial(Self::assemble(meta, dir.to_owned(), file, log, state)))
    }

    pub fn state(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap()
    }

    /// `receiving` until every chunk is in, then `hashing` until it is stored.
    pub fn phase(&self) -> &'static str {
        let st = self.state();
        if st.received < self.meta.chunks() {
            "receiving"
        } else {
            "hashing"
        }
    }

    pub fn received_bitmap(&self) -> String {
        bitmap(&self.state().chunks)
    }

    pub fn hashed_bytes(&self) -> u64 {
        (self.state().hashed * self.meta.chunk_bytes).min(self.meta.size)
    }

    /// Hashes of a few received chunks, for the page to check that the file
    /// it was given is the one this upload holds.
    pub fn samples(&self) -> Vec<(u64, String)> {
        let st = self.state();
        let have: Vec<u64> = (0..st.chunks.len() as u64).filter(|&i| st.chunks[i as usize].is_some()).collect();
        if have.is_empty() {
            return Vec::new();
        }
        let last = have.len() - 1;
        let mut picks = vec![have[0], have[last / 3], have[2 * last / 3], have[last]];
        picks.dedup();
        picks.into_iter().map(|i| (i, hex::encode(st.chunks[i as usize].unwrap()))).collect()
    }

    /// Admit a chunk upload. Ok(true): this exact chunk is already here and
    /// needn't be written again. The caller must call `end_put` afterwards.
    pub fn begin_put(&self, index: u64, hash: &[u8; 32]) -> Result<bool, Refusal> {
        let mut st = self.state();
        if st.gone {
            return Err(Refusal::Gone);
        }
        let have = st.chunks[index as usize];
        match have {
            Some(h) if &h == hash => {
                st.puts += 1;
                return Ok(true);
            }
            Some(_) => return Err(Refusal::Changed),
            None => {}
        }
        if st.finalizing {
            return Err(Refusal::Closed);
        }
        if !st.writing.insert(index) {
            return Err(Refusal::Busy);
        }
        st.puts += 1;
        Ok(false)
    }

    pub fn end_put(&self, index: u64, was_writing: bool) {
        let mut st = self.state();
        st.puts = st.puts.saturating_sub(1);
        if was_writing {
            st.writing.remove(&index);
        }
    }

    /// Blocking.
    pub fn write_chunk(&self, index: u64, data: &[u8]) -> io::Result<()> {
        self.file.write_all_at(data, index * self.meta.chunk_bytes)
    }

    /// The chunk is on disk: note it in the log and wake the hasher.
    pub fn record(&self, index: u64, hash: [u8; 32], ip: &str, now: u64) -> io::Result<()> {
        let mut st = self.state();
        if st.gone {
            return Ok(());
        }
        let mut line = String::new();
        if !st.ips.iter().any(|i| i == ip) && st.ips.len() < MAX_IPS {
            st.ips.push(ip.to_string());
            line.push_str(&format!("@{ip}\n"));
        }
        let i = index as usize;
        if st.chunks[i].is_none() {
            line.push_str(&format!("{index} {}\n", hex::encode(hash)));
        }
        if !line.is_empty() {
            (&self.log).write_all(line.as_bytes())?;
        }
        if st.chunks[i].is_none() {
            st.chunks[i] = Some(hash);
            st.fresh[i] = true;
            st.received += 1;
            st.received_bytes += self.meta.chunk_len(index);
        }
        st.last_activity = now;
        drop(st);
        self.wake.notify_one();
        Ok(())
    }

    pub fn touch(&self, now: u64) {
        self.state().last_activity = now;
    }

    /// Stop everything; the caller deletes the directory.
    pub fn discard(&self) {
        self.state().gone = true;
        self.wake.notify_one();
    }

    /// Follow the received prefix until the whole file is hashed. None if the
    /// upload was discarded first.
    pub async fn hash_all(self: Arc<Self>) -> Option<Sha256> {
        let count = self.meta.chunks();
        loop {
            let work = {
                let mut st = self.state();
                if st.gone {
                    return None;
                }
                if st.hashed == count {
                    st.finalizing = true;
                    return st.hasher.take();
                }
                let mut items = Vec::new();
                let mut i = st.hashed;
                while i < count && items.len() < BATCH {
                    match st.chunks[i as usize] {
                        Some(hash) => items.push((i, hash, st.fresh[i as usize])),
                        None => break,
                    }
                    i += 1;
                }
                if items.is_empty() {
                    None
                } else {
                    Some((st.hasher.take().expect("only the hash task takes the hasher"), items))
                }
            };
            let Some((hasher, items)) = work else {
                // Waiting for chunks: make the progress so far durable if the
                // upload pauses for a while.
                tokio::select! {
                    _ = self.wake.notified() => {}
                    _ = tokio::time::sleep(IDLE_CHECKPOINT) => {
                        let up = self.clone();
                        if let Ok(Err(e)) = tokio::task::spawn_blocking(move || up.checkpoint()).await {
                            tracing::warn!(id = %self.meta.id, "hash checkpoint failed: {e}");
                        }
                    }
                }
                continue;
            };
            let up = self.clone();
            let Ok((hasher, done, problem)) = tokio::task::spawn_blocking(move || up.hash_batch(hasher, &items)).await
            else {
                tracing::error!(id = %self.meta.id, "hashing task panicked; the upload stays unfinished until a restart");
                return None;
            };
            let behind = {
                let mut st = self.state();
                st.hasher = Some(hasher);
                st.hashed += done;
                match &problem {
                    Some(Problem::Mismatch(index)) => {
                        let i = *index as usize;
                        if st.chunks[i].take().is_some() {
                            st.received -= 1;
                            st.received_bytes -= self.meta.chunk_len(*index);
                            let _ = (&self.log).write_all(format!("-{index}\n").as_bytes());
                        }
                        tracing::warn!(id = %self.meta.id, index, "chunk on disk doesn't match what was received; asking for it again");
                    }
                    Some(Problem::Io(e)) => tracing::error!(id = %self.meta.id, "reading for the hash failed: {e}"),
                    None => {}
                }
                (st.hashed - st.checkpointed) * self.meta.chunk_bytes >= CHECKPOINT_BYTES
            };
            if matches!(problem, Some(Problem::Io(_))) {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            if behind {
                let up = self.clone();
                if let Ok(Err(e)) = tokio::task::spawn_blocking(move || up.checkpoint()).await {
                    tracing::warn!(id = %self.meta.id, "hash checkpoint failed: {e}");
                }
            }
        }
    }

    /// Blocking: hash consecutive chunks, checking the ones that were
    /// received before a restart against their log entries.
    fn hash_batch(&self, mut hasher: Sha256, items: &[(u64, [u8; 32], bool)]) -> (Sha256, u64, Option<Problem>) {
        let mut buf = vec![0u8; self.meta.chunk_bytes as usize];
        let mut done = 0;
        for &(index, expected, fresh) in items {
            let chunk = &mut buf[..self.meta.chunk_len(index) as usize];
            if let Err(e) = self.file.read_exact_at(chunk, index * self.meta.chunk_bytes) {
                return (hasher, done, Some(Problem::Io(e)));
            }
            if !fresh && Sha256::digest(&*chunk).as_slice() != expected {
                return (hasher, done, Some(Problem::Mismatch(index)));
            }
            hasher.update(&*chunk);
            done += 1;
        }
        (hasher, done, None)
    }

    /// Blocking: make the hashed prefix durable and record the hash state.
    pub fn checkpoint(&self) -> io::Result<()> {
        let _one = self.checkpointing.lock().unwrap();
        let (hasher, next) = {
            let st = self.state();
            match &st.hasher {
                Some(h) if !st.gone && st.hashed > st.checkpointed => (h.clone(), st.hashed),
                _ => return Ok(()),
            }
        };
        self.file.sync_data()?;
        self.log.sync_data()?;
        hasher::save(&self.dir.join(STATE), next, &hasher)?;
        let mut st = self.state();
        st.checkpointed = st.checkpointed.max(next);
        Ok(())
    }
}

pub enum Finalized {
    Stored,
    /// The store already has this file; the partial can go.
    Duplicate,
}

/// Move a fully hashed upload from `partial` into `store` as `<sha256>` and
/// `<sha256>.json`. Safe to run again after a crash at any point.
pub fn finalize(store: &Path, partial: &Path, sha256: &str, record: &Record) -> io::Result<Finalized> {
    let final_path = partial.join(FINAL);
    if !final_path.exists() {
        write_durably(&final_path, &serde_json::to_vec(&FinalFile { sha256: sha256.to_string() })?)?;
    }
    let data = partial.join(DATA);
    let target = store.join(sha256);
    let record_tmp = partial.join(RECORD);
    let record_path = store.join(format!("{sha256}.json"));
    if data.exists() {
        if target.exists() {
            return Ok(Finalized::Duplicate);
        }
        // Durable before it gets its name.
        File::open(&data)?.sync_data()?;
        if !record_tmp.exists() {
            write_durably(&record_tmp, &serde_json::to_vec_pretty(record)?)?;
        }
        std::fs::rename(&data, &target)?;
    } else if !target.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "the upload's data is gone"));
    }
    if record_tmp.exists() {
        std::fs::rename(&record_tmp, &record_path)?;
    } else if !record_path.exists() {
        write_durably(&record_path, &serde_json::to_vec_pretty(record)?)?;
    }
    sync_dir(store);
    Ok(Finalized::Stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(size: u64, chunk: u64) -> Meta {
        Meta {
            id: "0123456789abcdef01234567".into(),
            token: "t".into(),
            original_name: "big.img".into(),
            original_path: "dumps/big.img".into(),
            size,
            last_modified: Some(5),
            chunk_bytes: chunk,
            ip: "203.0.113.9".into(),
            started_at: 1,
        }
    }

    #[test]
    fn log_parsing_ignores_torn_and_bad_lines() {
        let h = hex::encode([7u8; 32]);
        let text = format!("0 {h}\n@198.51.100.2\n1 {h}\n-0\nbad line\n9 {h}\n2 {h}\n3 {}", &h[..10]);
        let mut chunks = vec![None; 4];
        let mut ips = vec!["203.0.113.9".to_string()];
        parse_log(text.as_bytes(), &mut chunks, &mut ips);
        assert_eq!(chunks, vec![None, Some([7; 32]), Some([7; 32]), None]);
        assert_eq!(ips, ["203.0.113.9", "198.51.100.2"]);
    }

    #[test]
    fn bitmap_is_lsb_first() {
        let chunks = [Some([0; 32]), None, Some([0; 32]), None, None, None, None, None, Some([0; 32])];
        let bytes = base64::engine::general_purpose::STANDARD.decode(bitmap(&chunks)).unwrap();
        assert_eq!(bytes, [0b101, 1]);
    }

    fn put(up: &Upload, index: u64, data: &[u8]) {
        let hash: [u8; 32] = Sha256::digest(data).into();
        let skip = up.begin_put(index, &hash).ok().expect("admitted");
        if !skip {
            up.write_chunk(index, data).unwrap();
        }
        up.end_put(index, !skip);
        up.record(index, hash, "203.0.113.9", 2).unwrap();
    }

    #[tokio::test]
    async fn hashes_resumes_and_detects_lost_writes() {
        let root = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let chunk = 1 << 16;
        let mut data = vec![0u8; chunk * 5 + 123];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut data);
        let m = meta(data.len() as u64, chunk as u64);
        let piece = |i: usize| &data[i * chunk..((i + 1) * chunk).min(data.len())];

        // First life: three chunks, a checkpoint after the first two.
        let up = Arc::new(Upload::create(root.path(), m.clone(), 1).unwrap());
        put(&up, 0, piece(0));
        put(&up, 1, piece(1));
        let hashing = tokio::spawn(up.clone().hash_all());
        while up.state().hashed < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        up.checkpoint().unwrap();
        put(&up, 3, piece(3));
        assert!(matches!(up.begin_put(3, &[0; 32]), Err(Refusal::Changed)));
        hashing.abort();
        let dir = up.dir.clone();
        drop(up);

        // A write "lost" in the crash: chunk 3 is zeros on disk.
        File::options().write(true).open(dir.join(DATA)).unwrap().write_all_at(&vec![0; chunk], 3 * chunk as u64).unwrap();
        let Loaded::Partial(up) = Upload::load(&dir).unwrap() else { panic!("not final yet") };
        let up = Arc::new(up);
        let counts = |up: &Upload| {
            let st = up.state();
            (st.hashed, st.received)
        };
        assert_eq!(counts(&up), (2, 3));
        let hashing = tokio::spawn(up.clone().hash_all());
        put(&up, 2, piece(2));
        // The hasher reaches 3, finds it wrong and drops it.
        while !matches!(counts(&up), (3.., 3)) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(up.state().chunks[3].is_none());
        for i in [3, 4, 5] {
            put(&up, i, piece(i as usize));
        }
        let hasher = hashing.await.unwrap().expect("hashed");
        let sha = hex::encode(hasher.finalize());
        assert_eq!(sha, hex::encode(Sha256::digest(&data)));

        let record = Record::new(&up.meta, "Sonic", &sha, &up.state().ips, 3);
        assert!(matches!(finalize(store.path(), &dir, &sha, &record).unwrap(), Finalized::Stored));
        // Running it again (a crash before the partial was removed) is harmless.
        assert!(matches!(finalize(store.path(), &dir, &sha, &record).unwrap(), Finalized::Stored));
        assert_eq!(std::fs::read(store.path().join(&sha)).unwrap(), data);
        let saved: Record = serde_json::from_slice(&std::fs::read(store.path().join(format!("{sha}.json"))).unwrap()).unwrap();
        assert_eq!((saved.name.as_str(), saved.original_name.as_str(), saved.ip.as_str()), ("Sonic", "big.img", "203.0.113.9"));
        assert!(matches!(Upload::load(&dir).unwrap(), Loaded::Final { .. }));
    }

    #[test]
    fn duplicate_when_the_store_has_it() {
        let root = tempfile::tempdir().unwrap();
        let store = tempfile::tempdir().unwrap();
        let up = Upload::create(root.path(), meta(10, 1 << 20), 1).unwrap();
        std::fs::write(store.path().join("ab"), b"x").unwrap();
        let record = Record::new(&up.meta, "Sonic", "ab", &[], 2);
        assert!(matches!(finalize(store.path(), &up.dir, "ab", &record).unwrap(), Finalized::Duplicate));
    }
}
