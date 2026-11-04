//! Classify the store again after a zrax update.
//!
//! Every record names the zrax that last classified its file
//! (`Record::checked_by`). At every start, once the dashboard's index is
//! built, the records whose zrax isn't the current one are classified again,
//! newest first, on a few threads at the lowest CPU and I/O priority:
//!
//! - accepted: the record takes the new classification;
//! - rejected: the record is marked unclassified (kept on disk and hidden
//!   from the dashboards and the statistics) and keeps the last
//!   classification that accepted it; a later zrax may accept it again;
//! - no answer (zrax crashed or timed out, the file couldn't be read): the
//!   record stays as it is until the next zrax update.
//!
//! When the post would now say something else, the poster edits its caption
//! (telegram/poster.rs). Progress lives in the records themselves, so a
//! restart continues where the run stopped. A file that takes the whole
//! process down (stack overflow, out of memory) would do so again at every
//! start: the files being classified are listed in `runtime/reclassify.inflight`,
//! and any left there after an unclean exit are given up on.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{oneshot, Semaphore};

use crate::analyze::{evaluate_file, Outcome, Verdict};
use crate::bulk::write_durably;
use crate::config::Policy;
use crate::firmwares::{Change, Firmwares, Recheck, Record};
use crate::telegram::poster::EditQueue;
use crate::uploads::unix_now;

/// Far longer than any file takes; a file past it is left as it is.
const FILE_TIMEOUT: Duration = Duration::from_secs(600);
const PROGRESS_EVERY: Duration = Duration::from_secs(60);
const MIB: u64 = 1 << 20;

/// How far the reclassification is, for the dashboard.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Progress {
    /// off, waiting, scanning, running, finished or failed.
    pub state: &'static str,
    /// The zrax it classifies with.
    pub zrax: String,
    /// Records in the store, and those to classify again.
    pub total: usize,
    pub todo: usize,
    pub todo_bytes: u64,
    pub done: usize,
    pub bytes: u64,
    /// The post would say the same (the confidence may differ).
    pub unchanged: usize,
    pub changed: usize,
    /// Newly rejected by this zrax.
    pub unclassified: usize,
    /// Rejected before, accepted again.
    pub restored: usize,
    /// No answer from zrax: left as they were.
    pub errors: usize,
    /// Records hidden as unclassified, in all.
    pub hidden: usize,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
}

pub type Status = Arc<Mutex<Progress>>;

pub fn status(state: &'static str) -> Status {
    Arc::new(Mutex::new(Progress { state, ..Default::default() }))
}

/// `runtime/reclassify.inflight`: the files being classified right now.
pub struct Inflight {
    path: PathBuf,
    shas: Mutex<(HashSet<String>, bool)>,
}

impl Inflight {
    pub fn new(path: PathBuf) -> Arc<Self> {
        Arc::new(Self { path, shas: Mutex::new((HashSet::new(), false)) })
    }

    /// What an earlier run left behind (it ended without a clean shutdown).
    fn leftover(&self) -> Vec<String> {
        std::fs::read_to_string(&self.path)
            .map(|s| s.lines().map(str::trim).filter(|l| l.len() == 64).map(String::from).collect())
            .unwrap_or_default()
    }

    fn save(&self, shas: &HashSet<String>) {
        let mut text: String = shas.iter().map(|s| format!("{s}\n")).collect();
        if text.is_empty() {
            text.push('\n');
        }
        if let Err(e) = write_durably(&self.path, text.as_bytes()) {
            tracing::error!("reclassify: writing {} failed: {e}", self.path.display());
        }
    }

    fn add(&self, sha: &str) {
        let mut g = self.shas.lock().unwrap();
        if !g.1 && g.0.insert(sha.to_string()) {
            self.save(&g.0);
        }
    }

    fn remove(&self, sha: &str) {
        let mut g = self.shas.lock().unwrap();
        if !g.1 && g.0.remove(sha) {
            self.save(&g.0);
        }
    }

    /// A clean shutdown: the files being classified didn't cause it.
    pub fn close(&self) {
        let mut g = self.shas.lock().unwrap();
        g.1 = true;
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct Reclassifier {
    pub firmwares: Arc<Firmwares>,
    pub policy: Arc<Policy>,
    pub edits: Arc<EditQueue>,
    /// The zrax label records are brought to (`analyze::zrax_label()`).
    pub zrax: String,
    pub threads: usize,
    pub memory_mib: u64,
    pub inflight: Arc<Inflight>,
    pub status: Status,
}

/// A record to classify again.
struct Todo {
    sha: String,
    size: u64,
    received_at: u64,
}

struct Scan {
    todo: Vec<Todo>,
    /// Up to date, but their post isn't.
    stale: Vec<String>,
    total: usize,
    hidden: usize,
}

fn scan(dir: &Path, zrax: &str) -> std::io::Result<Scan> {
    let mut out = Scan { todo: Vec::new(), stale: Vec::new(), total: 0, hidden: 0 };
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let Ok(record) = std::fs::read(&path).map_err(|_| ()).and_then(|b| serde_json::from_slice::<Record>(&b).map_err(|_| ())) else {
            continue;
        };
        out.total += 1;
        out.hidden += usize::from(record.hidden());
        if record.checked_by() != zrax {
            out.todo.push(Todo { sha: record.sha256, size: record.size, received_at: record.received_at });
        } else if record.post_stale() {
            out.stale.push(record.sha256);
        }
    }
    Ok(out)
}

/// Let live verification and the rest of the server go first.
#[cfg(target_os = "linux")]
fn lower_priority() {
    // SAFETY: plain syscalls on the calling thread's own id.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::setpriority(libc::PRIO_PROCESS, tid, 19);
        // IOPRIO_WHO_PROCESS (a thread id is fine), IOPRIO_CLASS_IDLE << 13.
        libc::syscall(libc::SYS_ioprio_set, 1, tid as libc::c_int, 3 << 13);
    }
}

#[cfg(not(target_os = "linux"))]
fn lower_priority() {}

impl Reclassifier {
    fn update(&self, f: impl FnOnce(&mut Progress)) {
        f(&mut self.status.lock().unwrap());
    }

    pub async fn run(self) {
        let this = Arc::new(self);
        this.update(|p| {
            p.state = "scanning";
            p.zrax = this.zrax.clone();
        });
        while !this.firmwares.catalog().ready() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let scanned = {
            let (dir, zrax) = (this.firmwares.dir().to_owned(), this.zrax.clone());
            tokio::task::spawn_blocking(move || scan(&dir, &zrax)).await
        };
        let mut scan = match scanned {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::error!("reclassify: reading the store failed: {e}");
                this.update(|p| p.state = "failed");
                return;
            }
            Err(e) => {
                tracing::error!("reclassify: reading the store panicked: {e}");
                this.update(|p| p.state = "failed");
                return;
            }
        };
        for sha in scan.stale.drain(..) {
            this.edits.push(sha);
        }
        let now = unix_now();
        let todo_bytes: u64 = scan.todo.iter().map(|t| t.size).sum();
        this.update(|p| {
            p.state = "running";
            p.total = scan.total;
            p.hidden = scan.hidden;
            p.todo = scan.todo.len();
            p.todo_bytes = todo_bytes;
            p.started_at = Some(now);
        });

        // Files an earlier run was classifying when the process died.
        for sha in this.inflight.leftover() {
            if let Some(i) = scan.todo.iter().position(|t| t.sha == sha) {
                let item = scan.todo.swap_remove(i);
                tracing::error!(sha256 = %sha, "reclassify: the process died while classifying this file; leaving it as it is");
                this.apply(&sha, Recheck::Failed("the process died while classifying it".into()), item.size).await;
            }
        }
        this.inflight.save(&HashSet::new());

        scan.todo.sort_by(|a, b| b.received_at.cmp(&a.received_at).then_with(|| a.sha.cmp(&b.sha)));
        if scan.todo.is_empty() {
            tracing::info!("reclassify: all {} records are classified by zrax {}", scan.total, this.zrax);
            this.update(|p| {
                p.state = "finished";
                p.finished_at = Some(unix_now());
            });
            return;
        }
        tracing::info!(
            "reclassify: {} of {} records ({:.1} GB) were classified by another zrax; classifying them with {}",
            scan.todo.len(),
            scan.total,
            todo_bytes as f64 / 1e9,
            this.zrax
        );

        let threads = Arc::new(Semaphore::new(this.threads));
        let memory = Arc::new(Semaphore::new(this.memory_mib.min(u32::MAX as u64) as usize));
        let mut tasks = tokio::task::JoinSet::new();
        let started = Instant::now();
        let mut last_report = Instant::now();
        for item in scan.todo {
            let weight = item.size.div_ceil(MIB).clamp(1, this.memory_mib) as u32;
            let (Ok(thread), Ok(bytes)) =
                (threads.clone().acquire_owned().await, memory.clone().acquire_many_owned(weight).await)
            else {
                break;
            };
            let (tx, rx) = oneshot::channel();
            let path = this.firmwares.path(&item.sha);
            let (policy, inflight, sha) = (this.policy.clone(), this.inflight.clone(), item.sha.clone());
            let spawned = std::thread::Builder::new().name("reclassify".into()).spawn(move || {
                // Held until zrax really finishes, even past the timeout.
                let _permits = (thread, bytes);
                lower_priority();
                inflight.add(&sha);
                let _ = tx.send(evaluate_file(&path, &policy));
            });
            if let Err(e) = spawned {
                tracing::error!("reclassify: starting a thread failed: {e}");
                continue;
            }
            let me = this.clone();
            tasks.spawn(async move {
                let recheck = match tokio::time::timeout(FILE_TIMEOUT, rx).await {
                    Ok(Ok(Outcome::Verdict(Verdict::Accepted(summary)))) => Recheck::Accepted(summary),
                    Ok(Ok(Outcome::Verdict(Verdict::Rejected { reason }))) => Recheck::Rejected(reason),
                    Ok(Ok(Outcome::Failed(reason))) => Recheck::Failed(reason),
                    Ok(Err(_)) => Recheck::Failed("analysis crashed".into()),
                    Err(_) => Recheck::Failed(format!("analysis timed out after {} s", FILE_TIMEOUT.as_secs())),
                };
                me.apply(&item.sha, recheck, item.size).await;
                me.inflight.remove(&item.sha);
            });
            while tasks.try_join_next().is_some() {}
            if last_report.elapsed() >= PROGRESS_EVERY {
                last_report = Instant::now();
                this.report(started);
            }
        }
        while tasks.join_next().await.is_some() {
            if last_report.elapsed() >= PROGRESS_EVERY {
                last_report = Instant::now();
                this.report(started);
            }
        }
        this.update(|p| {
            p.state = "finished";
            p.finished_at = Some(unix_now());
        });
        let p = this.status.lock().unwrap().clone();
        tracing::info!(
            "reclassify finished in {:.0} min: {} unchanged, {} changed, {} unclassified, {} restored, {} without an answer; {} hidden in all",
            started.elapsed().as_secs_f64() / 60.0,
            p.unchanged,
            p.changed,
            p.unclassified,
            p.restored,
            p.errors,
            p.hidden
        );
    }

    fn report(&self, started: Instant) {
        let p = self.status.lock().unwrap().clone();
        let secs = started.elapsed().as_secs_f64().max(1.0);
        tracing::info!(
            "reclassify: {}/{} done ({:.1} files/s), {} changed, {} unclassified, {} restored, {} without an answer; {} posts to edit",
            p.done,
            p.todo,
            p.done as f64 / secs,
            p.changed,
            p.unclassified,
            p.restored,
            p.errors,
            self.edits.len()
        );
    }

    /// Store what zrax made of a file, count it, and queue the post's edit.
    async fn apply(&self, sha: &str, recheck: Recheck, size: u64) {
        let failed = match &recheck {
            Recheck::Failed(reason) => Some(reason.clone()),
            _ => None,
        };
        let applied = {
            let (store, sha, zrax) = (self.firmwares.clone(), sha.to_string(), self.zrax.clone());
            tokio::task::spawn_blocking(move || store.reclassify(&sha, recheck, &zrax, unix_now())).await
        };
        let (change, stale) = match applied {
            Ok(Ok(Some(c))) => c,
            Ok(Ok(None)) => return,
            Ok(Err(e)) => {
                tracing::error!(sha256 = %sha, "reclassify: updating the record failed: {e}");
                return;
            }
            Err(e) => {
                tracing::error!(sha256 = %sha, "reclassify: updating the record panicked: {e}");
                return;
            }
        };
        if let Some(reason) = failed {
            tracing::warn!(sha256 = %sha, %reason, "reclassify: zrax came to no answer; the record stays as it is");
        }
        if stale {
            self.edits.push(sha.to_string());
        }
        self.update(|p| {
            p.done += 1;
            p.bytes += size;
            match change {
                Change::Skipped | Change::Unchanged => p.unchanged += 1,
                Change::Changed => p.changed += 1,
                Change::Unclassified => {
                    p.unclassified += 1;
                    p.hidden += 1;
                }
                Change::Restored => {
                    p.restored += 1;
                    p.hidden = p.hidden.saturating_sub(1);
                }
                Change::Failed => p.errors += 1,
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::Summary;
    use crate::dashboard::catalog::Catalog;
    use crate::firmwares::Posted;

    /// A minimal AArch64 ELF executable (zrax reads the ISA from its header).
    fn aarch64_elf() -> Vec<u8> {
        let mut head = vec![0u8; 0x200];
        head[..4].copy_from_slice(b"\x7fELF");
        head[4] = 2; // 64-bit
        head[5] = 1; // little-endian
        head[6] = 1;
        head[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        head[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        head[20..24].copy_from_slice(&1u32.to_le_bytes());
        head[24..32].copy_from_slice(&0x200u64.to_le_bytes());
        head[32..40].copy_from_slice(&64u64.to_le_bytes());
        head[52..54].copy_from_slice(&64u16.to_le_bytes());
        head[54..56].copy_from_slice(&56u16.to_le_bytes());
        head[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64;
        head[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        head[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        for f in [32, 40] {
            head[ph + f..ph + f + 8].copy_from_slice(&0x400u64.to_le_bytes());
        }
        // ret; nop; … (AArch64)
        head.extend(std::iter::repeat_n([0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20, 0x03, 0xd5], 64).flatten());
        head
    }

    fn fake_summary(isa: &str) -> Summary {
        Summary {
            format: "raw".into(),
            format_name: "Raw code".into(),
            format_variant: None,
            isa: Some(isa.into()),
            isa_name: Some(isa.into()),
            isa_tag: Some(isa.into()),
            bitwidth: 32,
            endianness: "little".into(),
            confidence: 0.6,
            source: "heuristic".into(),
            variant: None,
            slices: Vec::new(),
            metadata: Vec::new(),
            basis: "isa".into(),
            zrax: "0.0.0@0000000".into(),
        }
    }

    fn put(dir: &Path, n: u8, bytes: &[u8], z: Option<Summary>, message: i64) -> String {
        let sha = hex::encode([n; 32]);
        std::fs::write(dir.join(&sha), bytes).unwrap();
        let record = Record {
            sha256: sha.clone(),
            size: bytes.len() as u64,
            name: "donor".into(),
            original_name: format!("file{n}.bin"),
            zrax: z,
            unclassified: None,
            checked: None,
            received_at: u64::from(n),
            source: "upload".into(),
            telegram: Some(Posted::new(-1003917356862, message, 1)),
        };
        std::fs::write(dir.join(format!("{sha}.json")), serde_json::to_vec(&record).unwrap()).unwrap();
        sha
    }

    fn reclassifier(store: &Arc<Firmwares>, edits: &Arc<EditQueue>, inflight: &Arc<Inflight>) -> (Reclassifier, Status) {
        let status = status("waiting");
        let r = Reclassifier {
            firmwares: store.clone(),
            policy: Arc::new(Policy::default()),
            edits: edits.clone(),
            zrax: "test@0000001".into(),
            threads: 2,
            memory_mib: 16,
            inflight: inflight.clone(),
            status: status.clone(),
        };
        (r, status)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn classifies_the_store_again() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = tempfile::tempdir().unwrap();
        // Wrong about a real ELF, wrong about noise, an image the last run
        // was classifying when the process died, and an unclassified ELF.
        let elf = put(dir.path(), 1, &aarch64_elf(), Some(fake_summary("mips")), 1 << 20);
        let noise = put(dir.path(), 2, &[0u8; 8192], Some(fake_summary("dalvik")), 2 << 20);
        let died = put(dir.path(), 3, &aarch64_elf(), Some(fake_summary("mips")), 3 << 20);
        let back = put(dir.path(), 4, &aarch64_elf(), Some(fake_summary("mips")), 0);
        let mut r: Record = serde_json::from_slice(&std::fs::read(dir.path().join(format!("{back}.json"))).unwrap()).unwrap();
        r.unclassified = Some(crate::firmwares::Unclassified { zrax: "0.0.0@0000000".into(), since: 1, reason: "no".into() });
        std::fs::write(dir.path().join(format!("{back}.json")), serde_json::to_vec(&r).unwrap()).unwrap();
        std::fs::write(runtime.path().join("inflight"), format!("{died}\n")).unwrap();

        let catalog = Arc::new(Catalog::new());
        let store = Arc::new(Firmwares::open(dir.path(), catalog.clone()).unwrap());
        catalog.load(&[], &[], dir.path());
        assert!(catalog.detail(&back).is_none(), "loaded hidden");
        let edits = Arc::new(EditQueue::default());
        let inflight = Inflight::new(runtime.path().join("inflight"));
        let (job, status) = reclassifier(&store, &edits, &inflight);
        job.run().await;

        let p = status.lock().unwrap().clone();
        assert_eq!((p.state, p.total, p.todo, p.done), ("finished", 4, 4, 4));
        assert_eq!((p.changed, p.unclassified, p.restored, p.errors, p.hidden), (1, 1, 1, 1, 1));
        let get = |sha: &str| store.record(sha).unwrap().unwrap();
        let e = get(&elf);
        assert_eq!(e.zrax.as_ref().map(|z| (z.format.as_str(), z.isa.as_deref())), Some(("elf", Some("a_arch64"))));
        assert_eq!(e.checked_by(), "test@0000001");
        let n = get(&noise);
        assert!(n.hidden() && store.has(&noise), "rejected: hidden but kept");
        assert_eq!(n.zrax.as_ref().and_then(|z| z.isa.as_deref()), Some("dalvik"), "the last accepted classification stays");
        assert!(catalog.detail(&noise).is_none());
        let d = get(&died);
        assert_eq!(d.checked.as_ref().and_then(|c| c.error.as_deref()), Some("the process died while classifying it"));
        assert_eq!(d.zrax.as_ref().and_then(|z| z.isa.as_deref()), Some("mips"), "left as it was");
        assert!(!get(&back).hidden() && catalog.detail(&back).is_some(), "accepted again");
        // Both changed posts wait for an edit (the restored one was never posted).
        let mut queued = vec![edits.pop().unwrap(), edits.pop().unwrap()];
        queued.sort();
        assert_eq!(queued, [elf.clone(), noise.clone()]);
        assert!(edits.pop().is_none());
        assert_eq!(std::fs::read_to_string(runtime.path().join("inflight")).unwrap().trim(), "");

        // The next start has nothing to do, but the posts still need their edit.
        let (job, status) = reclassifier(&store, &edits, &inflight);
        job.run().await;
        let p = status.lock().unwrap().clone();
        assert_eq!((p.state, p.todo, p.hidden), ("finished", 0, 1));
        assert_eq!(edits.len(), 2);
    }
}
