//! Verified donations waiting to be posted, in two lanes:
//!
//! - web: donations from the page. Each job is backed by a sidecar
//!   (`spool/{id}.job.json`) and its spooled file, so a restart resumes it.
//! - background: uploads from fwdonate. They are posted only while no web
//!   donation waits, donors taking turns. Their file is the store's copy, so
//!   they hold no spool space; the sidecar is `runtime/background/{id}.json`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::analyze::Summary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub username: String,
    pub summary: Summary,
    pub file: PathBuf,
    pub created_at: u64,
}

impl Job {
    pub fn sidecar(spool: &Path, id: &str) -> PathBuf {
        spool.join(format!("{id}.job.json"))
    }

    pub fn dir(spool: &Path, id: &str) -> PathBuf {
        spool.join(id)
    }

    pub fn write_sidecar(&self, spool: &Path) -> Result<()> {
        let path = Self::sidecar(spool, &self.id);
        let tmp = path.with_extension("json.tmp");
        let file = std::fs::File::create(&tmp)?;
        serde_json::to_writer(&file, self)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
}

/// Which queue a donation goes to. The page uses `web`; fwdonate asks for
/// `background`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    #[default]
    Web,
    Background,
}

/// A background job, as its sidecar holds it. The classification is read
/// from the store's record when it is posted, so it is the current one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Queued {
    pub id: String,
    pub sha256: String,
    pub name: String,
    pub size: u64,
    pub username: String,
    pub created_at: u64,
    /// Posts that failed so far.
    #[serde(default)]
    pub attempts: u32,
}

impl Queued {
    pub fn sidecar(dir: &Path, id: &str) -> PathBuf {
        dir.join(format!("{id}.json"))
    }

    /// Blocking. Write the sidecar durably (the directory entry included).
    pub fn write(&self, dir: &Path) -> std::io::Result<()> {
        crate::bulk::write_durably(&Self::sidecar(dir, &self.id), &serde_json::to_vec(self)?)?;
        crate::bulk::sync_dir(dir);
        Ok(())
    }
}

pub enum Next {
    Web(Job),
    Background(Queued),
}

#[derive(Default)]
struct Background {
    /// Each donor's jobs, oldest first.
    by_donor: HashMap<String, VecDeque<Queued>>,
    /// Donors with jobs waiting; the front one is next.
    turns: VecDeque<String>,
    /// Every job from push until `release` (id → sha256), also while the
    /// poster gets it ready, so its hash is never free for a second upload.
    ids: HashMap<String, String>,
    shas: HashSet<String>,
    waiting: usize,
    bytes: u64,
}

#[derive(Default)]
struct Lanes {
    web: VecDeque<Job>,
    background: Background,
}

#[derive(Default)]
pub struct PostQueue {
    lanes: Mutex<Lanes>,
    notify: Notify,
}

impl PostQueue {
    pub fn push(&self, job: Job) {
        self.lanes.lock().unwrap().web.push_back(job);
        self.notify.notify_one();
    }

    /// Queue a background job at the back of its donor's turn. False if a
    /// job for this hash is already there.
    pub fn push_background(&self, job: Queued) -> bool {
        let mut lanes = self.lanes.lock().unwrap();
        let bg = &mut lanes.background;
        if bg.shas.contains(&job.sha256) || bg.ids.contains_key(&job.id) {
            return false;
        }
        bg.shas.insert(job.sha256.clone());
        bg.ids.insert(job.id.clone(), job.sha256.clone());
        bg.waiting += 1;
        bg.bytes += job.size;
        let mine = bg.by_donor.entry(job.username.clone()).or_default();
        if mine.is_empty() {
            bg.turns.push_back(job.username.clone());
        }
        mine.push_back(job);
        drop(lanes);
        self.notify.notify_one();
        true
    }

    /// The next job: web donations first, else the donor whose turn it is.
    /// A background job stays known (`contains_sha`) until `release`.
    pub fn pop(&self) -> Option<Next> {
        let mut lanes = self.lanes.lock().unwrap();
        if let Some(job) = lanes.web.pop_front() {
            return Some(Next::Web(job));
        }
        let bg = &mut lanes.background;
        let donor = bg.turns.pop_front()?;
        let mine = bg.by_donor.get_mut(&donor)?;
        let job = mine.pop_front()?;
        if mine.is_empty() {
            bg.by_donor.remove(&donor);
        } else {
            bg.turns.push_back(donor);
        }
        bg.waiting -= 1;
        bg.bytes -= job.size;
        Some(Next::Background(job))
    }

    pub async fn next(&self) -> Next {
        loop {
            if let Some(next) = self.pop() {
                return next;
            }
            self.notify.notified().await;
        }
    }

    /// A popped background job is posting now, or is gone for good.
    pub fn release(&self, id: &str) {
        let mut lanes = self.lanes.lock().unwrap();
        let bg = &mut lanes.background;
        if let Some(sha) = bg.ids.remove(id) {
            bg.shas.remove(&sha);
        }
    }

    /// 1-based position among waiting web jobs.
    pub fn position(&self, id: &str) -> Option<usize> {
        self.lanes.lock().unwrap().web.iter().position(|j| j.id == id).map(|p| p + 1)
    }

    /// Web jobs waiting.
    pub fn len(&self) -> usize {
        self.lanes.lock().unwrap().web.len()
    }

    /// Whether a background job for this hash waits (or is being readied).
    pub fn contains_sha(&self, sha256: &str) -> bool {
        self.lanes.lock().unwrap().background.shas.contains(sha256)
    }

    pub fn has_background(&self, id: &str) -> bool {
        self.lanes.lock().unwrap().background.ids.contains_key(id)
    }

    /// Background jobs waiting, and their bytes.
    pub fn background(&self) -> (usize, u64) {
        let lanes = self.lanes.lock().unwrap();
        (lanes.background.waiting, lanes.background.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(id: &str, donor: &str) -> Queued {
        Queued {
            id: id.into(),
            sha256: format!("sha-{id}"),
            name: format!("{id}.bin"),
            size: 10,
            username: donor.into(),
            created_at: 0,
            attempts: 0,
        }
    }

    fn web(id: &str) -> Job {
        Job {
            id: id.into(),
            name: "w.bin".into(),
            size: 1,
            sha256: format!("sha-{id}"),
            username: "web".into(),
            summary: serde_json::from_value(serde_json::json!({
                "format": "elf", "format_name": "ELF", "bitwidth": 64, "endianness": "little",
                "confidence": 1.0, "source": "container", "basis": "isa", "zrax": "x",
                "slices": [], "metadata": []
            }))
            .unwrap(),
            file: "w.bin".into(),
            created_at: 0,
        }
    }

    fn order(q: &PostQueue) -> Vec<String> {
        std::iter::from_fn(|| q.pop())
            .map(|n| match n {
                Next::Web(j) => format!("web:{}", j.id),
                Next::Background(j) => j.id,
            })
            .collect()
    }

    #[test]
    fn web_jobs_go_first_and_donors_take_turns() {
        let q = PostQueue::default();
        for (id, donor) in [("a1", "a"), ("a2", "a"), ("a3", "a"), ("b1", "b"), ("b2", "b"), ("n1", "anonymous")] {
            assert!(q.push_background(queued(id, donor)));
        }
        q.push(web("w1"));
        assert_eq!(q.background(), (6, 60));
        assert_eq!(q.len(), 1);
        let first: Vec<String> = (0..3).filter_map(|_| q.pop()).map(|n| match n {
            Next::Web(j) => format!("web:{}", j.id),
            Next::Background(j) => j.id,
        }).collect();
        assert_eq!(first, ["web:w1", "a1", "b1"]);
        // A donor who arrives now waits for the ones already taking turns.
        assert!(q.push_background(queued("c1", "c")));
        q.push(web("w2"));
        assert_eq!(order(&q), ["web:w2", "n1", "a2", "b2", "c1", "a3"]);
        assert_eq!(q.background(), (0, 0));
    }

    #[test]
    fn a_hash_stays_taken_until_released() {
        let q = PostQueue::default();
        assert!(q.push_background(queued("x", "a")));
        assert!(!q.push_background(Queued { id: "y".into(), ..queued("x", "b") }), "same hash");
        assert!(q.contains_sha("sha-x") && q.has_background("x"));
        let Some(Next::Background(job)) = q.pop() else { panic!() };
        assert!(q.contains_sha("sha-x"), "still known while the poster readies it");
        assert_eq!(q.background(), (0, 0));
        q.release(&job.id);
        assert!(!q.contains_sha("sha-x") && !q.has_background("x"));
        assert!(q.push_background(job), "can be queued again (a failed post)");
    }

    #[test]
    fn sidecars_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let job = Queued { attempts: 2, ..queued("abc", "a") };
        job.write(dir.path()).unwrap();
        let read: Queued = serde_json::from_slice(&std::fs::read(Queued::sidecar(dir.path(), "abc")).unwrap()).unwrap();
        assert_eq!(read, job);
        let old: Queued = serde_json::from_str(r#"{"id":"i","sha256":"s","name":"n","size":1,"username":"u","created_at":0}"#).unwrap();
        assert_eq!(old.attempts, 0);
    }
}
