//! Verified donations waiting to be posted. Each job is backed by a sidecar
//! (`spool/{id}.job.json`) so a restart resumes posting.

use std::collections::VecDeque;
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

#[derive(Default)]
pub struct PostQueue {
    jobs: Mutex<VecDeque<Job>>,
    notify: Notify,
}

impl PostQueue {
    pub fn push(&self, job: Job) {
        self.jobs.lock().unwrap().push_back(job);
        self.notify.notify_one();
    }

    pub async fn next(&self) -> Job {
        loop {
            if let Some(job) = self.jobs.lock().unwrap().pop_front() {
                return job;
            }
            self.notify.notified().await;
        }
    }

    /// 1-based position among waiting jobs.
    pub fn position(&self, id: &str) -> Option<usize> {
        self.jobs.lock().unwrap().iter().position(|j| j.id == id).map(|p| p + 1)
    }

    pub fn len(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }
}
