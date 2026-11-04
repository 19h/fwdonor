//! Every donated firmware image is kept after the server has verified it:
//! `<firmware_dir>/<sha256>` and `<firmware_dir>/<sha256>.json`. Donations
//! are copied in from the spool before they are posted; images posted before
//! this store existed are downloaded back from Telegram (telegram/backfill.rs).
//!
//! Files are copied, not hard-linked or moved: under the service's sandbox
//! the spool, the runtime directory and this store are separate mounts, and
//! link/rename between mounts fail (EXDEV). The copy goes to a temporary name
//! inside the store and is renamed into place, so `<sha256>` is always whole.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::analyze::Summary;
use crate::bulk::{sync_dir, write_durably};
use crate::dashboard::catalog::Catalog;
use crate::jobs::Job;

/// Where the image was posted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Posted {
    pub chat_id: i64,
    pub message_id: i64,
    pub posted_at: u64,
}

/// `<sha256>.json`. No address or other trace of the sender beyond the name
/// they chose to be credited with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub sha256: String,
    pub size: u64,
    /// The donor name the post credits.
    pub name: String,
    pub original_name: String,
    /// What zrax found (its version is inside). Absent for a recovered image
    /// the current zrax no longer accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zrax: Option<Summary>,
    pub received_at: u64,
    /// `upload`, or `telegram` for images recovered from the group.
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telegram: Option<Posted>,
}

impl Record {
    pub fn for_upload(job: &Job) -> Self {
        Self {
            sha256: job.sha256.clone(),
            size: job.size,
            name: job.username.clone(),
            original_name: job.name.clone(),
            zrax: Some(job.summary.clone()),
            received_at: job.created_at,
            source: "upload".into(),
            telegram: None,
        }
    }
}

pub struct Firmwares {
    dir: PathBuf,
    /// The dashboard's index, told about every record written.
    catalog: Arc<Catalog>,
}

impl Firmwares {
    /// Create the store and drop temporary files a crash left behind.
    pub fn open(dir: &Path, catalog: Arc<Catalog>) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().ends_with(".tmp") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(Self { dir: dir.to_owned(), catalog })
    }

    pub fn catalog(&self) -> &Arc<Catalog> {
        &self.catalog
    }

    pub fn path(&self, sha256: &str) -> PathBuf {
        self.dir.join(sha256)
    }

    fn record_path(&self, sha256: &str) -> PathBuf {
        self.dir.join(format!("{sha256}.json"))
    }

    pub fn has(&self, sha256: &str) -> bool {
        self.path(sha256).exists()
    }

    /// Blocking. Copy `file` in as `<sha256>` unless it is already there, and
    /// write the record unless there is one. Safe to repeat.
    pub fn keep(&self, file: &Path, record: &Record) -> io::Result<()> {
        let target = self.path(&record.sha256);
        if !target.exists() {
            let mut nonce = [0u8; 6];
            rand::rng().fill_bytes(&mut nonce);
            let tmp = self.dir.join(format!(".{}.{}.tmp", record.sha256, hex::encode(nonce)));
            let copied = std::fs::copy(file, &tmp)
                .and_then(|_| std::fs::File::open(&tmp)?.sync_all())
                .and_then(|_| std::fs::rename(&tmp, &target));
            if let Err(e) = copied {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        }
        let record_path = self.record_path(&record.sha256);
        let new_record = !record_path.exists();
        if new_record {
            write_durably(&record_path, &serde_json::to_vec_pretty(record)?)?;
        }
        sync_dir(&self.dir);
        if new_record {
            self.catalog.put(record, &target);
        }
        Ok(())
    }

    /// Blocking. Note where the image was posted. Ok(false): nothing is kept
    /// under this hash (keeping it failed earlier).
    pub fn mark_posted(&self, sha256: &str, posted: Posted) -> io::Result<bool> {
        let path = self.record_path(sha256);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let mut record: Record = serde_json::from_slice(&bytes)?;
        record.telegram = Some(posted);
        write_durably(&path, &serde_json::to_vec_pretty(&record)?)?;
        self.catalog.put(&record, &self.path(sha256));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(sha: &str) -> Record {
        Record {
            sha256: sha.into(),
            size: 5,
            name: "donor_1".into(),
            original_name: "router.bin".into(),
            zrax: None,
            received_at: 10,
            source: "upload".into(),
            telegram: None,
        }
    }

    #[test]
    fn keeps_copies_once_and_notes_the_post() {
        let spool = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        std::fs::write(spool.path().join("router.bin"), b"hello").unwrap();
        // A temporary file from a crash is cleaned up on open.
        std::fs::write(store_dir.path().join(".abc.123.tmp"), b"half").unwrap();
        let store = Firmwares::open(store_dir.path(), Arc::new(Catalog::new())).unwrap();
        let sha = "ab".repeat(32);
        assert!(!store.has(&sha));
        store.keep(&spool.path().join("router.bin"), &record(&sha)).unwrap();
        assert_eq!(std::fs::read(store.path(&sha)).unwrap(), b"hello");

        // Again (a job re-queued after a restart): nothing changes, even if
        // the spool copy is gone by now.
        std::fs::remove_file(spool.path().join("router.bin")).unwrap();
        store.keep(&spool.path().join("router.bin"), &record(&sha)).unwrap();

        let posted = Posted { chat_id: -100, message_id: 7 << 20, posted_at: 11 };
        assert!(store.mark_posted(&sha, posted.clone()).unwrap());
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(store.record_path(&sha)).unwrap()).unwrap();
        assert_eq!(json["name"], "donor_1");
        assert_eq!(json["original_name"], "router.bin");
        assert_eq!(json["telegram"]["message_id"], 7 << 20);
        assert!(json.get("ip").is_none(), "no address is kept");
        assert!(!store.mark_posted(&"cd".repeat(32), posted).unwrap(), "nothing kept under that hash");
        let (row, _) = store.catalog().detail(&sha).unwrap();
        assert_eq!((row["status"].as_str(), row["message_id"].as_i64()), (Some("stored"), Some(7 << 20)), "the index follows");

        let mut names: Vec<String> =
            std::fs::read_dir(store_dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, [sha.clone(), format!("{sha}.json")], "no temporary files left");
    }

    #[test]
    fn a_failed_copy_leaves_nothing() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Firmwares::open(store_dir.path(), Arc::new(Catalog::new())).unwrap();
        let sha = "ef".repeat(32);
        assert!(store.keep(Path::new("/nonexistent/file"), &record(&sha)).is_err());
        assert_eq!(std::fs::read_dir(store_dir.path()).unwrap().count(), 0);
    }
}
