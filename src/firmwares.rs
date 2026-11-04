//! Every donated firmware image is kept after the server has verified it:
//! `<firmware_dir>/<sha256>` and `<firmware_dir>/<sha256>.json`. Donations
//! are copied in from the spool before they are posted; images posted before
//! this store existed are downloaded back from Telegram (telegram/backfill.rs).
//!
//! Files are copied, not hard-linked or moved: under the service's sandbox
//! the spool, the runtime directory and this store are separate mounts, and
//! link/rename between mounts fail (EXDEV). The copy goes to a temporary name
//! inside the store and is renamed into place, so `<sha256>` is always whole.
//!
//! After a zrax update every record is classified again (src/reclassify.rs):
//! `zrax` is the last classification that accepted the file, `unclassified`
//! says the current zrax rejects it (the file is kept, but hidden), and
//! `checked` names the zrax that last looked at it.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::analyze::Summary;
use crate::bulk::{sync_dir, write_durably};
use crate::dashboard::catalog::Catalog;
use crate::jobs::Job;
use crate::telegram::caption;

/// Where the image was posted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Posted {
    pub chat_id: i64,
    pub message_id: i64,
    pub posted_at: u64,
    /// Caption key (telegram/caption.rs) of what the post shows. Absent for
    /// posts from before reclassification: they show the record as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shows: Option<String>,
    /// Why Telegram won't let the post be edited (not tried again until the
    /// classification changes again).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit_failed: Option<String>,
}

impl Posted {
    pub fn new(chat_id: i64, message_id: i64, posted_at: u64) -> Self {
        Self { chat_id, message_id, posted_at, shows: None, edit_failed: None }
    }

    /// Posts in a basic group (before it became the supergroup) can't be
    /// edited any more, and dry runs post nothing.
    pub fn editable(&self) -> bool {
        self.message_id > 0 && self.chat_id < -1_000_000_000_000
    }
}

/// The current zrax rejects the file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unclassified {
    /// The zrax that first rejected it, and when.
    pub zrax: String,
    pub since: u64,
    pub reason: String,
}

/// The zrax that last classified the file (whatever it found).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checked {
    pub zrax: String,
    pub at: u64,
    /// zrax didn't come to an answer (crashed, timed out, the file couldn't
    /// be read): the record is otherwise as it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What zrax made of a stored file this time.
#[derive(Debug, Clone)]
pub enum Recheck {
    Accepted(Summary),
    Rejected(String),
    Failed(String),
}

/// How a record changed, for the counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Already checked by this zrax (nothing done).
    Skipped,
    /// The post would say the same (the confidence may differ).
    Unchanged,
    Changed,
    Unclassified,
    Restored,
    Failed,
}

/// What came of editing a post.
pub enum Edit {
    /// It shows the caption with this key now.
    Shows(String),
    Refused(String),
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
    /// The last classification that accepted the file (its zrax version is
    /// inside). Absent for an image recovered from the group that no zrax
    /// here has accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zrax: Option<Summary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unclassified: Option<Unclassified>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<Checked>,
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
            unclassified: None,
            checked: None,
            received_at: job.created_at,
            source: "upload".into(),
            telegram: None,
        }
    }

    /// The zrax that last classified the file ("" if none did).
    pub fn checked_by(&self) -> &str {
        match (&self.checked, &self.zrax) {
            (Some(c), _) => &c.zrax,
            (None, Some(z)) => &z.zrax,
            (None, None) => "",
        }
    }

    /// Hidden from the dashboards and the statistics (kept on disk).
    pub fn hidden(&self) -> bool {
        self.unclassified.is_some()
    }

    /// The post shows something other than what the record says now.
    pub fn post_stale(&self) -> bool {
        let Some(t) = &self.telegram else { return false };
        if t.edit_failed.is_some() || t.message_id <= 0 {
            return false;
        }
        match (&t.shows, caption::record_key(self)) {
            (Some(shown), Some(now)) => *shown != now,
            _ => false,
        }
    }
}

pub struct Firmwares {
    dir: PathBuf,
    /// The dashboard's index, told about every record written.
    catalog: Arc<Catalog>,
    /// Held for every read-modify-write of a record and the index update
    /// after it: the writes share one temporary name, and the index must see
    /// them in order.
    records: Mutex<()>,
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
        Ok(Self { dir: dir.to_owned(), catalog, records: Mutex::new(()) })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
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

    /// Blocking. The record kept for `sha256`, if any.
    pub fn record(&self, sha256: &str) -> io::Result<Option<Record>> {
        match std::fs::read(self.record_path(sha256)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write a record and tell the index. Call with `records` held.
    fn store(&self, record: &Record) -> io::Result<()> {
        write_durably(&self.record_path(&record.sha256), &serde_json::to_vec_pretty(record)?)?;
        self.catalog.put(record, &self.path(&record.sha256));
        Ok(())
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
        let _guard = self.records.lock().unwrap();
        if !self.record_path(&record.sha256).exists() {
            self.store(record)?;
        }
        sync_dir(&self.dir);
        Ok(())
    }

    /// Blocking. Note where the image was posted. None: nothing is kept
    /// under this hash (keeping it failed earlier); else whether the post
    /// already needs an edit (it was made from a classification the record
    /// no longer has, e.g. a job queued before a zrax update).
    pub fn mark_posted(&self, sha256: &str, mut posted: Posted) -> io::Result<Option<bool>> {
        let _guard = self.records.lock().unwrap();
        let Some(mut record) = self.record(sha256)? else { return Ok(None) };
        if let Some(old) = record.telegram.take().filter(|t| t.chat_id == posted.chat_id && t.message_id == posted.message_id) {
            posted.shows = posted.shows.or(old.shows);
            posted.edit_failed = old.edit_failed;
        }
        record.telegram = Some(posted);
        self.store(&record)?;
        Ok(Some(record.post_stale()))
    }

    /// Blocking. Apply what `zrax` (its label) made of a stored file. None:
    /// no record. Also returns whether the post now needs an edit.
    pub fn reclassify(&self, sha256: &str, outcome: Recheck, zrax: &str, now: u64) -> io::Result<Option<(Change, bool)>> {
        let _guard = self.records.lock().unwrap();
        let Some(mut record) = self.record(sha256)? else { return Ok(None) };
        if record.checked_by() == zrax {
            return Ok(Some((Change::Skipped, record.post_stale())));
        }
        let before = caption::record_key(&record);
        // Until now the post showed the record as it was.
        if let Some(t) = record.telegram.as_mut().filter(|t| t.shows.is_none()) {
            t.shows = before.clone();
        }
        let mut error = None;
        let change = match outcome {
            Recheck::Accepted(summary) => {
                let restored = record.unclassified.take().is_some();
                record.zrax = Some(summary);
                match (restored, caption::record_key(&record) == before) {
                    (true, _) => Change::Restored,
                    (false, true) => Change::Unchanged,
                    (false, false) => Change::Changed,
                }
            }
            Recheck::Rejected(reason) => match record.unclassified.as_mut() {
                Some(u) if u.reason == reason => Change::Unchanged,
                Some(u) => {
                    u.reason = reason;
                    Change::Changed
                }
                None => {
                    record.unclassified = Some(Unclassified { zrax: zrax.to_string(), since: now, reason });
                    Change::Unclassified
                }
            },
            Recheck::Failed(reason) => {
                error = Some(reason);
                Change::Failed
            }
        };
        record.checked = Some(Checked { zrax: zrax.to_string(), at: now, error });
        // A new caption: worth trying an edit again.
        if caption::record_key(&record) != before {
            if let Some(t) = record.telegram.as_mut() {
                t.edit_failed = None;
            }
        }
        self.store(&record)?;
        Ok(Some((change, record.post_stale())))
    }

    /// Blocking. Note what came of editing post `message_id` of `sha256`
    /// (nothing changes if the record now names another post).
    pub fn note_edit(&self, sha256: &str, message_id: i64, edit: Edit) -> io::Result<()> {
        let _guard = self.records.lock().unwrap();
        let Some(mut record) = self.record(sha256)? else { return Ok(()) };
        let Some(t) = record.telegram.as_mut().filter(|t| t.message_id == message_id) else { return Ok(()) };
        match edit {
            Edit::Shows(key) => {
                t.shows = Some(key);
                t.edit_failed = None;
            }
            Edit::Refused(reason) => t.edit_failed = Some(reason),
        }
        write_durably(&self.record_path(sha256), &serde_json::to_vec_pretty(&record)?)
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
            unclassified: None,
            checked: None,
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

        let posted = Posted::new(-100, 7 << 20, 11);
        assert_eq!(store.mark_posted(&sha, posted.clone()).unwrap(), Some(false));
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(store.record_path(&sha)).unwrap()).unwrap();
        assert_eq!(json["name"], "donor_1");
        assert_eq!(json["original_name"], "router.bin");
        assert_eq!(json["telegram"]["message_id"], 7 << 20);
        assert!(json.get("ip").is_none(), "no address is kept");
        assert_eq!(store.mark_posted(&"cd".repeat(32), posted).unwrap(), None, "nothing kept under that hash");
        let (row, _) = store.catalog().detail(&sha).unwrap();
        assert_eq!((row["status"].as_str(), row["message_id"].as_i64()), (Some("stored"), Some(7 << 20)), "the index follows");

        let mut names: Vec<String> =
            std::fs::read_dir(store_dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, [sha.clone(), format!("{sha}.json")], "no temporary files left");
    }

    fn summary(isa: &str, confidence: f64, zrax: &str) -> Summary {
        Summary {
            format: "raw".into(),
            format_name: "Raw code".into(),
            format_variant: None,
            isa: Some(isa.into()),
            isa_name: Some(isa.to_uppercase()),
            isa_tag: Some(isa.into()),
            bitwidth: 32,
            endianness: "little".into(),
            confidence,
            source: "heuristic".into(),
            variant: None,
            slices: Vec::new(),
            metadata: Vec::new(),
            basis: "isa".into(),
            zrax: zrax.into(),
        }
    }

    #[test]
    fn reclassifying_a_record() {
        let spool = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        std::fs::write(spool.path().join("fw"), b"code").unwrap();
        let store = Firmwares::open(store_dir.path(), Arc::new(Catalog::new())).unwrap();
        let sha = "ab".repeat(32);
        let mut r = record(&sha);
        r.zrax = Some(summary("arm", 0.9, "z1"));
        store.keep(&spool.path().join("fw"), &r).unwrap();
        let msg = 7 << 20;
        let posted = Posted::new(-1003917356862, msg, 11);
        assert_eq!(store.mark_posted(&sha, posted.clone()).unwrap(), Some(false));
        let get = || store.record(&sha).unwrap().unwrap();
        assert_eq!(get().checked_by(), "z1");

        // Only the confidence differs: the post can stay.
        let shown = caption::record_key(&get());
        assert_eq!(store.reclassify(&sha, Recheck::Accepted(summary("arm", 0.5, "z2")), "z2", 20).unwrap(), Some((Change::Unchanged, false)));
        assert_eq!(get().telegram.unwrap().shows, shown, "the post shows the record as it was");
        assert_eq!((get().checked_by(), get().zrax.unwrap().confidence), ("z2", 0.5));
        assert_eq!(store.reclassify(&sha, Recheck::Rejected("x".into()), "z2", 21).unwrap(), Some((Change::Skipped, false)), "done already");

        // Another ISA: the post needs an edit.
        assert_eq!(store.reclassify(&sha, Recheck::Accepted(summary("mips", 0.5, "z3")), "z3", 30).unwrap(), Some((Change::Changed, true)));
        assert!(get().post_stale());
        let key = caption::record_key(&get()).unwrap();
        store.note_edit(&sha, msg, Edit::Shows(key)).unwrap();
        assert!(!get().post_stale());
        store.note_edit(&sha, msg + 1, Edit::Refused("another post".into())).unwrap();
        assert_eq!(get().telegram.unwrap().edit_failed, None, "a note about another post changes nothing");

        // Rejected: hidden, kept, and the last accepted classification stays.
        assert_eq!(
            store.reclassify(&sha, Recheck::Rejected("unrecognized by zrax".into()), "z4", 40).unwrap(),
            Some((Change::Unclassified, true))
        );
        let now = get();
        assert!(now.hidden() && store.has(&sha));
        assert_eq!(now.unclassified.as_ref().map(|u| (u.zrax.as_str(), u.since)), Some(("z4", 40)));
        assert_eq!(now.zrax.as_ref().and_then(|z| z.isa.as_deref()), Some("mips"));
        assert!(store.catalog().detail(&sha).is_none(), "the index hides it");
        store.note_edit(&sha, msg, Edit::Refused("Telegram doesn't allow editing it".into())).unwrap();
        assert!(!get().post_stale(), "refused: not tried again");

        // Still rejected, for the same reason: nothing to do. No answer: as it was.
        assert_eq!(
            store.reclassify(&sha, Recheck::Rejected("unrecognized by zrax".into()), "z5", 50).unwrap(),
            Some((Change::Unchanged, false))
        );
        assert_eq!(store.reclassify(&sha, Recheck::Failed("analysis timed out".into()), "z6", 60).unwrap(), Some((Change::Failed, false)));
        let now = get();
        assert!(now.hidden());
        assert_eq!(now.checked.as_ref().map(|c| (c.zrax.as_str(), c.error.as_deref())), Some(("z6", Some("analysis timed out"))));

        // Accepted again: visible. The post never showed it unclassified
        // (that edit was refused), so it is right as it is.
        assert_eq!(store.reclassify(&sha, Recheck::Accepted(summary("mips", 0.7, "z7")), "z7", 70).unwrap(), Some((Change::Restored, false)));
        assert!(!get().hidden() && get().telegram.unwrap().edit_failed.is_none());
        // Rejected again later, and this time the post can be edited.
        assert_eq!(store.reclassify(&sha, Recheck::Rejected("unrecognized by zrax".into()), "z8", 75).unwrap(), Some((Change::Unclassified, true)));
        store.note_edit(&sha, msg, Edit::Shows(caption::record_key(&get()).unwrap())).unwrap();
        assert_eq!(store.reclassify(&sha, Recheck::Accepted(summary("mips", 0.7, "z9")), "z9", 76).unwrap(), Some((Change::Restored, true)));
        assert!(store.catalog().detail(&sha).is_some());

        // Noting the same post again keeps what is known about it.
        store.note_edit(&sha, msg, Edit::Refused("no".into())).unwrap();
        assert_eq!(store.mark_posted(&sha, posted).unwrap(), Some(false));
        assert_eq!(get().telegram.unwrap().edit_failed.as_deref(), Some("no"));
        assert_eq!(store.reclassify(&"cd".repeat(32), Recheck::Failed("x".into()), "z10", 80).unwrap(), None);
    }

    #[test]
    fn a_post_made_from_an_older_classification_is_stale() {
        let spool = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        std::fs::write(spool.path().join("fw"), b"code").unwrap();
        let store = Firmwares::open(store_dir.path(), Arc::new(Catalog::new())).unwrap();
        let sha = "ef".repeat(32);
        let mut r = record(&sha);
        r.zrax = Some(summary("arm", 0.9, "z1"));
        store.keep(&spool.path().join("fw"), &r).unwrap();
        // Reclassified while its job waited to be posted with the old summary.
        store.reclassify(&sha, Recheck::Accepted(summary("mips", 0.9, "z2")), "z2", 5).unwrap();
        let mut posted = Posted::new(-1003917356862, 9 << 20, 6);
        posted.shows = caption::record_key(&r);
        assert_eq!(store.mark_posted(&sha, posted).unwrap(), Some(true));
        // Dry runs and basic groups.
        assert!(!Posted::new(-1003917356862, 0, 1).editable());
        assert!(!Posted::new(-5599544901, 3 << 20, 1).editable());
        assert!(Posted::new(-1003917356862, 3 << 20, 1).editable());
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
