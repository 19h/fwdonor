//! Append-only record of everything posted (`runtime/posted.jsonl`). Loaded
//! into memory at startup so a firmware image is only ever posted once, and
//! so the corpus statistics on the page cost nothing to serve.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub sha256: String,
    pub name: String,
    pub size: u64,
    pub username: String,
    pub format: String,
    /// Primary ISA (zrax serde name) when concrete.
    pub isa: Option<String>,
    /// Every distinct concrete ISA in the file (primary and slices). Older
    /// entries only have `isa`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub isas: Vec<String>,
    pub message_id: i64,
    pub posted_at: u64,
}

impl Entry {
    fn all_isas(&self) -> Vec<&str> {
        if self.isas.is_empty() {
            self.isa.as_deref().into_iter().collect()
        } else {
            self.isas.iter().map(String::as_str).collect()
        }
    }
}

/// UTC calendar date (YYYY-MM-DD) of a unix timestamp.
pub fn date(unix: u64) -> String {
    // Civil-from-days (Howard Hinnant), valid for all dates after 1970.
    let days = (unix / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub files: u64,
    pub bytes: u64,
}

impl Tally {
    fn add(&mut self, bytes: u64) {
        self.files += 1;
        self.bytes += bytes;
    }
}

#[derive(Default)]
struct Stats {
    total: Tally,
    by_isa: HashMap<String, Tally>,
    /// Files with no concrete ISA (accepted as firmware containers).
    no_isa: Tally,
    by_format: HashMap<String, Tally>,
    donors: HashSet<String>,
    /// posted_at of every entry, ascending.
    times: Vec<u64>,
}

impl Stats {
    fn add(&mut self, e: &Entry) {
        self.total.add(e.size);
        let isas = e.all_isas();
        if isas.is_empty() {
            self.no_isa.add(e.size);
        }
        for isa in isas {
            self.by_isa.entry(isa.to_string()).or_default().add(e.size);
        }
        self.by_format.entry(e.format.clone()).or_default().add(e.size);
        if e.username != "anonymous" {
            self.donors.insert(e.username.clone());
        }
        let at = self.times.partition_point(|t| *t <= e.posted_at);
        self.times.insert(at, e.posted_at);
    }
}

/// A copy of the corpus statistics, sorted for display (largest first).
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub total: Tally,
    pub isas: Vec<(String, Tally)>,
    pub no_isa: Tally,
    pub formats: Vec<(String, Tally)>,
    pub donors: usize,
    pub first_at: Option<u64>,
    pub last_at: Option<u64>,
    /// Files posted at or after `since`.
    pub recent: u64,
}

fn sorted(map: &HashMap<String, Tally>) -> Vec<(String, Tally)> {
    let mut v: Vec<_> = map.iter().map(|(k, t)| (k.clone(), *t)).collect();
    v.sort_by(|a, b| b.1.files.cmp(&a.1.files).then_with(|| a.0.cmp(&b.0)));
    v
}

struct Inner {
    file: File,
    /// sha256 → unix time it was posted.
    seen: HashMap<String, u64>,
    stats: Stats,
}

pub struct Ledger {
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Self> {
        let mut seen = HashMap::new();
        let mut stats = Stats::default();
        if path.exists() {
            let reader = BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
            for (n, line) in reader.lines().enumerate() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Entry>(&line) {
                    Ok(e) => {
                        // A repost after a crash appears twice; count it once.
                        if !seen.contains_key(&e.sha256) {
                            stats.add(&e);
                            seen.insert(e.sha256.clone(), e.posted_at);
                        }
                    }
                    // A torn final line after a crash must not stop the service.
                    Err(e) => tracing::warn!("ledger line {} unreadable: {e}", n + 1),
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { path: path.to_owned(), inner: Mutex::new(Inner { file, seen, stats }) })
    }

    pub fn contains(&self, sha256: &str) -> bool {
        self.inner.lock().unwrap().seen.contains_key(sha256)
    }

    /// When a file with this hash was posted, if ever.
    pub fn posted_at(&self, sha256: &str) -> Option<u64> {
        self.inner.lock().unwrap().seen.get(sha256).copied()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().seen.len()
    }

    /// Every posted image once (its first post), oldest first, read from
    /// the file (the backfill needs the message ids, which aren't kept in
    /// memory).
    pub fn entries(&self) -> Result<Vec<Entry>> {
        let reader = BufReader::new(File::open(&self.path).with_context(|| format!("opening {}", self.path.display()))?);
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if let Ok(e) = serde_json::from_str::<Entry>(&line) {
                if seen.insert(e.sha256.clone()) {
                    out.push(e);
                }
            }
        }
        Ok(out)
    }

    /// Durably record a post. Called before the spooled file is deleted.
    pub fn record(&self, entry: &Entry) -> Result<()> {
        let mut line = serde_json::to_string(entry)?;
        line.push('\n');
        let mut guard = self.inner.lock().unwrap();
        guard.file.write_all(line.as_bytes()).with_context(|| format!("appending {}", self.path.display()))?;
        guard.file.sync_data()?;
        if !guard.seen.contains_key(&entry.sha256) {
            guard.seen.insert(entry.sha256.clone(), entry.posted_at);
            guard.stats.add(entry);
        }
        Ok(())
    }

    pub fn snapshot(&self, since: u64) -> Snapshot {
        let guard = self.inner.lock().unwrap();
        let s = &guard.stats;
        Snapshot {
            total: s.total,
            isas: sorted(&s.by_isa),
            no_isa: s.no_isa,
            formats: sorted(&s.by_format),
            donors: s.donors.len(),
            first_at: s.times.first().copied(),
            last_at: s.times.last().copied(),
            recent: (s.times.len() - s.times.partition_point(|t| *t < since)) as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sha: &str, isa: Option<&str>, isas: &[&str], format: &str, user: &str, at: u64) -> Entry {
        Entry {
            sha256: sha.repeat(32),
            name: "fw.bin".into(),
            size: 10,
            username: user.into(),
            format: format.into(),
            isa: isa.map(Into::into),
            isas: isas.iter().map(|s| s.to_string()).collect(),
            message_id: 1,
            posted_at: at,
        }
    }

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_793_646_669), "2026-11-02");
        assert_eq!(date(951_782_400), "2000-02-29");
    }

    #[test]
    fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("posted.jsonl");
        let ledger = Ledger::open(&path).unwrap();
        ledger.record(&entry("ab", None, &[], "uimage", "anonymous", 0)).unwrap();
        drop(ledger);
        std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{\"torn").unwrap();
        let ledger = Ledger::open(&path).unwrap();
        assert!(ledger.contains(&"ab".repeat(32)));
        assert_eq!(ledger.posted_at(&"ab".repeat(32)), Some(0));
        assert_eq!(ledger.posted_at(&"cd".repeat(32)), None);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn statistics_survive_reload_and_count_reposts_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("posted.jsonl");
        let ledger = Ledger::open(&path).unwrap();
        // An old-style entry (primary ISA only), a multi-ISA container, a
        // container without ISA, and a repost of the first file.
        ledger.record(&entry("01", Some("arm"), &[], "raw", "anonymous", 100)).unwrap();
        ledger.record(&entry("02", Some("arm"), &["arm", "tricore"], "elf", "kenan", 200)).unwrap();
        ledger.record(&entry("03", None, &[], "squashfs", "kenan", 300)).unwrap();
        ledger.record(&entry("01", Some("arm"), &[], "raw", "anonymous", 400)).unwrap();
        let check = |s: Snapshot| {
            assert_eq!(s.total, Tally { files: 3, bytes: 30 });
            assert_eq!(s.isas, vec![("arm".into(), Tally { files: 2, bytes: 20 }), ("tricore".into(), Tally { files: 1, bytes: 10 })]);
            assert_eq!(s.no_isa.files, 1);
            assert_eq!(s.formats.len(), 3);
            assert_eq!(s.donors, 1);
            assert_eq!((s.first_at, s.last_at), (Some(100), Some(300)));
            assert_eq!(s.recent, 2);
        };
        check(ledger.snapshot(200));
        drop(ledger);
        check(Ledger::open(&path).unwrap().snapshot(200));
    }
}
