//! Which zrax revisions the server accepts uploads from.
//!
//! A page classifies files with the zrax WASM it was loaded with, and the
//! server checks it was built from the same commit. After a zrax update, pages
//! that are already open keep the previous revision until they are reloaded.
//! Turning them away would fail everything they still have queued, so a
//! revision stays accepted for a grace period after it was replaced. The server
//! re-verifies every file with its own zrax either way.
//!
//! The history lives in `runtime/zrax-revs.json`, oldest first:
//! `[{"rev": "<commit>", "since": <unix time it became current>}, ...]`.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// How long pages built against a replaced zrax revision keep working.
pub const GRACE_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Era {
    rev: String,
    since: u64,
}

#[derive(Debug)]
pub struct Revisions {
    current: String,
    /// Replaced revisions and when they were replaced, oldest first.
    retired: Vec<(String, u64)>,
}

impl Revisions {
    /// Load the history, record `current` if it is new, and save it.
    pub fn open(path: &Path, current: &str, now: u64) -> Result<Self> {
        let mut eras: Vec<Era> = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        if eras.last().map(|e| e.rev.as_str()) != Some(current) {
            eras.push(Era { rev: current.to_string(), since: now });
            // Old entries only matter for the grace period.
            let keep_from = eras.len().saturating_sub(32);
            eras.drain(..keep_from);
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&eras)?)
                .and_then(|()| std::fs::rename(&tmp, path))
                .with_context(|| format!("writing {}", path.display()))?;
        }
        Ok(Self::from_eras(&eras, current))
    }

    fn from_eras(eras: &[Era], current: &str) -> Self {
        let retired = eras
            .windows(2)
            .filter(|w| w[0].rev != current)
            .map(|w| (w[0].rev.clone(), w[1].since))
            .collect();
        Self { current: current.to_string(), retired }
    }

    pub fn current(&self) -> &str {
        &self.current
    }

    /// Whether a page built against `rev` may still upload.
    pub fn accepts(&self, rev: &str, now: u64) -> bool {
        rev == self.current || self.retired.iter().any(|(r, at)| r == rev && now.saturating_sub(*at) <= GRACE_SECS)
    }

    /// The oldest revision still accepted. Pages from before clients reported
    /// their revision to /api/policy compare it with their own, and they were
    /// all built against the revision that was current then.
    pub fn oldest_accepted(&self, now: u64) -> &str {
        self.retired
            .iter()
            .find(|(_, at)| now.saturating_sub(*at) <= GRACE_SECS)
            .map(|(r, _)| r.as_str())
            .unwrap_or(&self.current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previous_revision_is_accepted_for_the_grace_period() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zrax-revs.json");

        let first = Revisions::open(&path, "aaa", 1_000).unwrap();
        assert!(first.accepts("aaa", 1_000));
        assert!(!first.accepts("bbb", 1_000));
        assert_eq!(first.oldest_accepted(1_000), "aaa");

        // Restarting on the same revision changes nothing.
        Revisions::open(&path, "aaa", 5_000).unwrap();

        let t = 10_000;
        let second = Revisions::open(&path, "bbb", t).unwrap();
        assert!(second.accepts("bbb", t));
        assert!(second.accepts("aaa", t + GRACE_SECS));
        assert!(!second.accepts("aaa", t + GRACE_SECS + 1));
        assert!(!second.accepts("zzz", t));
        assert_eq!(second.oldest_accepted(t), "aaa");
        assert_eq!(second.oldest_accepted(t + GRACE_SECS + 1), "bbb");

        // Back to the old revision: the one in between is now the retired one.
        let third = Revisions::open(&path, "aaa", t + 100).unwrap();
        assert!(third.accepts("aaa", t + 100));
        assert!(third.accepts("bbb", t + 100));
        assert_eq!(third.oldest_accepted(t + 100), "bbb");
        assert_eq!(third.current(), "aaa");
    }
}
