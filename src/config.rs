//! Service configuration (`fwdonor.toml`). Every field has a default so a
//! minimal file only needs the paths that differ from the deployment layout.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::policy;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    /// Built frontend (scripts/build.sh output).
    pub dist_dir: PathBuf,
    /// Credentials, TDLib database, ledger, pause flag.
    pub runtime_dir: PathBuf,
    /// Uploads in progress and verified jobs awaiting posting.
    pub spool_dir: PathBuf,
    /// Every verified donation, kept as `<sha256>` and `<sha256>.json`.
    pub firmware_dir: PathBuf,
    /// Download images posted before `firmware_dir` existed back from the
    /// Telegram group (at every start, skipping what is already there).
    pub firmware_backfill: bool,
    /// Peers whose X-Forwarded-For header is trusted (pyx on loopback).
    pub trusted_proxies: Vec<std::net::IpAddr>,
    /// Refuse new donations (also toggled live by `runtime/paused`).
    pub paused: bool,
    /// Where the site is reachable (for the URLs `fwdonor admin-url` prints).
    pub public_url: String,
    pub limits: Limits,
    pub pow: Pow,
    pub policy: Policy,
    pub telegram: Telegram,
    pub bulk: Bulk,
}

/// Bulk donations: grant links whose uploads stay on this server.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Bulk {
    /// Stored files (`<sha256>` and `<sha256>.json`) and, in `.partial/`,
    /// unfinished uploads.
    pub dir: PathBuf,
    /// Chunk size: a multiple of 1 MiB, at most 16 MiB (the proxy allows
    /// 32 MiB per request and 120 s to send it).
    pub chunk_bytes: u64,
    /// Unfinished uploads untouched this long are deleted.
    pub partial_ttl_days: u64,
    /// Never let uploads fill the disk beyond this much free space.
    pub min_free_bytes: u64,
    /// Chunk uploads in flight per grant, and in total.
    pub max_puts_per_grant: usize,
    pub max_puts: usize,
    /// Unfinished uploads per grant.
    pub max_unfinished: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub min_file_bytes: u64,
    pub chunk_bytes: u64,
    pub per_ip_concurrent: u32,
    pub per_ip_files_per_hour: u32,
    pub per_ip_bytes_per_hour: u64,
    pub spool_cap_bytes: u64,
    pub idle_upload_secs: u64,
    pub ban_after_rejections: u32,
    pub ban_secs: u64,
    pub analysis_concurrency: usize,
    pub analysis_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Pow {
    pub bits: u8,
    pub ttl_secs: u64,
    /// Downloads from the public dashboard need this many bits more than
    /// an upload (each bit doubles the work).
    pub download_extra_bits: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Heuristic or combined ISA guesses below this confidence are not trusted.
    pub min_guess_confidence: f64,
    /// Formats accepted even when zrax resolves no ISA (firmware containers).
    pub allow: Vec<String>,
    /// Formats rejected even when zrax resolves an ISA.
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Telegram {
    pub chat_id: i64,
    /// Path to libtdjson.so (scripts/build-tdlib.sh output).
    pub tdjson: PathBuf,
    /// Log and delete instead of posting (local testing).
    pub dry_run: bool,
    /// TDLib log verbosity (0 = fatal only, 1 = errors, 2 = warnings).
    pub log_verbosity: u8,
    /// Chats the group had before, newest first (Telegram upgrades a basic
    /// group to a supergroup with a new id). The backfill finds older posts
    /// there.
    pub previous_chat_ids: Vec<i64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:18090".parse().unwrap(),
            dist_dir: "/data/fwdonor/dist".into(),
            runtime_dir: "/data/fwdonor/runtime".into(),
            spool_dir: "/data/fwdonor/spool".into(),
            firmware_dir: "/data/fwdonor/firmwares".into(),
            firmware_backfill: true,
            trusted_proxies: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            paused: false,
            public_url: "https://fwdonor.zr.ax".into(),
            limits: Limits::default(),
            pow: Pow::default(),
            policy: Policy::default(),
            telegram: Telegram::default(),
            bulk: Bulk::default(),
        }
    }
}

impl Default for Bulk {
    fn default() -> Self {
        Self {
            dir: "/data/fwdonor/bulk".into(),
            chunk_bytes: 8 * 1024 * 1024,
            partial_ttl_days: 14,
            min_free_bytes: 200 * 1024 * 1024 * 1024,
            max_puts_per_grant: 16,
            max_puts: 64,
            max_unfinished: 1000,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 512 * 1024 * 1024,
            min_file_bytes: 24,
            chunk_bytes: 4 * 1024 * 1024,
            per_ip_concurrent: 2,
            per_ip_files_per_hour: 30_000,
            per_ip_bytes_per_hour: 256 * 1024 * 1024 * 1024,
            spool_cap_bytes: 16 * 1024 * 1024 * 1024,
            idle_upload_secs: 120,
            ban_after_rejections: 3,
            ban_secs: 24 * 3600,
            analysis_concurrency: 2,
            analysis_timeout_secs: 180,
        }
    }
}

impl Default for Pow {
    fn default() -> Self {
        Self { bits: 20, ttl_secs: 600, download_extra_bits: 6 }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_guess_confidence: 0.5,
            allow: policy::DEFAULT_ALLOW.iter().map(|s| s.to_string()).collect(),
            deny: policy::DEFAULT_DENY.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Default for Telegram {
    fn default() -> Self {
        Self {
            chat_id: -1003917356862,
            tdjson: "/data/fwdonor/tdlib/lib/libtdjson.so".into(),
            dry_run: false,
            log_verbosity: 1,
            previous_chat_ids: vec![-5599544901],
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else { return Ok(Self::default()) };
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Self = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        let l = &self.limits;
        anyhow::ensure!(l.chunk_bytes >= 64 * 1024, "limits.chunk_bytes must be at least 64 KiB");
        anyhow::ensure!(l.max_file_bytes >= l.min_file_bytes, "limits.max_file_bytes < min_file_bytes");
        anyhow::ensure!(l.analysis_concurrency > 0, "limits.analysis_concurrency must be > 0");
        anyhow::ensure!((8..=32).contains(&self.pow.bits), "pow.bits must be within 8..=32");
        anyhow::ensure!(
            (8..=36).contains(&(self.pow.bits + self.pow.download_extra_bits)),
            "pow.bits + pow.download_extra_bits must be within 8..=36 (16 solutions of 4 bits less each)"
        );
        let b = &self.bulk;
        anyhow::ensure!(
            b.chunk_bytes % (1024 * 1024) == 0 && (1..=16).contains(&(b.chunk_bytes >> 20)),
            "bulk.chunk_bytes must be a multiple of 1 MiB, at most 16 MiB"
        );
        anyhow::ensure!(b.max_puts > 0 && b.max_puts_per_grant > 0, "bulk.max_puts* must be > 0");
        Ok(())
    }

    pub fn credentials_path(&self) -> PathBuf {
        self.runtime_dir.join("telegram.json")
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.runtime_dir.join("posted.jsonl")
    }

    pub fn zrax_revs_path(&self) -> PathBuf {
        self.runtime_dir.join("zrax-revs.json")
    }

    /// The admin page is `/g/<this key>`.
    pub fn admin_key_path(&self) -> PathBuf {
        self.runtime_dir.join("admin.key")
    }

    /// The firmware dashboard is `/d/<this key>` (a different key).
    pub fn dashboard_key_path(&self) -> PathBuf {
        self.runtime_dir.join("dashboard.key")
    }

    pub fn bulk_grants_path(&self) -> PathBuf {
        self.runtime_dir.join("bulk-grants.json")
    }

    /// One line per stored bulk file (quota totals without reading every record).
    pub fn bulk_ledger_path(&self) -> PathBuf {
        self.runtime_dir.join("bulk.jsonl")
    }

    pub fn pause_flag_path(&self) -> PathBuf {
        self.runtime_dir.join("paused")
    }

    pub fn tdlib_dir(&self) -> PathBuf {
        self.runtime_dir.join("tdlib")
    }

    /// Paused by config or by the live flag file.
    pub fn is_paused(&self) -> bool {
        self.paused || self.pause_flag_path().exists()
    }
}

/// zrax commit this binary and its WASM were built from.
pub fn zrax_rev() -> &'static str {
    include_str!("../ZRAX_REV").trim()
}
