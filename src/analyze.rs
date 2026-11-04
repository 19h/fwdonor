//! zrax wrapper: classify bytes, apply the donation policy, and summarize the
//! result for the browser table and the Telegram caption.
//!
//! The rule here is authoritative; `web/policy.js` mirrors it using the same
//! lists from `/api/policy`, so the browser and server must agree.

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Semaphore;
use zrax::types::{ClassificationSource, ClassifierOptions, DetectionPayload, Isa};
use zrax::ClassifierError;

use crate::config::{zrax_rev, Policy};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SliceSummary {
    pub label: Option<String>,
    pub isa: Option<String>,
    pub isa_name: Option<String>,
    pub bitwidth: u8,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetaSummary {
    pub label: String,
    pub value: String,
}

/// What zrax established about an accepted file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    /// zrax `FileFormat` serde name, e.g. `elf`, `uimage`.
    pub format: String,
    /// Human format name, e.g. `ELF`, `U-Boot uImage`.
    pub format_name: String,
    pub format_variant: Option<String>,
    /// zrax `Isa` serde name when concrete, e.g. `a_arch64`.
    pub isa: Option<String>,
    /// Human ISA name, e.g. `AArch64 (ARM64)`.
    pub isa_name: Option<String>,
    /// Short ISA label for hashtags, e.g. `aarch64`.
    pub isa_tag: Option<String>,
    pub bitwidth: u8,
    pub endianness: String,
    pub confidence: f64,
    pub source: String,
    pub variant: Option<String>,
    pub slices: Vec<SliceSummary>,
    pub metadata: Vec<MetaSummary>,
    /// Why the file was accepted: `isa` or `container`.
    pub basis: String,
    pub zrax: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Accepted(Summary),
    Rejected { reason: String },
}

impl Verdict {
    fn reject(reason: impl Into<String>) -> Self {
        Verdict::Rejected { reason: reason.into() }
    }
}

/// serde name of a value that serializes to a plain string (concrete enum
/// variants); `None` for `Isa::Unknown(_)`, which serializes as an object.
fn serde_name<T: Serialize>(value: &T) -> Option<String> {
    match serde_json::to_value(value).ok()? {
        Value::String(s) => Some(s),
        _ => None,
    }
}

fn concrete_isa(isa: &Isa) -> Option<String> {
    if matches!(isa, Isa::Unknown(_)) {
        return None;
    }
    serde_name(isa)
}

/// An ISA that zrax's raw-code model recognizes, as listed on the page.
#[derive(Debug, Clone, Serialize)]
pub struct RawIsa {
    /// zrax `Isa` serde name, the key used in the ledger.
    pub key: String,
    pub name: &'static str,
}

/// Bytecode and CTF machines the model knows but that real firmware doesn't
/// ship, so the page doesn't ask for them.
const NOT_FIRMWARE: &[&str] = &["wasm", "jvm", "dalvik", "bpf", "clemency"];

/// Every ISA the embedded heuristic model can identify from raw code, in the
/// model's own order, one entry per ISA (ARM/Thumb/BE classes collapse).
pub fn raw_isas() -> &'static [RawIsa] {
    static LIST: std::sync::OnceLock<Vec<RawIsa>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        let mut seen = std::collections::HashSet::new();
        zrax::heuristics::Model::embedded()
            .classes()
            .filter_map(|class| match class.kind {
                zrax::heuristics::ClassKind::Code { isa, .. } => Some(isa),
                _ => None,
            })
            .filter_map(|isa| Some((concrete_isa(&isa)?, isa.name())))
            .filter(|(key, _)| !NOT_FIRMWARE.contains(&key.as_str()) && seen.insert(key.clone()))
            .map(|(key, name)| RawIsa { key, name })
            .collect()
    })
}

/// Human name for an ISA serde name from the ledger.
pub fn isa_display_name(key: &str) -> Option<&'static str> {
    serde_json::from_value::<Isa>(Value::String(key.to_string())).ok().map(|isa| isa.name())
}

pub fn zrax_label() -> String {
    format!("{}@{}", zrax::version(), &zrax_rev()[..7.min(zrax_rev().len())])
}

/// Classify `data` and apply `policy`. Synchronous and CPU-bound.
pub fn evaluate(data: &[u8], policy: &Policy) -> Verdict {
    let payload = match zrax::detect_payload(data, &ClassifierOptions::new()) {
        Ok(p) => p,
        Err(
            ClassifierError::HeuristicInconclusive { .. }
            | ClassifierError::HeuristicSparseCode { .. }
            | ClassifierError::FileTooSmall { .. },
        ) => {
            return Verdict::reject("unrecognized by zrax");
        }
        Err(e) => return Verdict::reject(format!("malformed: {e}")),
    };
    judge(&payload, policy)
}

/// The donation rule, applied to a zrax payload.
pub fn judge(p: &DetectionPayload, policy: &Policy) -> Verdict {
    let format = serde_name(&p.format.format).unwrap_or_else(|| "unknown".into());
    if policy.deny.iter().any(|d| *d == format) {
        return Verdict::reject(format!("excluded format ({format})"));
    }

    let guessed = matches!(p.primary.source, ClassificationSource::Heuristic | ClassificationSource::Combined);
    let primary_isa = concrete_isa(&p.primary.isa);
    let primary_ok = primary_isa.is_some() && (!guessed || p.primary.confidence >= policy.min_guess_confidence);
    let slice_ok = p.slices.iter().any(|s| concrete_isa(&s.isa).is_some());

    let basis = if primary_ok || slice_ok {
        "isa"
    } else if policy.allow.iter().any(|a| *a == format) {
        "container"
    } else if primary_isa.is_some() {
        return Verdict::reject(format!(
            "low-confidence guess ({:.0}% < {:.0}%)",
            p.primary.confidence * 100.0,
            policy.min_guess_confidence * 100.0
        ));
    } else {
        return Verdict::reject(format!("no ISA found in {format}"));
    };

    Verdict::Accepted(summarize(p, format, basis))
}

fn summarize(p: &DetectionPayload, format: String, basis: &str) -> Summary {
    let isa = concrete_isa(&p.primary.isa);
    Summary {
        format,
        format_name: p.format.format.to_string(),
        format_variant: p.format.variant_name.clone(),
        isa_name: isa.as_ref().map(|_| p.primary.isa.name().to_string()),
        isa_tag: isa.as_ref().map(|_| p.primary.isa.to_string()),
        isa,
        bitwidth: p.primary.bitwidth,
        endianness: serde_name(&p.primary.endianness).unwrap_or_default(),
        confidence: p.primary.confidence,
        source: serde_name(&p.primary.source).unwrap_or_default(),
        variant: p.primary.variant.as_ref().map(|v| v.to_string()),
        slices: p
            .slices
            .iter()
            .map(|s| {
                let isa = concrete_isa(&s.isa);
                SliceSummary {
                    label: s.label.clone(),
                    isa_name: isa.as_ref().map(|_| s.isa.name().to_string()),
                    isa,
                    bitwidth: s.bitwidth,
                    offset: s.offset,
                    size: s.size,
                }
            })
            .collect(),
        metadata: p
            .metadata
            .iter()
            .map(|m| MetaSummary { label: m.label.clone(), value: m.value.to_string() })
            .collect(),
        basis: basis.to_string(),
        zrax: zrax_label(),
    }
}

/// Bounded, panic-safe, time-limited analysis of spooled files.
#[derive(Clone)]
pub struct Analyzer {
    permits: Arc<Semaphore>,
    timeout: Duration,
    policy: Arc<Policy>,
}

impl Analyzer {
    pub fn new(concurrency: usize, timeout: Duration, policy: Arc<Policy>) -> Self {
        Self { permits: Arc::new(Semaphore::new(concurrency)), timeout, policy }
    }

    /// Parse the 6.2 MB code model once so the first donor doesn't pay for it.
    pub async fn warm_up(&self) {
        let policy = self.policy.clone();
        let _ = tokio::task::spawn_blocking(move || evaluate(&[0x90; 4096], &policy)).await;
    }

    /// A donation's verdict: zrax not coming to an answer is a rejection.
    pub async fn analyze_file(&self, path: PathBuf) -> Verdict {
        match self.analyze_file_outcome(path).await {
            Outcome::Verdict(v) => v,
            Outcome::Failed(reason) => Verdict::reject(reason),
        }
    }

    pub async fn analyze_file_outcome(&self, path: PathBuf) -> Outcome {
        let Ok(permit) = self.permits.clone().acquire_owned().await else {
            return Outcome::Failed("analyzer shut down".into());
        };
        let policy = self.policy.clone();
        // The permit lives inside the blocking closure: a timed-out analysis
        // keeps its slot until it really finishes, so stuck inputs cannot
        // pile up unbounded CPU work.
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            evaluate_file(&path, &policy)
        });
        match tokio::time::timeout(self.timeout, task).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => Outcome::Failed(format!("analysis failed: {e}")),
            Err(_) => Outcome::Failed("analysis timed out".into()),
        }
    }
}

/// zrax's verdict on a file, or why there is none.
#[derive(Debug, Clone)]
pub enum Outcome {
    Verdict(Verdict),
    /// The file couldn't be read, or zrax crashed or ran out of time.
    Failed(String),
}

/// Blocking. Read and classify a file, catching a zrax panic.
pub fn evaluate_file(path: &std::path::Path, policy: &Policy) -> Outcome {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return Outcome::Failed(format!("read failed: {e}")),
    };
    match std::panic::catch_unwind(AssertUnwindSafe(|| evaluate(&data, policy))) {
        Ok(v) => Outcome::Verdict(v),
        Err(_) => Outcome::Failed("analysis crashed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DEFAULT_ALLOW, DEFAULT_DENY};

    #[test]
    fn every_policy_name_is_a_zrax_format() {
        for name in DEFAULT_ALLOW.iter().chain(DEFAULT_DENY) {
            let parsed: Result<zrax::types::FileFormat, _> = serde_json::from_value(Value::String(name.to_string()));
            assert!(parsed.is_ok(), "{name} is not a zrax FileFormat serde name");
        }
    }

    #[test]
    fn raw_isa_list() {
        let list = raw_isas();
        let keys: Vec<&str> = list.iter().map(|i| i.key.as_str()).collect();
        assert!(list.len() > 50, "{keys:?}");
        for key in ["arm", "a_arch64", "i8051", "mcs96", "c166", "tricore", "risc_v64"] {
            assert!(keys.contains(&key), "{key} missing from {keys:?}");
        }
        assert!(!keys.contains(&"jvm") && !keys.contains(&"clemency"));
        assert_eq!(keys.iter().filter(|k| **k == "arm").count(), 1);
        assert_eq!(isa_display_name("a_arch64"), Some("AArch64 (ARM64)"));
        assert_eq!(isa_display_name("nonsense"), None);
    }

    #[test]
    fn rejects_text_and_noise() {
        let policy = Policy::default();
        let text = b"Hello, this is just a README file with some words in it.\n".repeat(200);
        assert!(matches!(evaluate(&text, &policy), Verdict::Rejected { .. }));
        assert!(matches!(evaluate(b"tiny", &policy), Verdict::Rejected { .. }));
        // Deterministic pseudo-random bytes.
        let mut x: u32 = 0x1234_5678;
        let noise: Vec<u8> = (0..65536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        assert!(matches!(evaluate(&noise, &policy), Verdict::Rejected { .. }));
    }
}
