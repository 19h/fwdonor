//! A look inside a stored file for the detail view: its first bytes, an
//! entropy profile (compressed or encrypted parts stand out) and printable
//! strings. Computed on demand, a few at a time, and cached.

use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::sync::Semaphore;

const HEAD_BYTES: u64 = 1024;
const POINTS: u64 = 256;
/// Bytes read per entropy window, at most (huge files are sampled).
const WINDOW_READ: u64 = 64 * 1024;
const STRINGS_SCAN: u64 = 4 * 1024 * 1024;
const MAX_STRINGS: usize = 300;
const MIN_STRING: usize = 6;
const MAX_STRING_LEN: usize = 200;
const CACHED: usize = 64;

/// Shannon entropy in bits per byte (0 to 8).
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}

/// Runs of printable ASCII (and tabs) of at least MIN_STRING characters,
/// with their offsets. Second value: there were more than MAX_STRINGS.
pub fn strings(bytes: &[u8]) -> (Vec<(u64, String)>, bool) {
    let mut out = Vec::new();
    let mut start = None;
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t';
    for (i, &b) in bytes.iter().chain(std::iter::once(&0u8)).enumerate() {
        match (printable(b) && i < bytes.len(), start) {
            (true, None) => start = Some(i),
            (true, Some(_)) => {}
            (false, Some(s)) => {
                if i - s >= MIN_STRING {
                    if out.len() == MAX_STRINGS {
                        return (out, true);
                    }
                    let end = (s + MAX_STRING_LEN).min(i);
                    out.push((s as u64, String::from_utf8_lossy(&bytes[s..end]).into_owned()));
                }
                start = None;
            }
            (false, None) => {}
        }
    }
    (out, false)
}

/// Blocking.
pub fn inspect_file(path: &Path) -> io::Result<Value> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    let read = |offset: u64, len: u64| -> io::Result<Vec<u8>> {
        let mut buf = vec![0; len as usize];
        file.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    };
    let head = read(0, size.min(HEAD_BYTES))?;
    let points = POINTS.min((size / 256).max(1));
    let window = size.div_ceil(points).max(1);
    let mut profile = Vec::with_capacity(points as usize);
    for i in 0..points {
        let offset = i * window;
        if offset >= size {
            break;
        }
        let bytes = read(offset, window.min(WINDOW_READ).min(size - offset))?;
        profile.push((entropy(&bytes) * 1000.0).round() / 1000.0);
    }
    let scanned = size.min(STRINGS_SCAN);
    let (found, truncated) = strings(&read(0, scanned)?);
    Ok(json!({
        "size": size,
        "head": hex::encode(head),
        "entropy": { "window": window, "sampled": window > WINDOW_READ, "points": profile },
        "strings": found,
        "strings_scanned": scanned,
        "strings_truncated": truncated,
    }))
}

pub struct Inspector {
    permits: Arc<Semaphore>,
    cache: Mutex<VecDeque<(String, Arc<Value>)>>,
}

impl Default for Inspector {
    fn default() -> Self {
        Self { permits: Arc::new(Semaphore::new(2)), cache: Mutex::new(VecDeque::new()) }
    }
}

impl Inspector {
    pub async fn inspect(&self, sha256: &str, path: PathBuf) -> io::Result<Arc<Value>> {
        if let Some((_, v)) = self.cache.lock().unwrap().iter().find(|(s, _)| s == sha256) {
            return Ok(v.clone());
        }
        let _permit = self.permits.acquire().await.map_err(io::Error::other)?;
        let value = Arc::new(tokio::task::spawn_blocking(move || inspect_file(&path)).await.map_err(io::Error::other)??);
        let mut cache = self.cache.lock().unwrap();
        if cache.len() == CACHED {
            cache.pop_front();
        }
        cache.push_back((sha256.to_string(), value.clone()));
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_strings_and_profile() {
        assert_eq!(entropy(&[0; 4096]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all.repeat(16)) - 8.0).abs() < 1e-9);
        let (found, more) = strings(b"\x00\x01short\x00a longer string here\xffend-of-file");
        assert_eq!(found, vec![(8, "a longer string here".to_string()), (29, "end-of-file".to_string())]);
        assert!(!more);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fw");
        let mut data = vec![0u8; 512 * 1024];
        data.extend((0..512 * 1024).map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
        data[100..117].copy_from_slice(b"U-Boot 2016.01-rc");
        std::fs::write(&path, &data).unwrap();
        let v = inspect_file(&path).unwrap();
        assert_eq!(v["size"], data.len());
        assert_eq!(v["head"].as_str().unwrap().len(), 2048);
        let points: Vec<f64> = v["entropy"]["points"].as_array().unwrap().iter().map(|p| p.as_f64().unwrap()).collect();
        assert_eq!(points.len(), 256);
        assert!(points[1] == 0.0 && points[200] > 7.0, "{:?}", &points[..4]);
        assert_eq!(v["strings"][0], json!([100, "U-Boot 2016.01-rc"]));
    }
}
