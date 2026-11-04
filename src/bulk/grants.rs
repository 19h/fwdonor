//! Grants (bulk upload links with a fixed donor name and a storage ceiling)
//! and the admin key that protects the page issuing them.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub token: String,
    /// Donor name every upload of this grant is credited to.
    pub name: String,
    pub ceiling_bytes: u64,
    /// Private note for the admin page.
    #[serde(default)]
    pub note: String,
    pub created_at: u64,
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

impl Grant {
    pub fn live(&self) -> bool {
        self.revoked_at.is_none()
    }
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// 128 random bits: the `/r/<token>` part of a grant link.
pub fn new_token() -> String {
    random_b64(16)
}

fn url_safe(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn valid_token(s: &str) -> bool {
    url_safe(s, 22)
}

pub fn valid_admin_key(s: &str) -> bool {
    url_safe(s, 43)
}

/// Compare secrets without an early exit.
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Donor names follow the main page's rule (letters, digits, `_ . -`).
pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A secret page key (256 random bits), created on the first start. `what`
/// and `command` name it in the log.
pub fn load_or_create_key(path: &Path, what: &str, command: &str) -> Result<String> {
    match read_key(path) {
        Ok(key) => Ok(key),
        Err(_) if !path.exists() => {
            let key = random_b64(32);
            super::write_durably(path, format!("{key}\n").as_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            tracing::info!("created the {what} key in {} (`fwdonor {command}` prints the page URL)", path.display());
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// The bulk admin key (`/g/<key>`).
pub fn load_or_create_admin_key(path: &Path) -> Result<String> {
    load_or_create_key(path, "bulk admin", "admin-url")
}

pub fn read_key(path: &Path) -> Result<String> {
    let key = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = key.trim().to_string();
    anyhow::ensure!(valid_admin_key(&key), "{} does not hold a valid key", path.display());
    Ok(key)
}

/// `runtime/bulk-grants.json`, rewritten whole on every change.
pub struct GrantFile {
    path: PathBuf,
    pub grants: Vec<Grant>,
}

impl GrantFile {
    pub fn load(path: &Path) -> Result<Self> {
        let grants = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path: path.to_owned(), grants })
    }

    pub fn save(&self) -> std::io::Result<()> {
        super::write_durably(&self.path, &serde_json::to_vec_pretty(&self.grants)?)
    }

    pub fn get(&self, token: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| ct_eq(&g.token, token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_keys() {
        let t = new_token();
        assert!(valid_token(&t), "{t}");
        assert!(!valid_token(&t[1..]) && !valid_token(&format!("{}/", &t[1..])));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin.key");
        let key = load_or_create_admin_key(&path).unwrap();
        assert!(valid_admin_key(&key));
        assert_eq!(load_or_create_admin_key(&path).unwrap(), key, "created once");
        let dash = load_or_create_key(&dir.path().join("dashboard.key"), "dashboard", "dashboard-url").unwrap();
        assert!(valid_admin_key(&dash) && dash != key, "a key of its own");
        assert_eq!(read_key(&dir.path().join("dashboard.key")).unwrap(), dash);
        assert!(ct_eq(&key, &key.clone()) && !ct_eq(&key, &new_token()));
        assert!(valid_name("Sonic") && valid_name("a.b-c_1") && !valid_name("") && !valid_name("no spaces"));
    }

    #[test]
    fn grant_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.json");
        let mut file = GrantFile::load(&path).unwrap();
        assert!(file.grants.is_empty());
        let token = new_token();
        file.grants.push(Grant {
            token: token.clone(),
            name: "Sonic".into(),
            ceiling_bytes: 500_000_000_000,
            note: String::new(),
            created_at: 1,
            revoked_at: None,
        });
        file.save().unwrap();
        let again = GrantFile::load(&path).unwrap();
        assert_eq!(again.get(&token).unwrap().name, "Sonic");
        assert!(again.get(&new_token()).is_none());
    }
}
