//! Stateless, file-bound proof of work.
//!
//! token  = rand16 ‖ expiry_u64be ‖ bits_u8 ‖ HMAC-SHA256(key, those 25 bytes)[..16]
//! seed   = SHA256(token ‖ file_sha256)
//! accept = leading_zero_bits(SHA256(seed ‖ nonce_u64be)) >= bits
//!
//! Zero bits are counted MSB-first from byte 0. The key is regenerated on
//! every start, so outstanding tokens die with the process (clients simply
//! fetch a new challenge). Used tokens are remembered until they expire.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

const BODY_LEN: usize = 16 + 8 + 1;
const MAC_LEN: usize = 16;
pub const TOKEN_LEN: usize = BODY_LEN + MAC_LEN;
const MAX_TRACKED: usize = 500_000;

#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    Malformed,
    BadMac,
    Expired,
    Replayed,
    Insufficient,
    Busy,
    /// Not the required number of distinct solutions.
    Incomplete(usize),
}

impl std::fmt::Display for PowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PowError::Malformed => "malformed proof-of-work token",
            PowError::BadMac => "invalid proof-of-work token",
            PowError::Expired => "proof-of-work token expired",
            PowError::Replayed => "proof-of-work token already used",
            PowError::Insufficient => "proof of work does not meet the difficulty",
            PowError::Busy => "too many outstanding challenges",
            PowError::Incomplete(n) => return write!(f, "the proof of work needs {n} different solutions, in increasing order"),
        })
    }
}

pub struct Challenge {
    pub token: String,
    pub bits: u8,
    pub expires: u64,
}

pub struct PowGate {
    key: [u8; 32],
    bits: u8,
    ttl_secs: u64,
    used: Mutex<HashMap<[u8; 16], u64>>,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// HMAC-SHA256 (RFC 2104) over sha2; the key is always 32 bytes here.
fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(message).finalize();
    let outer = Sha256::new().chain_update(opad).chain_update(inner).finalize();
    outer.into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

pub fn seed(token: &[u8], file_sha256: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update(token).chain_update(file_sha256).finalize().into()
}

pub fn work_hash(seed: &[u8; 32], nonce: u64) -> [u8; 32] {
    Sha256::new().chain_update(seed).chain_update(nonce.to_be_bytes()).finalize().into()
}

impl PowGate {
    pub fn new(bits: u8, ttl_secs: u64) -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self { key, bits, ttl_secs, used: Mutex::new(HashMap::new()) }
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }

    pub fn issue(&self) -> Challenge {
        let expires = now_secs() + self.ttl_secs;
        let mut token = [0u8; TOKEN_LEN];
        rand::rng().fill_bytes(&mut token[..16]);
        token[16..24].copy_from_slice(&expires.to_be_bytes());
        token[24] = self.bits;
        let mac = hmac_sha256(&self.key, &token[..BODY_LEN]);
        token[BODY_LEN..].copy_from_slice(&mac[..MAC_LEN]);
        Challenge { token: URL_SAFE_NO_PAD.encode(token), bits: self.bits, expires }
    }

    /// Verify and consume a solution. On success the token can't be reused.
    pub fn redeem(&self, token_b64: &str, file_sha256: &[u8; 32], nonce: u64) -> Result<(), PowError> {
        let (id, expires) = self.verify(token_b64, file_sha256, nonce)?;
        let now = now_secs();
        let mut used = self.used.lock().unwrap();
        if used.len() >= MAX_TRACKED {
            used.retain(|_, exp| *exp >= now);
            if used.len() >= MAX_TRACKED {
                return Err(PowError::Busy);
            }
        }
        if used.insert(id, expires).is_some() {
            return Err(PowError::Replayed);
        }
        Ok(())
    }

    /// Verify `count` distinct solutions (strictly increasing nonces) without
    /// consuming them: they stay good for this file until the token expires
    /// (downloads, which a client may resume). Many small proofs instead of
    /// one big one cost the same on average but take a steady time, and a
    /// client can find them on all its cores at once.
    pub fn check_all(&self, token_b64: &str, file_sha256: &[u8; 32], nonces: &[u64], count: usize) -> Result<(), PowError> {
        let (token, bits, _) = self.open(token_b64)?;
        if nonces.len() != count || nonces.windows(2).any(|w| w[0] >= w[1]) {
            return Err(PowError::Incomplete(count));
        }
        let s = seed(&token, file_sha256);
        if nonces.iter().any(|&n| leading_zero_bits(&work_hash(&s, n)) < u32::from(bits)) {
            return Err(PowError::Insufficient);
        }
        Ok(())
    }

    /// The token's id and expiry when the solution is valid.
    fn verify(&self, token_b64: &str, file_sha256: &[u8; 32], nonce: u64) -> Result<([u8; 16], u64), PowError> {
        let (token, bits, expires) = self.open(token_b64)?;
        if leading_zero_bits(&work_hash(&seed(&token, file_sha256), nonce)) < u32::from(bits) {
            return Err(PowError::Insufficient);
        }
        Ok((token[..16].try_into().unwrap(), expires))
    }

    /// A token this gate issued that hasn't expired: its bytes, difficulty
    /// and expiry.
    fn open(&self, token_b64: &str) -> Result<(Vec<u8>, u8, u64), PowError> {
        let token = URL_SAFE_NO_PAD.decode(token_b64.trim()).map_err(|_| PowError::Malformed)?;
        if token.len() != TOKEN_LEN {
            return Err(PowError::Malformed);
        }
        let mac = hmac_sha256(&self.key, &token[..BODY_LEN]);
        if !constant_time_eq(&mac[..MAC_LEN], &token[BODY_LEN..]) {
            return Err(PowError::BadMac);
        }
        let expires = u64::from_be_bytes(token[16..24].try_into().unwrap());
        if expires < now_secs() {
            return Err(PowError::Expired);
        }
        // The MAC covers the difficulty, but never accept less than current.
        let bits = token[24].max(self.bits);
        Ok((token, bits, expires))
    }

    pub fn prune(&self) {
        let now = now_secs();
        self.used.lock().unwrap().retain(|_, exp| *exp >= now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solve(token_b64: &str, sha: &[u8; 32], bits: u32) -> u64 {
        let token = URL_SAFE_NO_PAD.decode(token_b64).unwrap();
        let s = seed(&token, sha);
        (0u64..).find(|n| leading_zero_bits(&work_hash(&s, *n)) >= bits).unwrap()
    }

    #[test]
    fn hmac_matches_rfc4231_style_vector() {
        // HMAC-SHA256 with a 32-byte key of 0x0b and message "Hi There"
        // (RFC 4231 case 1 uses a 20-byte key; padding makes these equal
        // only for the zero-extended key, so check against a known value).
        let mut key = [0u8; 32];
        key[..20].copy_from_slice(&[0x0b; 20]);
        assert_eq!(
            hex::encode(hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    const SEED_HEX: &str = "dbc6fdbf9aa7073991a41989beb2d94337580fb52a8e5b345441762a1a59d48e";
    const NONCE_12: u64 = 449;

    #[test]
    fn shared_test_vector() {
        // Mirrored in tests/pow.test.mjs: the browser solver must agree.
        let token = [0x11u8; TOKEN_LEN];
        let sha = [0x22u8; 32];
        let s = seed(&token, &sha);
        let nonce = (0u64..).find(|n| leading_zero_bits(&work_hash(&s, *n)) >= 12).unwrap();
        println!("seed={} nonce12={} hash={}", hex::encode(s), nonce, hex::encode(work_hash(&s, nonce)));
        assert_eq!(hex::encode(s), SEED_HEX);
        assert_eq!(nonce, NONCE_12);
    }

    #[test]
    fn round_trip_and_failures() {
        let gate = PowGate::new(10, 60);
        let sha = [7u8; 32];
        let c = gate.issue();
        let nonce = solve(&c.token, &sha, 10);
        // A solution is bound to its file hash (skip the 1/1024 coincidence).
        let raw = URL_SAFE_NO_PAD.decode(&c.token).unwrap();
        if leading_zero_bits(&work_hash(&seed(&raw, &[8u8; 32]), nonce)) < 10 {
            assert_eq!(gate.redeem(&c.token, &[8u8; 32], nonce), Err(PowError::Insufficient));
        }
        // check_all() wants distinct solutions and leaves the token usable.
        let s = seed(&raw, &sha);
        let three: Vec<u64> = (0u64..).filter(|n| leading_zero_bits(&work_hash(&s, *n)) >= 10).take(3).collect();
        assert_eq!(three[0], nonce);
        assert_eq!(gate.check_all(&c.token, &sha, &three, 3), Ok(()));
        assert_eq!(gate.check_all(&c.token, &sha, &three, 3), Ok(()), "not consumed");
        assert_eq!(gate.check_all(&c.token, &sha, &three[..2], 3), Err(PowError::Incomplete(3)));
        assert_eq!(gate.check_all(&c.token, &sha, &[three[0], three[0], three[1]], 3), Err(PowError::Incomplete(3)));
        assert_eq!(gate.check_all(&c.token, &sha, &[three[1], three[0], three[2]], 3), Err(PowError::Incomplete(3)));
        let bad = (three[0] + 1..).find(|n| leading_zero_bits(&work_hash(&s, *n)) < 10).unwrap();
        let mut mixed = vec![three[0], bad, three[2]];
        mixed.sort();
        assert_eq!(gate.check_all(&c.token, &sha, &mixed, 3), Err(PowError::Insufficient));
        assert_eq!(gate.redeem(&c.token, &sha, nonce), Ok(()));
        assert_eq!(gate.redeem(&c.token, &sha, nonce), Err(PowError::Replayed));

        // Tampered difficulty breaks the MAC.
        let c = gate.issue();
        let mut raw = URL_SAFE_NO_PAD.decode(&c.token).unwrap();
        raw[24] = 1;
        assert_eq!(gate.redeem(&URL_SAFE_NO_PAD.encode(&raw), &sha, 0), Err(PowError::BadMac));

        // Token from another process (different key) is rejected.
        let other = PowGate::new(10, 60).issue();
        assert_eq!(gate.redeem(&other.token, &sha, 0), Err(PowError::BadMac));

        // Expired.
        let old = PowGate::new(10, 0);
        let c = old.issue();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let nonce = solve(&c.token, &sha, 10);
        assert_eq!(old.redeem(&c.token, &sha, nonce), Err(PowError::Expired));

        assert_eq!(gate.redeem("not base64!", &sha, 0), Err(PowError::Malformed));
    }

    #[test]
    fn zero_bits() {
        assert_eq!(leading_zero_bits(&[0, 0, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0, 0x0f]), 12);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
    }
}
