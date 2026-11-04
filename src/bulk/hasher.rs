//! A SHA-256 whose state can be saved to disk and restored, so the whole-file
//! hash of a bulk upload survives restarts (`hash.state` in its partial dir).

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::digest::common::hazmat::{SerializableState, SerializedState};
use sha2::Sha256;

/// `hash.state`: the hash over chunks `0..next`.
#[derive(Serialize, Deserialize)]
struct Saved {
    next: u64,
    state: String,
}

pub fn encode(hasher: &Sha256) -> String {
    hex::encode(hasher.serialize().as_slice())
}

pub fn decode(text: &str) -> Option<Sha256> {
    let bytes = hex::decode(text).ok()?;
    let state = SerializedState::<Sha256>::try_from(bytes.as_slice()).ok()?;
    Sha256::deserialize(&state).ok()
}

/// Write the checkpoint durably (tmp, fsync, rename). The caller has already
/// made the data it covers durable.
pub fn save(path: &Path, next: u64, hasher: &Sha256) -> std::io::Result<()> {
    let saved = Saved { next, state: encode(hasher) };
    super::write_durably(path, &serde_json::to_vec(&saved)?)
}

/// The checkpoint, if there is a readable one.
pub fn load(path: &Path) -> Option<(u64, Sha256)> {
    let bytes = std::fs::read(path).ok()?;
    let saved: Saved = serde_json::from_slice(&bytes).ok()?;
    Some((saved.next, decode(&saved.state)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use sha2::Digest;

    #[test]
    fn restored_state_continues_the_same_hash() {
        let mut rng = rand::rng();
        for size in [0usize, 1, 63, 64, 65, 1000, 4096 * 3 + 17] {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            let expected = Sha256::digest(&data);
            for cut in [0, size / 3, size / 2, size] {
                let mut first = Sha256::new();
                first.update(&data[..cut]);
                let mut second = decode(&encode(&first)).expect("state round trip");
                second.update(&data[cut..]);
                assert_eq!(second.finalize(), expected, "size {size}, cut {cut}");
            }
        }
    }

    #[test]
    fn checkpoint_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hash.state");
        let mut h = Sha256::new();
        h.update(b"abc");
        save(&path, 7, &h).unwrap();
        let (next, restored) = load(&path).unwrap();
        assert_eq!(next, 7);
        assert_eq!(restored.finalize(), Sha256::digest(b"abc"));
        std::fs::write(&path, b"{\"next\":1,\"state\":\"zz\"}").unwrap();
        assert!(load(&path).is_none());
    }
}
