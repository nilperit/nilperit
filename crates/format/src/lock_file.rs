//! The writer lock file (format.md 8.6).
//!
//! The lock file is plaintext and not authenticated (format.md 3.3.10). It is one
//! deterministic CBOR map. It has no envelope: it is not an object.

use alloc::vec::Vec;

use crate::canonical;
use crate::content_object::ObjectError;
use crate::envelope::EnvelopeError;
use crate::fields::{Fields, read_array, read_i64, write_bytes, write_i64, write_map};
use crate::ids::NodeId;

const KEY_NODE_ID: u64 = 1;
const KEY_HEARTBEAT: u64 = 2;

/// The largest lock file that a reader accepts, in bytes.
pub const MAX_LOCK_FILE_SIZE: usize = 1024;

/// The content of the writer lock (format.md 8.6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockFile {
    /// The node that holds the lock.
    pub node_id: NodeId,
    /// The time of the last heartbeat of the holder, by its clock, in milliseconds
    /// (format.md 5.4.5.3).
    pub heartbeat: i64,
}

impl LockFile {
    /// Encodes the lock file.
    pub fn encode(&self) -> Vec<u8> {
        write_map(&[
            (KEY_NODE_ID, write_bytes(self.node_id.as_bytes())),
            (KEY_HEARTBEAT, write_i64(self.heartbeat)),
        ])
    }

    /// Decodes a lock file. It ignores unknown keys (format.md 4.5).
    pub fn decode(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() > MAX_LOCK_FILE_SIZE {
            return Err(ObjectError::Rule("lock file is larger than the limit"));
        }
        canonical::check(bytes)
            .map_err(|e| ObjectError::Envelope(EnvelopeError::NotCanonical(e)))?;
        let fields = Fields::of_map(bytes, 0)?;
        Ok(Self {
            node_id: NodeId::from_bytes(read_array(fields.require(KEY_NODE_ID)?, KEY_NODE_ID)?),
            heartbeat: read_i64(fields.require(KEY_HEARTBEAT)?, KEY_HEARTBEAT)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn lock() -> LockFile {
        LockFile {
            node_id: NodeId::from_bytes([0x55; 16]),
            heartbeat: 1_700_000_002_000,
        }
    }

    #[test]
    fn round_trips() {
        for heartbeat in [0, 1, -1, i64::MIN, i64::MAX, 1_700_000_002_000] {
            let lock = LockFile {
                heartbeat,
                ..lock()
            };
            assert_eq!(LockFile::decode(&lock.encode()).unwrap(), lock);
        }
    }

    #[test]
    fn ignores_unknown_keys() {
        let bytes = write_map(&[
            (KEY_NODE_ID, write_bytes(&[0x55; 16])),
            (KEY_HEARTBEAT, write_i64(5)),
            (9, write_bytes(b"future")),
        ]);
        assert_eq!(LockFile::decode(&bytes).unwrap().heartbeat, 5);
    }

    #[test]
    fn rejects_what_is_not_a_lock_file() {
        let good = lock().encode();
        // Not a map, trailing bytes, too large, and a damaged map.
        assert!(LockFile::decode(&[]).is_err());
        assert!(LockFile::decode(&[0x01]).is_err());
        let mut longer = good.clone();
        longer.push(0);
        assert!(LockFile::decode(&longer).is_err());
        assert!(LockFile::decode(&vec![0; MAX_LOCK_FILE_SIZE + 1]).is_err());
        for cut in 0..good.len() {
            assert!(LockFile::decode(&good[..cut]).is_err(), "cut at {cut}");
        }
        // A field is missing, or has the wrong type or size.
        for fields in [
            vec![(KEY_NODE_ID, write_bytes(&[0x55; 16]))],
            vec![(KEY_HEARTBEAT, write_i64(5))],
            vec![
                (KEY_NODE_ID, write_bytes(&[0x55; 15])),
                (KEY_HEARTBEAT, write_i64(5)),
            ],
            vec![
                (KEY_NODE_ID, write_bytes(&[0x55; 16])),
                (KEY_HEARTBEAT, write_bytes(b"5")),
            ],
        ] {
            assert!(LockFile::decode(&write_map(&fields)).is_err());
        }
    }
}
