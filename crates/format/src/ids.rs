//! Identifier types. Each kind of ID and each hash domain has its own type, so
//! one kind cannot be used where another is expected (format.md 3.2.5, 5.4.5).

use core::fmt;

/// Size of every hash in the format, in bytes.
pub const HASH_LEN: usize = 32;
/// Size of a source ID, a snapshot ID, and a vault ID, in bytes.
pub const SHORT_ID_LEN: usize = 16;

macro_rules! hash_type {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Wraps the bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
        }

        // Lowercase hexadecimal. These values are opaque and are not secret.
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
    };
}

hash_type!(
    /// The ID of an object: a hash in the object ID domain (format.md 4.7).
    /// The ID of a chunk is also an object ID (format.md 5.1.2).
    ObjectId,
    HASH_LEN
);

hash_type!(
    /// The keyed hash of the full plaintext of a content, in the content hash
    /// domain (format.md 5.3.1).
    ContentHash,
    HASH_LEN
);

hash_type!(
    /// The key of an item: a hash in the item key domain (format.md 5.6.5).
    ItemKey,
    HASH_LEN
);

hash_type!(
    /// The ID of a source: 16 random bytes (format.md 5.4.5.1).
    SourceId,
    SHORT_ID_LEN
);

hash_type!(
    /// The ID of a snapshot: 16 random bytes (format.md 5.9.1.1).
    SnapshotId,
    SHORT_ID_LEN
);

hash_type!(
    /// The ID of a vault: 16 random bytes in the vault config (format.md 7.2.2).
    VaultId,
    SHORT_ID_LEN
);

#[cfg(test)]
mod tests {
    extern crate std;
    use std::format;

    use super::*;

    #[test]
    fn display_is_lowercase_hex() {
        let mut bytes = [0u8; HASH_LEN];
        bytes[0] = 0xab;
        bytes[31] = 0x05;
        let id = ObjectId::from_bytes(bytes);
        let shown = format!("{id}");
        assert_eq!(shown.len(), 64);
        assert!(shown.starts_with("ab00"));
        assert!(shown.ends_with("0005"));
        assert_eq!(format!("{id:?}"), format!("ObjectId({shown})"));
    }
}
