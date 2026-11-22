//! Identifier types. Each hash domain has its own type, so one kind of hash
//! cannot be used where another is expected (format.md 3.2.5).

use core::fmt;

/// Length of every hash in the format, in bytes.
pub const HASH_LEN: usize = 32;

macro_rules! hash_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; HASH_LEN]);

        impl $name {
            /// Wraps the 32 bytes of a hash.
            pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
                Self(bytes)
            }

            /// The 32 bytes of the hash.
            pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
                &self.0
            }
        }

        impl From<[u8; HASH_LEN]> for $name {
            fn from(bytes: [u8; HASH_LEN]) -> Self {
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
    ObjectId
);

hash_type!(
    /// The keyed hash of the full plaintext of a content, in the content hash
    /// domain (format.md 5.3.1).
    ContentHash
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
