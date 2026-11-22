//! The names of the files of a vault (format.md section 7).

use alloc::format;
use alloc::string::String;
use nilperit_format::{PackName, SnapshotId};

/// The first copy of the vault config.
pub const CONFIG_A: &str = "config-a";
/// The second copy of the vault config.
pub const CONFIG_B: &str = "config-b";
/// The directory of the packs.
pub const PACKS_DIR: &str = "packs";
/// The directory of the snapshot headers.
pub const SNAPSHOTS_DIR: &str = "snapshots";

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Writes bytes as lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}

/// The path of a pack: `packs/<first two characters>/<name>` (see 6.4 and 7).
/// The name is the BLAKE3 hash of the file.
pub fn pack_path(name: &PackName) -> String {
    let name = hex(name.as_bytes());
    format!("{PACKS_DIR}/{}/{name}", &name[..2])
}

/// The path of a snapshot header (see 5.9.4).
pub fn snapshot_path(id: &SnapshotId) -> String {
    format!("{SNAPSHOTS_DIR}/{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn pack_path_uses_a_two_character_directory() {
        let path = pack_path(&PackName::from_bytes([0xab; 32]));
        assert_eq!(path, format!("packs/ab/{}", "ab".repeat(32)));
    }
}
