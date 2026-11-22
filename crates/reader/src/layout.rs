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
/// The writer lock (format.md 8.6.1). Only a writer uses it.
pub const LOCK_PATH: &str = "locks/writer";
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

/// Reads the name of a pack from a path in `packs/`. It returns `None` for a path
/// that is not `packs/<two characters>/<64 lowercase hexadecimal characters>`
/// where the two characters are the first two of the name. Such a file is not a
/// pack, for example a temporary file or an orphan from another program.
pub fn parse_pack_path(path: &str) -> Option<PackName> {
    let rest = path.strip_prefix(PACKS_DIR)?.strip_prefix('/')?;
    let (dir, name) = rest.split_once('/')?;
    if !name.starts_with(dir) || dir.len() != 2 {
        return None;
    }
    parse_hex(name).map(PackName::from_bytes)
}

/// Reads exactly `N` bytes from `2 * N` lowercase hexadecimal characters.
fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N {
        return None;
    }
    let mut bytes = [0u8; N];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(bytes)
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The path of a snapshot header (see 5.9.4).
pub fn snapshot_path(id: &SnapshotId) -> String {
    format!("{SNAPSHOTS_DIR}/{id}")
}

/// Reads the snapshot ID from a path in `snapshots/` (see `snapshot_path`). It
/// returns `None` for any other path.
pub fn parse_snapshot_path(path: &str) -> Option<SnapshotId> {
    let name = path.strip_prefix(SNAPSHOTS_DIR)?.strip_prefix('/')?;
    parse_hex(name).map(SnapshotId::from_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn parse_pack_path_reads_what_pack_path_writes() {
        let name = PackName::from_bytes(core::array::from_fn(|i| (i * 9) as u8));
        assert_eq!(parse_pack_path(&pack_path(&name)), Some(name));
    }

    #[test]
    fn parse_snapshot_path_reads_what_snapshot_path_writes() {
        let id = SnapshotId::from_bytes(core::array::from_fn(|i| (i * 17) as u8));
        assert_eq!(parse_snapshot_path(&snapshot_path(&id)), Some(id));
        for bad in [
            "snapshots",
            "snapshots/",
            "snapshots/00",
            "snapshots/00112233445566778899AABBCCDDEEFF",
            "snapshots/00112233445566778899aabbccddeeff0",
            "snapshots/a/00112233445566778899aabbccddeeff",
            "packs/00112233445566778899aabbccddeeff",
        ] {
            assert!(parse_snapshot_path(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn parse_pack_path_rejects_other_files() {
        let good = pack_path(&PackName::from_bytes([0xab; 32]));
        assert!(parse_pack_path(&good).is_some());
        let name = "ab".repeat(32);
        for bad in [
            "packs",
            "packs/ab",
            "packs/ab/abab",
            &format!("packs/cd/{name}"),
            &format!("packs/ab/{}", name.to_uppercase()),
            &format!("packs/ab/{name}.tmp"),
            &format!("packs/ab/x/{name}"),
            &format!("other/ab/{name}"),
            &format!("packs/abc/{name}"),
            &format!("packs/ab/{}", "zz".repeat(32)),
        ] {
            assert!(parse_pack_path(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn pack_path_uses_a_two_character_directory() {
        let path = pack_path(&PackName::from_bytes([0xab; 32]));
        assert_eq!(path, format!("packs/ab/{}", "ab".repeat(32)));
    }
}
