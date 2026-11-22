//! The MAC of the vault config (format.md 3.3.8 and 7.2.1).

pub use crate::keys::MacKey;

/// The size of the MAC.
pub const MAC_SIZE: usize = 32;

/// The keyed BLAKE3 hash of the bytes of a config map.
pub fn config_mac(key: &MacKey, bytes: &[u8]) -> [u8; MAC_SIZE] {
    *blake3::keyed_hash(key.as_bytes(), bytes).as_bytes()
}

/// Checks the MAC of a config map. The comparison takes the same time whatever
/// the bytes are.
pub fn verify_config_mac(key: &MacKey, bytes: &[u8], mac: &[u8; MAC_SIZE]) -> bool {
    // `blake3::Hash` compares in constant time.
    blake3::keyed_hash(key.as_bytes(), bytes) == blake3::Hash::from_bytes(*mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_verifies_only_the_same_bytes_and_key() {
        let key = MacKey::from_bytes([3; 32]);
        let mac = config_mac(&key, b"config");
        assert!(verify_config_mac(&key, b"config", &mac));
        assert!(!verify_config_mac(&key, b"config!", &mac));
        assert!(!verify_config_mac(
            &MacKey::from_bytes([4; 32]),
            b"config",
            &mac
        ));
        let mut bad = mac;
        bad[31] ^= 1;
        assert!(!verify_config_mac(&key, b"config", &bad));
    }
}
