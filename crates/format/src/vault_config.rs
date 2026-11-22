//! The vault config (format.md 7.2) and the essential fields that a snapshot
//! header repeats (format.md 5.9.1).
//!
//! A config file is the bytes of one deterministic CBOR map followed by a MAC of
//! 32 bytes. This module reads and writes the map and splits the file. It does
//! not make or check the MAC: that needs keys, which are in `nilperit-crypto`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::canonical;
use crate::content_object::ObjectError;
use crate::envelope::EnvelopeError;
use crate::fields::{
    Fields, read_array, read_bytes, read_text, read_u32, read_u64, write_array, write_bytes,
    write_map, write_text, write_u64,
};
use crate::ids::VaultId;
use crate::pack::{ENCRYPTION_XCHACHA20_POLY1305, FORMAT_VERSION, HASH_BLAKE3};

/// The largest allowed config file, in bytes (format.md 7.2.1).
pub const MAX_CONFIG_SIZE: usize = 1 << 20;
/// The size of the MAC at the end of a config file.
pub const MAC_SIZE: usize = 32;

const KEY_FORMAT_VERSION: u64 = 1;
const KEY_SEQUENCE: u64 = 2;
const KEY_VAULT_ID: u64 = 3;
const KEY_ENCRYPTION: u64 = 4;
const KEY_HASH: u64 = 5;
const KEY_KEY_ENCAPSULATION: u64 = 6;
const KEY_READ_PUBLIC_KEY: u64 = 7;
const KEY_PROFILES: u64 = 8;

/// The fields that the vault config and every snapshot header have (format.md 7.2.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultEssentials {
    /// The format version of the vault.
    pub format_version: u32,
    /// The vault ID.
    pub vault_id: VaultId,
    /// The name of the AEAD algorithm.
    pub encryption: String,
    /// The name of the hash algorithm.
    pub hash: String,
    /// The name of the key encapsulation algorithm.
    pub key_encapsulation: String,
    /// The public part of the read key.
    pub read_public_key: Vec<u8>,
}

impl VaultEssentials {
    /// The fields with the numbers of the vault config map, in ascending order.
    pub(crate) fn fields(&self) -> Vec<(u64, Vec<u8>)> {
        alloc::vec![
            (
                KEY_FORMAT_VERSION,
                write_u64(u64::from(self.format_version))
            ),
            (KEY_VAULT_ID, write_bytes(self.vault_id.as_bytes())),
            (KEY_ENCRYPTION, write_text(&self.encryption)),
            (KEY_HASH, write_text(&self.hash)),
            (KEY_KEY_ENCAPSULATION, write_text(&self.key_encapsulation)),
            (KEY_READ_PUBLIC_KEY, write_bytes(&self.read_public_key)),
        ]
    }

    /// The map that a snapshot header contains (format.md 5.9.1).
    pub(crate) fn encode_map(&self) -> Vec<u8> {
        write_map(&self.fields())
    }

    /// Reads the essential fields from the fields of a map. Rejects a format
    /// version that is newer than this code, and an unknown encryption or hash name.
    pub(crate) fn read(fields: &Fields<'_>) -> Result<Self, ObjectError> {
        let format_version = read_u32(fields.require(KEY_FORMAT_VERSION)?, KEY_FORMAT_VERSION)?;
        if format_version > FORMAT_VERSION {
            return Err(ObjectError::NewerFormat(format_version));
        }
        let encryption = read_text(fields.require(KEY_ENCRYPTION)?, KEY_ENCRYPTION)?;
        let hash = read_text(fields.require(KEY_HASH)?, KEY_HASH)?;
        if encryption != ENCRYPTION_XCHACHA20_POLY1305 || hash != HASH_BLAKE3 {
            return Err(ObjectError::UnknownAlgorithm);
        }
        Ok(Self {
            format_version,
            vault_id: VaultId::from_bytes(read_array(fields.require(KEY_VAULT_ID)?, KEY_VAULT_ID)?),
            encryption,
            hash,
            key_encapsulation: read_text(
                fields.require(KEY_KEY_ENCAPSULATION)?,
                KEY_KEY_ENCAPSULATION,
            )?,
            read_public_key: read_bytes(fields.require(KEY_READ_PUBLIC_KEY)?, KEY_READ_PUBLIC_KEY)?,
        })
    }

    /// Reads the map of a snapshot header.
    pub(crate) fn decode_map(raw: &[u8], key: u64) -> Result<Self, ObjectError> {
        Self::read(&Fields::of_map(raw, key)?)
    }
}

/// One chunking profile (format.md 5.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkingProfile {
    /// The ID of the profile. It is not 0.
    pub id: u32,
    /// The name of the chunking algorithm.
    pub algorithm: String,
    /// The minimum size of a chunk, in bytes.
    pub min_size: u32,
    /// The average size of a chunk, in bytes.
    pub avg_size: u32,
    /// The maximum size of a chunk, in bytes.
    pub max_size: u32,
}

/// The vault config (format.md 7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultConfig {
    /// The essential fields.
    pub essentials: VaultEssentials,
    /// The config sequence. It is 1 when NilPerit creates the vault.
    pub sequence: u64,
    /// The table of chunking profiles. Only new profiles are added at the end
    /// (format.md 5.2.2).
    pub chunking_profiles: Vec<ChunkingProfile>,
}

impl VaultConfig {
    /// Encodes the map of the vault config. The MAC is not part of it.
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        self.check()?;
        let profiles: Vec<Vec<u8>> = self
            .chunking_profiles
            .iter()
            .map(|p| {
                write_array(&[
                    write_u64(u64::from(p.id)),
                    write_text(&p.algorithm),
                    write_u64(u64::from(p.min_size)),
                    write_u64(u64::from(p.avg_size)),
                    write_u64(u64::from(p.max_size)),
                ])
            })
            .collect();
        let mut fields = self.essentials.fields();
        fields.push((KEY_SEQUENCE, write_u64(self.sequence)));
        fields.sort_by_key(|(key, _)| *key);
        fields.push((KEY_PROFILES, write_array(&profiles)));
        let bytes = write_map(&fields);
        if bytes.len() + MAC_SIZE > MAX_CONFIG_SIZE {
            return Err(ObjectError::Rule("config is larger than the limit"));
        }
        Ok(bytes)
    }

    /// Decodes the map of a vault config. `map` is the config file without its MAC.
    ///
    /// Ignores unknown keys (format.md 4.5). Rejects a format version that is
    /// newer than this code.
    pub fn decode(map: &[u8]) -> Result<Self, ObjectError> {
        canonical::check(map).map_err(|e| ObjectError::Envelope(EnvelopeError::NotCanonical(e)))?;
        let fields = Fields::of_map(map, 0)?;
        let essentials = VaultEssentials::read(&fields)?;
        let sequence = read_u64(fields.require(KEY_SEQUENCE)?, KEY_SEQUENCE)?;
        let chunking_profiles = read_profiles(fields.require(KEY_PROFILES)?)?;
        let config = Self {
            essentials,
            sequence,
            chunking_profiles,
        };
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<(), ObjectError> {
        if self.sequence == 0 {
            return Err(ObjectError::Rule("config sequence is 0"));
        }
        let mut ids: Vec<u32> = self.chunking_profiles.iter().map(|p| p.id).collect();
        if ids.contains(&0) {
            return Err(ObjectError::Rule("chunking profile ID 0 is not used"));
        }
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(ObjectError::Rule("chunking profile ID occurs twice"));
        }
        Ok(())
    }
}

fn read_profiles(raw: &[u8]) -> Result<Vec<ChunkingProfile>, ObjectError> {
    let bad = |_| ObjectError::BadField(KEY_PROFILES);
    let mut d = minicbor::Decoder::new(raw);
    let count = d
        .array()
        .map_err(bad)?
        .ok_or(ObjectError::BadField(KEY_PROFILES))?;
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(raw.len()));
    for _ in 0..count {
        if d.array().map_err(bad)? != Some(5) {
            return Err(ObjectError::BadField(KEY_PROFILES));
        }
        out.push(ChunkingProfile {
            id: d.u32().map_err(bad)?,
            algorithm: String::from(d.str().map_err(bad)?),
            min_size: d.u32().map_err(bad)?,
            avg_size: d.u32().map_err(bad)?,
            max_size: d.u32().map_err(bad)?,
        });
    }
    Ok(out)
}

/// Splits a config file into the map and the MAC (format.md 7.2.1).
pub fn split_config_file(file: &[u8]) -> Result<(&[u8], [u8; MAC_SIZE]), ObjectError> {
    if file.len() > MAX_CONFIG_SIZE {
        return Err(ObjectError::Rule("config is larger than the limit"));
    }
    if file.len() <= MAC_SIZE {
        return Err(ObjectError::Rule("config is too short"));
    }
    let (map, mac) = file.split_at(file.len() - MAC_SIZE);
    let mut out = [0u8; MAC_SIZE];
    out.copy_from_slice(mac);
    Ok((map, out))
}

/// Joins the map and the MAC into the bytes of a config file.
pub fn join_config_file(map: &[u8], mac: &[u8; MAC_SIZE]) -> Result<Vec<u8>, ObjectError> {
    if map.len() + MAC_SIZE > MAX_CONFIG_SIZE {
        return Err(ObjectError::Rule("config is larger than the limit"));
    }
    let mut out = Vec::with_capacity(map.len() + MAC_SIZE);
    out.extend_from_slice(map);
    out.extend_from_slice(mac);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn essentials() -> VaultEssentials {
        VaultEssentials {
            format_version: 0,
            vault_id: VaultId::from_bytes([0x11; 16]),
            encryption: String::from("xchacha20-poly1305"),
            hash: String::from("blake3"),
            key_encapsulation: String::from("x-wing-draft-06"),
            read_public_key: vec![9; 1216],
        }
    }

    fn profile(id: u32) -> ChunkingProfile {
        ChunkingProfile {
            id,
            algorithm: String::from("fastcdc-2020"),
            min_size: 1,
            avg_size: 2,
            max_size: 3,
        }
    }

    fn config() -> VaultConfig {
        VaultConfig {
            essentials: essentials(),
            sequence: 3,
            chunking_profiles: vec![profile(1), profile(2), profile(40)],
        }
    }

    // A raw config map with the given sequence and profile table.
    fn raw_map(essentials: &VaultEssentials, sequence: u64, profiles: &[Vec<u8>]) -> Vec<u8> {
        let mut fields = essentials.fields();
        fields.push((KEY_SEQUENCE, write_u64(sequence)));
        fields.sort_by_key(|(k, _)| *k);
        fields.push((KEY_PROFILES, write_array(profiles)));
        write_map(&fields)
    }

    fn raw_profile(id: u64) -> Vec<u8> {
        write_array(&[
            write_u64(id),
            write_text("none"),
            write_u64(0),
            write_u64(0),
            write_u64(10),
        ])
    }

    #[test]
    fn round_trip() {
        let bytes = config().encode().unwrap();
        assert_eq!(VaultConfig::decode(&bytes).unwrap(), config());
        let empty = VaultConfig {
            chunking_profiles: Vec::new(),
            ..config()
        };
        assert_eq!(
            VaultConfig::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
        // A real read public key of 1216 bytes fits easily.
        assert!(bytes.len() < 1500);
    }

    #[test]
    fn encode_rejects_a_sequence_of_zero_and_bad_profile_ids() {
        let rule = |c: VaultConfig| matches!(c.encode(), Err(ObjectError::Rule(_)));
        assert!(rule(VaultConfig {
            sequence: 0,
            ..config()
        }));
        assert!(rule(VaultConfig {
            chunking_profiles: vec![profile(0)],
            ..config()
        }));
        assert!(rule(VaultConfig {
            chunking_profiles: vec![profile(2), profile(2)],
            ..config()
        }));
    }

    #[test]
    fn decode_rejects_a_sequence_of_zero_and_bad_profile_ids() {
        let rule = |map: Vec<u8>| matches!(VaultConfig::decode(&map), Err(ObjectError::Rule(_)));
        assert!(!rule(raw_map(&essentials(), 1, &[raw_profile(1)])));
        assert!(rule(raw_map(&essentials(), 0, &[raw_profile(1)])));
        assert!(rule(raw_map(&essentials(), 1, &[raw_profile(0)])));
        assert!(rule(raw_map(
            &essentials(),
            1,
            &[raw_profile(5), raw_profile(5)]
        )));
    }

    #[test]
    fn decode_rejects_a_newer_version_and_unknown_algorithms() {
        let mut newer = essentials();
        newer.format_version = 1;
        assert_eq!(
            VaultConfig::decode(&raw_map(&newer, 1, &[])),
            Err(ObjectError::NewerFormat(1))
        );
        let mut aead = essentials();
        aead.encryption = String::from("aes-gcm");
        assert_eq!(
            VaultConfig::decode(&raw_map(&aead, 1, &[])),
            Err(ObjectError::UnknownAlgorithm)
        );
        let mut hash = essentials();
        hash.hash = String::from("sha256");
        assert_eq!(
            VaultConfig::decode(&raw_map(&hash, 1, &[])),
            Err(ObjectError::UnknownAlgorithm)
        );
        // The name of the key encapsulation algorithm is not checked here: the reader
        // checks it when it opens a seal (format.md 3.3.2.3).
        let mut kem = essentials();
        kem.key_encapsulation = String::from("something-else");
        assert!(VaultConfig::decode(&raw_map(&kem, 1, &[])).is_ok());
    }

    #[test]
    fn decode_rejects_bad_maps_and_missing_fields() {
        // Not deterministic CBOR: keys out of order, trailing bytes.
        assert!(matches!(
            VaultConfig::decode(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
            Err(ObjectError::Envelope(EnvelopeError::NotCanonical(_)))
        ));
        let mut trailing = config().encode().unwrap();
        trailing.push(0);
        assert!(matches!(
            VaultConfig::decode(&trailing),
            Err(ObjectError::Envelope(EnvelopeError::NotCanonical(_)))
        ));
        // Not a map.
        assert_eq!(VaultConfig::decode(&[0x80]), Err(ObjectError::BadField(0)));
        // A missing field (no profile table).
        let mut fields = essentials().fields();
        fields.push((KEY_SEQUENCE, write_u64(1)));
        fields.sort_by_key(|(k, _)| *k);
        assert_eq!(
            VaultConfig::decode(&write_map(&fields)),
            Err(ObjectError::MissingField(KEY_PROFILES))
        );
        // A profile with 4 items, and a size that does not fit in 32 bits.
        let four = write_array(&[write_array(&[
            write_u64(1),
            write_text("a"),
            write_u64(0),
            write_u64(0),
        ])]);
        assert_eq!(
            VaultConfig::decode(&raw_map(&essentials(), 1, &[four])),
            Err(ObjectError::BadField(KEY_PROFILES))
        );
        let big = write_array(&[
            write_u64(1),
            write_text("a"),
            write_u64(0),
            write_u64(0),
            write_u64(1 << 32),
        ]);
        assert_eq!(
            VaultConfig::decode(&raw_map(&essentials(), 1, &[big])),
            Err(ObjectError::BadField(KEY_PROFILES))
        );
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let mut fields = essentials().fields();
        fields.push((KEY_SEQUENCE, write_u64(1)));
        fields.sort_by_key(|(k, _)| *k);
        fields.push((KEY_PROFILES, write_array(&[])));
        fields.push((99, write_text("future")));
        assert!(VaultConfig::decode(&write_map(&fields)).is_ok());
    }

    #[test]
    fn config_file_split_and_join() {
        let map = config().encode().unwrap();
        let mac = [0xab; MAC_SIZE];
        let file = join_config_file(&map, &mac).unwrap();
        let (split_map, split_mac) = split_config_file(&file).unwrap();
        assert_eq!(split_map, map);
        assert_eq!(split_mac, mac);

        // Too short: the MAC alone, or less.
        assert!(split_config_file(&[]).is_err());
        assert!(split_config_file(&[0; MAC_SIZE]).is_err());
        assert!(split_config_file(&[0; MAC_SIZE + 1]).is_ok());
        // The limit of 1 MiB.
        assert!(split_config_file(&vec![0; MAX_CONFIG_SIZE]).is_ok());
        assert!(split_config_file(&vec![0; MAX_CONFIG_SIZE + 1]).is_err());
        assert!(join_config_file(&vec![0; MAX_CONFIG_SIZE - MAC_SIZE + 1], &mac).is_err());
    }
}
