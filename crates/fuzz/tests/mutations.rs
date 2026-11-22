//! The mutation tests: every check runs on its seeds, and on many changes of its seeds.
//!
//! The random generator is fixed, so a failure is the same on every system and can be run
//! again. The number of changes for each seed is 3000 by default, and can be set with the
//! variable `NILPERIT_MUTATIONS` (for example to run a long time before a release).

use nilperit_fuzz::checks::{Check, TARGETS};
use nilperit_fuzz::fixtures_for_tests::unhex;
use nilperit_fuzz::mutate::{Rng, mutate};
use nilperit_fuzz::seeds::{A8_PACK, A8_TABLE, a8_pack_from_seed, seeds};

fn budget() -> u64 {
    std::env::var("NILPERIT_MUTATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3000)
}

fn check_of(name: &str) -> Check {
    TARGETS
        .iter()
        .find(|(target, _)| *target == name)
        .unwrap_or_else(|| panic!("no check named {name}"))
        .1
}

/// Runs a check on the seeds of its name, and on changes of them.
fn mutated(name: &str) {
    let check = check_of(name);
    let seeds = seeds(name);
    assert!(!seeds.is_empty(), "{name} has no seeds");
    for seed in &seeds {
        check(seed);
    }
    // Each target has its own sequence: the same name gives the same inputs.
    let mut rng = Rng::new(name.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    }));
    for seed in &seeds {
        for round in 0..budget() {
            let input = mutate(&mut rng, seed, &seeds);
            // Name the input in the message of a failure: this is what to run again.
            let result = std::panic::catch_unwind(|| check(&input));
            if let Err(panic) = result {
                eprintln!(
                    "{name} failed on round {round} for this input:\n{}",
                    hex(&input)
                );
                std::panic::resume_unwind(panic);
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

macro_rules! mutation_tests {
    ($($name:ident),* $(,)?) => {$(
        #[test]
        fn $name() {
            mutated(stringify!($name));
        }
    )*};
}

mutation_tests!(
    canonical,
    envelope,
    content_object,
    item_record,
    delta_entry,
    snapshot_header,
    vault_config,
    lock_file,
    object_table,
    pack_parts,
    pack_with_table,
    pack_with_object,
    encryption,
    chunker,
);

#[test]
fn every_check_has_a_test_and_seeds() {
    // The macro above names each check once. A new check without a test fails here.
    let tested = [
        "canonical",
        "envelope",
        "content_object",
        "item_record",
        "delta_entry",
        "snapshot_header",
        "vault_config",
        "lock_file",
        "object_table",
        "pack_parts",
        "pack_with_table",
        "pack_with_object",
        "encryption",
        "chunker",
    ];
    let named: Vec<&str> = TARGETS.iter().map(|(name, _)| *name).collect();
    assert_eq!(named, tested);
    for name in named {
        assert!(!seeds(name).is_empty(), "{name}");
    }
}

#[test]
fn the_pack_of_the_seed_is_the_pack_of_appendix_a8() {
    // The checks make the pack of A.8 byte for byte from its parts. The vector was made
    // with other software, so this shows that the seed is real and not our own invention.
    assert_eq!(a8_pack_from_seed(), unhex(A8_PACK));
}

#[test]
fn the_hexadecimal_text_of_the_seeds_is_in_the_format_document() {
    let document = include_str!("../../../docs/format.md");
    assert!(document.contains(A8_PACK), "A.8.5 is not in format.md");
    assert!(document.contains(A8_TABLE), "A.8.3 is not in format.md");
}

#[test]
fn the_seeds_are_accepted_by_the_decoders_that_they_are_for() {
    use nilperit_format::{
        ContentObject, DeltaEntry, Envelope, ItemRecord, LockFile, ObjectTable, SnapshotHeader,
        VaultConfig,
    };
    for (name, accepted) in [
        (
            "content_object",
            all(seeds("content_object"), |s| {
                ContentObject::decode(s).is_ok()
            }),
        ),
        (
            "item_record",
            all(seeds("item_record"), |s| ItemRecord::decode(s).is_ok()),
        ),
        (
            "delta_entry",
            all(seeds("delta_entry"), |s| DeltaEntry::decode(s).is_ok()),
        ),
        (
            "snapshot_header",
            all(seeds("snapshot_header"), |s| {
                SnapshotHeader::decode(s).is_ok()
            }),
        ),
        (
            "lock_file",
            all(seeds("lock_file"), |s| LockFile::decode(s).is_ok()),
        ),
        (
            "object_table",
            all(seeds("object_table"), |s| ObjectTable::decode(s).is_ok()),
        ),
        (
            "envelope",
            all(seeds("envelope"), |s| Envelope::decode(s).is_ok()),
        ),
    ] {
        assert!(accepted, "a seed of {name} is not valid input");
    }
    // The first seed of a config is a map, the second is the file with a MAC.
    assert!(VaultConfig::decode(&seeds("vault_config")[0]).is_ok());
}

fn all(seeds: Vec<Vec<u8>>, accepts: impl Fn(&[u8]) -> bool) -> bool {
    seeds.iter().all(|seed| accepts(seed))
}
