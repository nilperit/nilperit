#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| nilperit_fuzz::checks::snapshot_header(data));
