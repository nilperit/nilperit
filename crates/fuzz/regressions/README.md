# Inputs that a fuzzer found

A folder for each check, with one file for each input that made it fail. The input is the raw
bytes that the fuzzer saved. The test `the_inputs_that_a_fuzzer_found_pass_the_checks` runs every
file here through its check, on every system, so a problem that was fixed stays fixed.

To keep a finding:

1. Download the artifact of the failed run of the workflow `Fuzz`, or take the file from
   `fuzz/artifacts/<check>/` after a local run.
2. Run it: `cd fuzz && cargo fuzz run <check> artifacts/<check>/<file>`.
3. Fix the code.
4. Copy the file to `crates/fuzz/regressions/<check>/` (a short, clear name), and run
   `cargo test -p nilperit-fuzz`.

Do not put anything here that is not an input that failed once.
