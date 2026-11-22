//! The `nilperit` program. All the work is in the library, so that the tests can run
//! it without starting a process.

use nilperit_cli::{Environment, run};
use std::process::ExitCode;

fn main() -> ExitCode {
    // Randomness comes from the operating system. If the system cannot give it, the
    // program stops: it never goes on with weak randomness.
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    run(
        std::env::args_os(),
        &Environment::from_process(),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
        &mut rng,
    )
}
