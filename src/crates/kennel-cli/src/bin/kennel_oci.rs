//! `kennel-oci` — the OCI substrate verb sub-binary (W10).
//!
//! Handles: `oci build`, `oci run`, `oci revert`, `oci update`.
//! Installed at `/usr/libexec/kennel/oci`; reached through `kennel oci ...`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match kennel_cli::oci::dispatch(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("kennel: {message}");
            ExitCode::FAILURE
        }
    }
}
