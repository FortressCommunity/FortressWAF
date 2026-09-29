//! `healthcheck` — an HTTP readiness probe for a FortressWAF listener.
//!
//! Port of `cmd/healthcheck/main.go`. Exit 0 when the endpoint answers 2xx, 1
//! otherwise, 2 on usage error.

use std::process::exit;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: healthcheck <url>");
        exit(2);
    }
    let target = &args[1];

    let resp = match ureq::get(target).timeout(Duration::from_secs(3)).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            eprintln!("healthcheck {target}: unexpected status {code}");
            exit(1);
        }
        Err(e) => {
            eprintln!("healthcheck {target}: {e}");
            exit(1);
        }
    };

    // Drain the body so the connection can be reused, matching the Go version.
    let _ = resp.into_string();

    // ureq returns Ok only for 2xx by default; a non-2xx arrives as
    // Error::Status above. Reaching here means success.
}
