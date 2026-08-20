//! `sumidero serve` — run the daemon in the foreground.

use std::path::Path;
use std::process::ExitCode;

use crate::output::fail;

pub fn run(config: &Path, json: bool, shadow: Option<std::net::SocketAddr>) -> ExitCode {
    // The daemon is the one command with an ongoing life: wire tracing to
    // stderr, honoring RUST_LOG (default info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return fail(json, "serve", &format!("cannot start runtime: {e}"), 1),
    };
    match runtime.block_on(sumidero_core::server::run(config, shadow)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(json, "serve", &e.to_string(), 1),
    }
}
