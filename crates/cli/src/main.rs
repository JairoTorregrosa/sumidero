//! `sumidero` — agent-native CLI for the sumidero DNS blocker.
//!
//! Contract (v1): every command supports `--json`, emitting one JSON
//! object on stdout with `"schema": "v1"` and `"command": "<name>"`.
//! Errors with `--json` are `{"schema":"v1","command":…,"error":"…"}` on
//! stdout. Exit codes are semantic and stable:
//!
//! | code | meaning |
//! |------|---------|
//! | 0 | success (for `explain`: name is not blocked) |
//! | 1 | runtime error (bad config, unreadable db, …) |
//! | 2 | usage error (clap) |
//! | 3 | `explain`: name is blocked |
//! | 4 | `explain`: name matches an exception |
//! | 5 | daemon not running or heartbeat stale (`status`, `reload`) |
//! | 6 | refusing to overwrite an existing file (`init`, `migrate`) |
//! | 7 | `status`: daemon running but degraded (cannot resolve, or dropping log events) |

mod commands;
mod output;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

pub(crate) const SCHEMA: &str = "v1";
/// Heartbeat older than this counts as "daemon not running".
pub(crate) const HEARTBEAT_FRESH_SECS: i64 = 150;

#[derive(Parser)]
#[command(
    name = "sumidero",
    version,
    about = "DNS blocker with an agent-native CLI"
)]
struct Cli {
    /// Path to the TOML config file.
    #[arg(long, global = true, default_value = "/etc/sumidero/config.toml")]
    config: PathBuf,
    /// Emit machine-readable JSON (schema v1) instead of human text.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum ShadowCommand {
    /// Summarize and list recorded divergences.
    Report {
        /// Window in hours to summarize.
        #[arg(long, default_value_t = 48)]
        hours: u32,
        /// Maximum individual divergences to list, newest first.
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Run the DNS daemon (foreground).
    Serve {
        /// Shadow mode: also mirror every query to this reference
        /// resolver (ip:port, plain DNS) and record divergences.
        #[arg(long)]
        shadow: Option<std::net::SocketAddr>,
    },
    /// Daemon health from the database heartbeat.
    Status,
    /// Recent query log entries.
    Log {
        /// Maximum entries to show, newest first.
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Aggregate statistics.
    Stats {
        /// Window in hours to aggregate over.
        #[arg(long, default_value_t = 24)]
        hours: u32,
    },
    /// Evaluate one domain against the configured blocklists.
    Explain {
        /// Domain name to evaluate.
        domain: String,
    },
    /// Validate the config file and the loadability of its blocklists.
    Check,
    /// Validate config, then signal the running daemon to reload (SIGHUP).
    Reload,
    /// Write a commented starter config.
    Init {
        /// Filtering profile for the starter config.
        #[arg(long, value_parser = ["minimal", "balanced", "strict"])]
        profile: String,
        /// Output path (defaults to the global --config path).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Shadow-mode divergence report.
    #[command(subcommand)]
    Shadow(ShadowCommand),
    /// One-shot conversion of an `AdGuard Home` YAML config.
    Migrate {
        /// Path to AdGuardHome.yaml.
        input: PathBuf,
        /// Output path for the generated TOML (defaults to --config path).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite an existing output file.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    // clap prints usage errors as human text; the --json contract still
    // requires one JSON object on stdout, so wrap exit-code-2 errors.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = e.exit_code();
            if code == 2 && std::env::args().any(|a| a == "--json") {
                let payload = serde_json::json!({
                    "schema": SCHEMA,
                    "command": "usage",
                    "error": e.to_string(),
                });
                println!("{payload}");
            } else {
                // help/version (code 0) and human-mode errors print as usual.
                let _ = e.print();
            }
            return ExitCode::from(u8::try_from(code).unwrap_or(2));
        }
    };
    let json = cli.json;
    let config = cli.config;
    match cli.command {
        Command::Serve { shadow } => commands::serve::run(&config, json, shadow),
        Command::Status => commands::status::run(&config, json),
        Command::Log { limit } => commands::log::run(&config, json, limit),
        Command::Stats { hours } => commands::stats::run(&config, json, hours),
        Command::Explain { domain } => commands::explain::run(&config, json, &domain),
        Command::Check => commands::check::run(&config, json),
        Command::Reload => commands::reload::run(&config, json),
        Command::Init {
            profile,
            out,
            force,
        } => commands::init::run(&config, json, &profile, out.as_deref(), force),
        Command::Shadow(ShadowCommand::Report { hours, limit }) => {
            commands::shadow_report::run(&config, json, hours, limit)
        }
        Command::Migrate { input, out, force } => {
            commands::migrate::run(&config, json, &input, out.as_deref(), force)
        }
    }
}
