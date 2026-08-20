//! `sumidero check` — validate config + blocklist loadability (offline).

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::load_config;
use crate::output::{emit, fail};

/// Validate without touching the network: config semantics plus every
/// effective list resolvable from disk (stored copy or local path).
/// This is the gate `reload` runs before signalling the daemon.
pub(crate) fn validate(config: &Path) -> Result<CheckReport, String> {
    let cfg = load_config(config)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let loaded = runtime
        .block_on(sumidero_core::lists::load(
            &cfg.effective_lists(),
            &cfg.filtering.list_dir,
            true,
        ))
        .map_err(|e| e.to_string())?;
    Ok(CheckReport {
        lists: loaded.names,
        rule_counts: loaded.rule_counts,
        issues: loaded.issues.len(),
        lists_hash: loaded.hash,
        config_hash: cfg.hash(),
    })
}

pub(crate) struct CheckReport {
    pub lists: Vec<String>,
    pub rule_counts: Vec<usize>,
    pub issues: usize,
    pub lists_hash: String,
    pub config_hash: String,
}

pub fn run(config: &Path, json: bool) -> ExitCode {
    match validate(config) {
        Ok(report) => {
            let total: usize = report.rule_counts.iter().sum();
            let payload = json!({
                "valid": true,
                "lists": report.lists,
                "rule_counts": report.rule_counts,
                "total_rules": total,
                "parse_issues": report.issues,
                "lists_hash": report.lists_hash,
                "config_hash": report.config_hash,
            });
            let human = format!(
                "config OK: {} lists, {total} rules, {} parse issues",
                report.lists.len(),
                report.issues
            );
            emit(json, "check", payload, &human)
        }
        Err(e) => fail(json, "check", &e, 1),
    }
}
