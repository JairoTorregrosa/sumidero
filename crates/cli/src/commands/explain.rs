//! `sumidero explain <domain>` — evaluate one name against the lists.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use sumidero_filter::Verdict;

use super::{load_config, open_db};
use crate::output::{emit_code, fail};

/// Cheap syntactic sanity check so garbage input errors instead of
/// reading as a confident "no-match".
fn plausible_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 254
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*'))
}

pub fn run(config: &Path, json: bool, domain: &str) -> ExitCode {
    if !plausible_domain(domain) {
        return fail(
            json,
            "explain",
            &format!("{domain:?} is not a plausible DNS name"),
            2,
        );
    }
    let cfg = match load_config(config) {
        Ok(c) => c,
        Err(e) => return fail(json, "explain", &e, 1),
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return fail(json, "explain", &e.to_string(), 1),
    };
    let loaded = match runtime.block_on(sumidero_core::lists::load(
        &cfg.effective_lists(),
        &cfg.filtering.list_dir,
        true,
    )) {
        Ok(l) => l,
        Err(e) => return fail(json, "explain", &e.to_string(), 1),
    };

    // Compare our list hash against the running daemon's, so a verdict
    // computed from newer/older disk copies is flagged as such.
    let daemon_hash: Option<String> = open_db(&cfg)
        .ok()
        .and_then(|db| db.heartbeat().ok().flatten())
        .map(|hb| hb.lists_hash);
    let hash_match = daemon_hash.as_ref().map(|h| *h == loaded.hash);
    let stale_warning = match hash_match {
        Some(true) | None => None,
        Some(false) => Some(
            "list hash differs from the daemon's heartbeat: the daemon may be \
             filtering with a different rule set than this verdict",
        ),
    };

    let (verdict_str, rule, list, code) = match loaded.engine.verdict(domain) {
        Verdict::NoMatch => ("no-match", None, None, ExitCode::SUCCESS),
        Verdict::Block { list, rule } => (
            "blocked",
            Some(rule.text.to_string()),
            Some(list),
            ExitCode::from(3),
        ),
        Verdict::Except { list, rule } => (
            "excepted",
            Some(rule.text.to_string()),
            Some(list),
            ExitCode::from(4),
        ),
    };
    let list_name = list.map(|l| loaded.names[l].clone());

    let payload = json!({
        "domain": domain,
        "verdict": verdict_str,
        "rule": rule,
        "list": list_name,
        "lists_hash": loaded.hash,
        "daemon_lists_hash": daemon_hash,
        "hash_match": hash_match,
        "warning": stale_warning,
    });
    let mut human = match (&rule, &list_name) {
        (Some(rule), Some(list)) => format!("{domain}: {verdict_str} by `{rule}` (list {list})"),
        _ => format!("{domain}: {verdict_str}"),
    };
    if let Some(w) = stale_warning {
        human.push_str("\nwarning: ");
        human.push_str(w);
    }
    emit_code(json, "explain", payload, &human, code)
}
