//! `sumidero status` — daemon health from the heartbeat row.

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use serde_json::{Value, json};

use super::{load_config, open_db, unix_now};
use crate::output::{emit_code, fail};

/// Human-readable lines for a running daemon: identity, then one line
/// per upstream, then the drop warning when the log is lossy.
fn running_text(
    hb: &sumidero_core::db::Heartbeat,
    age: i64,
    pool: &Value,
    upstreams: &Value,
    dropped: &Value,
    dropped_recent: &Value,
) -> String {
    let mut text = format!(
        "running: pid {} (heartbeat {age}s ago)\nconfig {}\nlists  {}",
        hb.pid, hb.config_hash, hb.lists_hash
    );
    if let Some(list) = upstreams.as_array() {
        for entry in list {
            // Not "DOWN": connections are rebuilt lazily on the next
            // query, so a disconnected slot is normal on a healthy
            // upstream. What matters is when it last answered.
            let last = entry["last_success_secs_ago"].as_u64().map_or_else(
                || "never answered".to_owned(),
                |s| format!("last answer {s}s ago"),
            );
            let _ = write!(
                text,
                "\nupstream {} ({last}, {} queries, {} failures, {} reconnects)",
                entry["url"].as_str().unwrap_or("?"),
                entry["queries"],
                entry["failures"],
                entry["reconnects"],
            );
        }
    }
    if let Some(stuck) = pool["consecutive_all_failed"].as_u64()
        && stuck > 0
    {
        let _ = write!(
            text,
            "\nERROR: every upstream is failing ({stuck} consecutive queries unanswered)"
        );
    }
    if let Some(count) = dropped_recent.as_u64()
        && count > 0
    {
        let _ = write!(
            text,
            "\nWARNING: {count} query-log events dropped since the last sample"
        );
    } else if let Some(total) = dropped.as_u64()
        && total > 0
    {
        // Historical, not current: worth seeing, not worth alerting on.
        let _ = write!(text, "\nnote: {total} query-log events dropped since start");
    }
    text
}

pub fn run(config: &Path, json: bool) -> ExitCode {
    let cfg = match load_config(config) {
        Ok(c) => c,
        Err(e) => return fail(json, "status", &e, 1),
    };
    let db = match open_db(&cfg) {
        Ok(d) => d,
        Err(e) => return fail(json, "status", &e, 1),
    };
    let hb = match db.heartbeat() {
        Ok(hb) => hb,
        Err(e) => return fail(json, "status", &e.to_string(), 1),
    };

    // Runtime counters the daemon publishes next to the heartbeat. A
    // daemon from before this existed has no row; that is reported as
    // unknown rather than as healthy.
    let stats = match db.daemon_stats() {
        Ok(s) => s,
        Err(e) => return fail(json, "status", &e.to_string(), 1),
    };
    let pool: Value = stats.as_ref().map_or(Value::Null, |s| {
        serde_json::from_str(&s.upstreams_json).unwrap_or(Value::Null)
    });
    let upstreams: Value = pool["upstreams"].clone();
    let dropped: Value = stats
        .as_ref()
        .map_or(Value::Null, |s| json!(s.log_events_dropped));
    // Alert on what is being lost now. The lifetime total never goes
    // back down, so keying `degraded` off it would pin the daemon
    // degraded forever after a single transient queue-full spike.
    let dropped_recent: Value = stats
        .as_ref()
        .map_or(Value::Null, |s| json!(s.log_events_dropped_recent));
    // A daemon is degraded when it cannot resolve — not when one of
    // three raced upstreams is between connections.
    let cannot_resolve = pool["consecutive_all_failed"]
        .as_u64()
        .is_some_and(|stuck| stuck > 0);

    let now = unix_now();
    match hb {
        Some(hb) => {
            let age = now - hb.updated_ts;
            let running = age <= crate::HEARTBEAT_FRESH_SECS;
            // "Running" is not the same as "working": a daemon with every
            // upstream down still heartbeats happily.
            let degraded =
                running && (cannot_resolve || dropped_recent.as_u64().is_some_and(|d| d > 0));
            let payload = json!({
                "running": running,
                "degraded": degraded,
                "pid": hb.pid,
                "started_ts": hb.started_ts,
                "updated_ts": hb.updated_ts,
                "heartbeat_age_secs": age,
                "config_hash": hb.config_hash,
                "lists_hash": hb.lists_hash,
                "log_events_dropped": dropped,
                "log_events_dropped_recent": dropped_recent,
                "upstreams": upstreams,
                "queries_resolved": pool["resolved"],
                "queries_all_upstreams_failed": pool["all_failed_total"],
                "consecutive_all_upstreams_failed": pool["consecutive_all_failed"],
            });
            let human = if running {
                running_text(&hb, age, &pool, &upstreams, &dropped, &dropped_recent)
            } else {
                format!(
                    "NOT running: last heartbeat {age}s ago (pid was {})",
                    hb.pid
                )
            };
            let code = match (running, degraded) {
                (true, false) => ExitCode::SUCCESS,
                // Distinct from 5 ("not running") so a cron alert can tell
                // "dead" from "alive but not resolving". 6 is already taken
                // by init/migrate's refuse-to-overwrite in the CLI contract.
                (true, true) => ExitCode::from(7),
                (false, _) => ExitCode::from(5),
            };
            emit_code(json, "status", payload, &human, code)
        }
        // Same field set as the heartbeat branch (nulls), so the v1 shape
        // is stable for agents regardless of daemon state.
        None => emit_code(
            json,
            "status",
            json!({
                "running": false,
                "degraded": false,
                "pid": Value::Null,
                "started_ts": Value::Null,
                "updated_ts": Value::Null,
                "heartbeat_age_secs": Value::Null,
                "config_hash": Value::Null,
                "lists_hash": Value::Null,
                "log_events_dropped": Value::Null,
                "log_events_dropped_recent": Value::Null,
                "upstreams": Value::Null,
                "queries_resolved": Value::Null,
                "queries_all_upstreams_failed": Value::Null,
                "consecutive_all_upstreams_failed": Value::Null,
            }),
            "NOT running: no heartbeat recorded",
            ExitCode::from(5),
        ),
    }
}
