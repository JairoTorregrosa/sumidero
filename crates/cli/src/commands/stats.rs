//! `sumidero stats` — aggregates over a time window.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::{load_config, open_db, unix_now};
use crate::output::{emit, fail};

pub fn run(config: &Path, json: bool, hours: u32) -> ExitCode {
    let cfg = match load_config(config) {
        Ok(c) => c,
        Err(e) => return fail(json, "stats", &e, 1),
    };
    let db = match open_db(&cfg) {
        Ok(d) => d,
        Err(e) => return fail(json, "stats", &e, 1),
    };
    let since = unix_now() - i64::from(hours) * 3600;
    let stats = match db.stats(since) {
        Ok(s) => s,
        Err(e) => return fail(json, "stats", &e.to_string(), 1),
    };

    let payload = json!({
        "window_hours": hours,
        "total": stats.total,
        "blocked": stats.blocked,
        "excepted": stats.excepted,
        "cache_hits": stats.cache_hits,
        "upstream_failures": stats.upstream_failures,
        "top_queried": stats.top_queried,
        "top_blocked": stats.top_blocked,
    });
    let human = format!(
        "last {hours}h: {} queries, {} blocked, {} excepted, {} cache hits, {} upstream failures",
        stats.total, stats.blocked, stats.excepted, stats.cache_hits, stats.upstream_failures
    );
    emit(json, "stats", payload, &human)
}
