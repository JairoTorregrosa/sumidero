//! `sumidero log` — recent query log entries, newest first.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use sumidero_core::db::{ResponseSource, VerdictKind};

use super::{load_config, open_db};
use crate::output::{emit, fail};

pub(crate) fn verdict_str(v: VerdictKind) -> &'static str {
    match v {
        VerdictKind::Allowed => "allowed",
        VerdictKind::Blocked => "blocked",
        VerdictKind::Excepted => "excepted",
    }
}

pub(crate) fn source_str(s: ResponseSource) -> &'static str {
    match s {
        ResponseSource::Synth => "synth",
        ResponseSource::Cache => "cache",
        ResponseSource::Stale => "stale",
        ResponseSource::Upstream => "upstream",
        ResponseSource::Failed => "failed",
    }
}

pub fn run(config: &Path, json: bool, limit: u32) -> ExitCode {
    let cfg = match load_config(config) {
        Ok(c) => c,
        Err(e) => return fail(json, "log", &e, 1),
    };
    let db = match open_db(&cfg) {
        Ok(d) => d,
        Err(e) => return fail(json, "log", &e, 1),
    };
    let rows = match db.recent_queries(limit) {
        Ok(r) => r,
        Err(e) => return fail(json, "log", &e.to_string(), 1),
    };

    let entries: Vec<_> = rows
        .iter()
        .map(|r| {
            json!({
                "ts": r.ts,
                "client": r.client.to_string(),
                "qname": r.qname,
                "qtype": r.qtype,
                "verdict": verdict_str(r.verdict),
                "rule": r.rule,
                "list": r.list,
                "source": source_str(r.source),
                "rcode": r.rcode,
                "duration_us": r.duration_us,
            })
        })
        .collect();
    let human = rows
        .iter()
        .map(|r| {
            format!(
                "{} {} {} {} ({}, rcode {})",
                r.ts,
                r.client,
                r.qname,
                verdict_str(r.verdict),
                source_str(r.source),
                r.rcode
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    emit(json, "log", json!({ "entries": entries }), &human)
}
