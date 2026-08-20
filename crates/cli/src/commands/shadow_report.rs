//! `sumidero shadow report` — divergence summary + recent examples.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use std::fmt::Write as _;

use super::{load_config, open_db, unix_now};
use crate::output::{emit, fail};

pub fn run(config: &Path, json: bool, hours: u32, limit: u32) -> ExitCode {
    let cfg = match load_config(config) {
        Ok(c) => c,
        Err(e) => return fail(json, "shadow-report", &e, 1),
    };
    let db = match open_db(&cfg) {
        Ok(d) => d,
        Err(e) => return fail(json, "shadow-report", &e, 1),
    };
    let since = unix_now() - i64::from(hours) * 3600;
    let summary = match db.divergence_summary(since) {
        Ok(s) => s,
        Err(e) => return fail(json, "shadow-report", &e.to_string(), 1),
    };
    let recent = match db.recent_divergences(limit) {
        Ok(r) => r,
        Err(e) => return fail(json, "shadow-report", &e.to_string(), 1),
    };

    let unexpected: u64 = summary
        .iter()
        .filter(|(class, _)| class != "expected")
        .map(|(_, n)| n)
        .sum();
    let payload = json!({
        "window_hours": hours,
        "summary": summary,
        "unexpected": unexpected,
        "recent": recent
            .iter()
            .map(|d| json!({
                "ts": d.ts,
                "qname": d.qname,
                "qtype": d.qtype,
                "ours": d.ours,
                "theirs": d.theirs,
                "class": d.class,
            }))
            .collect::<Vec<_>>(),
    });
    let mut human = format!("divergences in the last {hours}h:");
    if summary.is_empty() {
        human.push_str(" none");
    }
    for (class, n) in &summary {
        let _ = write!(human, "\n  {class}: {n}");
    }
    let _ = write!(human, "\nunexpected total: {unexpected}");
    emit(json, "shadow-report", payload, &human)
}
