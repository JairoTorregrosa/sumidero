//! `sumidero reload` — validate first, SIGHUP the daemon, report what it did.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::{load_config, open_db, unix_now};
use crate::output::{emit, emit_code, fail};

pub fn run(config: &Path, json: bool, wait_secs: u64) -> ExitCode {
    // Never signal the daemon into a config that does not even parse or
    // validate. Lists are the daemon's job: it downloads new ones and
    // reports the outcome, which this command waits for.
    let cfg = match load_config(config) {
        Ok(c) => c,
        Err(e) => return fail(json, "reload", &e, 1),
    };
    let hb = match open_db(&cfg).and_then(|db| db.heartbeat().map_err(|e| e.to_string())) {
        Ok(Some(hb)) => hb,
        Ok(None) => return fail(json, "reload", "daemon not running (no heartbeat)", 5),
        Err(e) => return fail(json, "reload", &e, 1),
    };
    let age = unix_now() - hb.updated_ts;
    if age > crate::HEARTBEAT_FRESH_SECS {
        return fail(
            json,
            "reload",
            &format!("daemon not running (heartbeat {age}s old)"),
            5,
        );
    }

    let pid = nix::unistd::Pid::from_raw(match i32::try_from(hb.pid) {
        Ok(p) => p,
        Err(_) => return fail(json, "reload", "heartbeat pid out of range", 1),
    });
    let db = match open_db(&cfg) {
        Ok(db) => db,
        Err(e) => return fail(json, "reload", &e, 1),
    };
    let before = last_signal_reload(&db);
    if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGHUP) {
        return fail(json, "reload", &format!("cannot signal pid {pid}: {e}"), 1);
    }
    if wait_secs == 0 {
        return emit(
            json,
            "reload",
            json!({ "signalled_pid": hb.pid, "outcome": null }),
            &format!("reload signalled to pid {}", hb.pid),
        );
    }

    // The daemon writes every reload outcome to daemon_stats as soon as
    // it has one; wait for a signal-triggered outcome newer than ours.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let Some(outcome) = last_signal_reload(&db) else {
            continue;
        };
        if Some(&outcome) == before.as_ref() {
            continue;
        }
        let payload = json!({ "signalled_pid": hb.pid, "outcome": outcome });
        return if outcome.ok {
            emit(
                json,
                "reload",
                payload,
                &format!(
                    "reload applied by pid {} in {} ms",
                    hb.pid, outcome.duration_ms
                ),
            )
        } else {
            let why = outcome.error.clone().unwrap_or_default();
            emit_code(
                json,
                "reload",
                payload,
                &format!("reload FAILED, previous lists and policy still in force: {why}"),
                ExitCode::from(1),
            )
        };
    }
    emit_code(
        json,
        "reload",
        json!({ "signalled_pid": hb.pid, "outcome": null }),
        &format!(
            "signalled pid {}, but it reported no outcome within {wait_secs}s; check `sumidero status`",
            hb.pid
        ),
        ExitCode::from(8),
    )
}

/// The newest reload outcome the daemon reported for a signal.
fn last_signal_reload(db: &sumidero_core::db::Db) -> Option<sumidero_core::daemon::ReloadOutcome> {
    let stats = db.daemon_stats().ok()??;
    let runtime: sumidero_core::daemon::RuntimeReport =
        serde_json::from_str(&stats.runtime_json).ok()?;
    runtime
        .last_reload
        .filter(|o| o.trigger == sumidero_core::daemon::Trigger::Signal)
}
