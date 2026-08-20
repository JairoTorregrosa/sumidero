//! `sumidero reload` — validate first, then SIGHUP the daemon.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::{load_config, open_db, unix_now};
use crate::output::{emit, fail};

pub fn run(config: &Path, json: bool) -> ExitCode {
    // nginx pattern: never signal the daemon into a config it can't load.
    if let Err(e) = super::check::validate(config) {
        return fail(json, "reload", &format!("check failed: {e}"), 1);
    }
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
    if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGHUP) {
        return fail(json, "reload", &format!("cannot signal pid {pid}: {e}"), 1);
    }
    emit(
        json,
        "reload",
        json!({ "signalled_pid": hb.pid }),
        &format!("reload signalled to pid {}", hb.pid),
    )
}
