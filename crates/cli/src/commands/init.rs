//! `sumidero init --profile <p>` — write a commented starter config.

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use sumidero_core::config::Profile;

use crate::output::{emit, fail};

pub fn run(config: &Path, json: bool, profile: &str, out: Option<&Path>, force: bool) -> ExitCode {
    let profile = match profile {
        "minimal" => Profile::Minimal,
        "balanced" => Profile::Balanced,
        "strict" => Profile::Strict,
        other => return fail(json, "init", &format!("unknown profile {other}"), 2),
    };
    let target = out.unwrap_or(config);
    if target.exists() && !force {
        return fail(
            json,
            "init",
            &format!("{} exists; pass --force to overwrite", target.display()),
            6,
        );
    }
    let content = sumidero_core::config::starter_config(profile);
    if let Err(e) = std::fs::write(target, &content) {
        return fail(
            json,
            "init",
            &format!("cannot write {}: {e}", target.display()),
            1,
        );
    }
    emit(
        json,
        "init",
        json!({ "written": target.display().to_string(), "profile": format!("{profile:?}").to_lowercase() }),
        &format!("wrote {}", target.display()),
    )
}
