//! JSON envelope + error/exit plumbing shared by every command.

use std::process::ExitCode;

use serde_json::{Value, json};

/// Print a success payload. With `--json` the payload is wrapped in the
/// versioned envelope; otherwise `human` (already formatted) is printed.
pub fn emit(json_mode: bool, command: &str, payload: Value, human: &str) -> ExitCode {
    emit_code(json_mode, command, payload, human, ExitCode::SUCCESS)
}

/// Like [`emit`] with an explicit exit code (for semantic non-zero codes
/// that still carry a normal payload, e.g. `explain` on a blocked name).
pub fn emit_code(
    json_mode: bool,
    command: &str,
    mut payload: Value,
    human: &str,
    code: ExitCode,
) -> ExitCode {
    if json_mode {
        let obj = payload
            .as_object_mut()
            .expect("payload must be a JSON object");
        obj.insert("schema".into(), crate::SCHEMA.into());
        obj.insert("command".into(), command.into());
        println!("{payload}");
    } else if !human.is_empty() {
        println!("{human}");
    }
    code
}

/// Print an error and return its exit code. With `--json` the error goes
/// to stdout in the envelope; otherwise to stderr.
pub fn fail(json_mode: bool, command: &str, message: &str, code: u8) -> ExitCode {
    if json_mode {
        let payload = json!({
            "schema": crate::SCHEMA,
            "command": command,
            "error": message,
        });
        println!("{payload}");
    } else {
        eprintln!("error: {message}");
    }
    ExitCode::from(code)
}
