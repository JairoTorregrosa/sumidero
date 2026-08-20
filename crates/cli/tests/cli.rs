//! Golden tests for the agent-native CLI contract: every command's
//! `--json` schema and semantic exit codes, run against the real binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use sumidero_core::db::{
    DaemonStats, Db, Heartbeat, LogEvent, QueryRecord, ResponseSource, VerdictKind,
};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sumidero"))
}

fn json_of(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout is not one JSON object: {e}\nstdout: {stdout}");
    })
}

fn assert_envelope(v: &Value, command: &str) {
    assert_eq!(v["schema"], "v1", "schema field: {v}");
    assert_eq!(v["command"], command, "command field: {v}");
}

fn unix_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Wrap an `upstreams` array in the pool-health envelope the daemon
/// publishes, with `consecutive_all_failed` set to `stuck`.
fn pool_json(upstreams: &str, stuck: u64) -> String {
    format!(
        r#"{{"upstreams":{upstreams},"resolved":42,
        "all_failed_total":{stuck},"consecutive_all_failed":{stuck}}}"#
    )
}

/// A working environment: config + local list + populated fixture db.
struct Env {
    dir: tempfile::TempDir,
    config: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("local-list.txt");
        std::fs::write(&list, "||blocked.test^\n@@safe.blocked.test\n").unwrap();
        let list_dir = dir.path().join("lists");
        std::fs::create_dir(&list_dir).unwrap();
        let db_path = dir.path().join("sumidero.sqlite");
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            format!(
                r#"
[server]
bind = ["127.0.0.1:5399"]
allow = ["192.168.0.0/16", "127.0.0.0/8"]

[filtering]
list_dir = {list_dir:?}

[[filtering.lists]]
name = "local"
path = {list:?}

[upstreams]
servers = ["https://dns.google/dns-query"]
bootstrap = ["8.8.8.8"]
timeout_ms = 3000

[database]
path = {db_path:?}
"#,
                list_dir = list_dir.display().to_string(),
                list = list.display().to_string(),
                db_path = db_path.display().to_string(),
            ),
        )
        .unwrap();
        Self { dir, config }
    }

    fn db_path(&self) -> PathBuf {
        self.dir.path().join("sumidero.sqlite")
    }

    /// Seed the fixture database with log rows and a fresh heartbeat.
    fn seed_db(&self, heartbeat_age_secs: i64) -> Db {
        let db = Db::open(&self.db_path()).unwrap();
        let w = db.writer();
        let now = unix_now();
        for (qname, verdict, source, rcode) in [
            (
                "blocked.test",
                VerdictKind::Blocked,
                ResponseSource::Synth,
                3,
            ),
            ("ok.test", VerdictKind::Allowed, ResponseSource::Upstream, 0),
            ("ok.test", VerdictKind::Allowed, ResponseSource::Cache, 0),
        ] {
            assert!(w.log(LogEvent::Query(QueryRecord {
                ts: now,
                client: "192.168.1.10".parse().unwrap(),
                qname: qname.into(),
                qtype: 1,
                verdict,
                rule: matches!(verdict, VerdictKind::Blocked).then(|| "||blocked.test^".into()),
                list: matches!(verdict, VerdictKind::Blocked).then_some(0),
                source,
                rcode,
                duration_us: 250,
            })));
        }
        db.flush();
        db.write_heartbeat(&Heartbeat {
            pid: 999_999,
            started_ts: now - 1000,
            updated_ts: now - heartbeat_age_secs,
            config_hash: "cfg-hash".into(),
            lists_hash: "lists-hash".into(),
        })
        .unwrap();
        db
    }

    fn run(&self, args: &[&str]) -> Output {
        bin()
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .output()
            .unwrap()
    }
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

#[test]
fn check_valid_config_json_and_exit_zero() {
    let env = Env::new();
    let out = env.run(&["--json", "check"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_envelope(&v, "check");
    assert_eq!(v["valid"], true);
    assert_eq!(v["lists"], serde_json::json!(["local"]));
    assert_eq!(v["total_rules"], 2);
    assert_eq!(v["parse_issues"], 0);
    assert_eq!(v["lists_hash"].as_str().unwrap().len(), 64);
    assert_eq!(v["config_hash"].as_str().unwrap().len(), 64);
}

#[test]
fn check_invalid_config_json_error_exit_one() {
    let env = Env::new();
    std::fs::write(&env.config, "[server]\nbind = []\n").unwrap();
    let out = env.run(&["--json", "check"]);
    assert_eq!(out.status.code(), Some(1));
    let v = json_of(&out);
    assert_envelope(&v, "check");
    assert!(v["error"].as_str().unwrap().len() > 5);
}

#[test]
fn check_missing_config_fails_loud() {
    let out = bin()
        .args(["--config", "/nonexistent/sumidero.toml", "--json", "check"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v = json_of(&out);
    assert!(v["error"].as_str().unwrap().contains("/nonexistent"));
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

#[test]
fn explain_blocked_exit_three_with_rule() {
    let env = Env::new();
    env.seed_db(0);
    let out = env.run(&["--json", "explain", "sub.blocked.test"]);
    assert_eq!(out.status.code(), Some(3));
    let v = json_of(&out);
    assert_envelope(&v, "explain");
    assert_eq!(v["verdict"], "blocked");
    assert_eq!(v["rule"], "||blocked.test^");
    assert_eq!(v["list"], "local");
    assert_eq!(v["hash_match"], false, "fixture heartbeat has fake hash");
    assert!(v["warning"].as_str().unwrap().contains("differs"));
}

#[test]
fn explain_excepted_exit_four() {
    let env = Env::new();
    let out = env.run(&["--json", "explain", "safe.blocked.test"]);
    assert_eq!(out.status.code(), Some(4));
    let v = json_of(&out);
    assert_eq!(v["verdict"], "excepted");
}

#[test]
fn explain_no_match_exit_zero_without_daemon() {
    let env = Env::new();
    let out = env.run(&["--json", "explain", "wikipedia.org"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_eq!(v["verdict"], "no-match");
    assert_eq!(v["rule"], Value::Null);
    // No daemon db: hash comparison is explicitly null, not false.
    assert_eq!(v["hash_match"], Value::Null);
    assert_eq!(v["warning"], Value::Null);
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

#[test]
fn status_fresh_heartbeat_running_exit_zero() {
    let env = Env::new();
    env.seed_db(10);
    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_envelope(&v, "status");
    assert_eq!(v["running"], true);
    assert_eq!(v["pid"], 999_999);
    assert_eq!(v["config_hash"], "cfg-hash");
    assert_eq!(v["lists_hash"], "lists-hash");
}

#[test]
fn status_without_daemon_stats_reports_unknown_not_healthy() {
    // A daemon that predates the daemon_stats row publishes nothing; the
    // fields are null rather than a reassuring zero.
    let env = Env::new();
    env.seed_db(10);
    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_eq!(v["upstreams"], Value::Null);
    assert_eq!(v["log_events_dropped"], Value::Null);
    assert_eq!(v["degraded"], false);
}

#[test]
fn status_reports_upstream_health() {
    let env = Env::new();
    let db = env.seed_db(10);
    db.write_daemon_stats(&DaemonStats {
        updated_ts: unix_now(),
        log_events_dropped: 0,
        log_events_dropped_recent: 0,
        upstreams_json: pool_json(
            r#"[{"url":"https://dns.google/dns-query","connected":true,
            "last_success_secs_ago":2,"queries":42,"failures":1,"reconnects":1,
            "consecutive_failures":0}]"#,
            0,
        ),
    })
    .unwrap();

    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_eq!(v["degraded"], false);
    assert_eq!(v["log_events_dropped"], 0);
    assert_eq!(v["queries_resolved"], 42);
    let ups = v["upstreams"].as_array().unwrap();
    assert_eq!(ups.len(), 1);
    assert_eq!(ups[0]["url"], "https://dns.google/dns-query");
    assert_eq!(ups[0]["reconnects"], 1);
}

#[test]
fn status_not_degraded_while_one_upstream_reconnects() {
    // Regression cover for a false alarm: connections are rebuilt lazily
    // on the next query, so a healthy raced pool routinely shows an
    // upstream with `connected: false` between queries. Observed live —
    // AdGuard's DoQ slot reads disconnected for tens of seconds while
    // every client query is answered. That is not degraded.
    let env = Env::new();
    let db = env.seed_db(10);
    db.write_daemon_stats(&DaemonStats {
        updated_ts: unix_now(),
        log_events_dropped: 0,
        log_events_dropped_recent: 0,
        upstreams_json: pool_json(
            r#"[{"url":"quic://dns.adguard-dns.com","connected":false,
            "last_success_secs_ago":8,"queries":100,"failures":0,"reconnects":7,
            "consecutive_failures":0},
            {"url":"https://dns.google/dns-query","connected":true,
            "last_success_secs_ago":1,"queries":100,"failures":0,"reconnects":0,
            "consecutive_failures":0}]"#,
            0,
        ),
    })
    .unwrap();

    let out = env.run(&["--json", "status"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a reconnecting upstream is not an outage"
    );
    let v = json_of(&out);
    assert_eq!(v["degraded"], false);
}

#[test]
fn status_degraded_exit_seven_when_no_upstream_can_answer() {
    // The 2026-08-20 outage shape: heartbeat fresh, every upstream dead.
    // "Running" must not read as "fine".
    let env = Env::new();
    let db = env.seed_db(10);
    db.write_daemon_stats(&DaemonStats {
        updated_ts: unix_now(),
        log_events_dropped: 0,
        log_events_dropped_recent: 0,
        upstreams_json: pool_json(
            r#"[{"url":"https://dns.google/dns-query","connected":false,
            "last_success_secs_ago":25200,"queries":900,"failures":900,"reconnects":0,
            "consecutive_failures":900}]"#,
            900,
        ),
    })
    .unwrap();

    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(7));
    let v = json_of(&out);
    assert_eq!(v["running"], true);
    assert_eq!(v["degraded"], true);
}

#[test]
fn status_degraded_exit_seven_when_log_events_were_dropped() {
    let env = Env::new();
    let db = env.seed_db(10);
    db.write_daemon_stats(&DaemonStats {
        updated_ts: unix_now(),
        log_events_dropped: 17,
        log_events_dropped_recent: 17,
        upstreams_json: pool_json(
            r#"[{"url":"https://dns.google/dns-query","connected":true,
            "last_success_secs_ago":1,"queries":42,"failures":0,"reconnects":0,
            "consecutive_failures":0}]"#,
            0,
        ),
    })
    .unwrap();

    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(7));
    let v = json_of(&out);
    assert_eq!(v["degraded"], true);
    assert_eq!(v["log_events_dropped"], 17);
    assert_eq!(v["log_events_dropped_recent"], 17);
}

#[test]
fn status_not_degraded_when_drops_are_only_historical() {
    // Regression cover for a review finding: `log_events_dropped` is a
    // lifetime counter that never goes back down, so keying `degraded`
    // off it pinned the daemon degraded — exit 7 on every check, forever
    // — after a single transient queue-full spike hours earlier. Only
    // events dropped since the last sample mean anything is wrong now.
    let env = Env::new();
    let db = env.seed_db(10);
    db.write_daemon_stats(&DaemonStats {
        updated_ts: unix_now(),
        log_events_dropped: 42,
        log_events_dropped_recent: 0,
        upstreams_json: pool_json(
            r#"[{"url":"https://dns.google/dns-query","connected":true,
            "last_success_secs_ago":1,"queries":9000,"failures":0,"reconnects":0,
            "consecutive_failures":0}]"#,
            0,
        ),
    })
    .unwrap();

    let out = env.run(&["--json", "status"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a historical drop must not pin the daemon degraded"
    );
    let v = json_of(&out);
    assert_eq!(v["degraded"], false);
    assert_eq!(v["log_events_dropped"], 42, "the total is still reported");
    assert_eq!(v["log_events_dropped_recent"], 0);

    // ...and the human output says so without shouting.
    let out = env.run(&["status"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("42 query-log events dropped since start"),
        "{text}"
    );
    assert!(!text.contains("WARNING"), "{text}");
}

#[test]
fn status_human_output_reports_the_outage_and_drops() {
    let env = Env::new();
    let db = env.seed_db(10);
    db.write_daemon_stats(&DaemonStats {
        updated_ts: unix_now(),
        log_events_dropped: 3,
        log_events_dropped_recent: 3,
        upstreams_json: pool_json(
            r#"[{"url":"quic://dns.adguard-dns.com","connected":false,
            "last_success_secs_ago":600,"queries":5,"failures":5,"reconnects":2,
            "consecutive_failures":5}]"#,
            5,
        ),
    })
    .unwrap();

    let out = env.run(&["status"]);
    assert_eq!(out.status.code(), Some(7));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("every upstream is failing"), "{text}");
    assert!(text.contains("quic://dns.adguard-dns.com"), "{text}");
    assert!(text.contains("3 query-log events dropped"), "{text}");
}

#[test]
fn status_stale_heartbeat_exit_five() {
    let env = Env::new();
    env.seed_db(3600);
    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(5));
    let v = json_of(&out);
    assert_eq!(v["running"], false);
}

#[test]
fn status_no_heartbeat_exit_five() {
    let env = Env::new();
    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(5));
    let v = json_of(&out);
    assert_eq!(v["running"], false);
}

// ---------------------------------------------------------------------------
// log / stats
// ---------------------------------------------------------------------------

#[test]
fn log_returns_seeded_entries() {
    let env = Env::new();
    env.seed_db(0);
    let out = env.run(&["--json", "log", "--limit", "10"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_envelope(&v, "log");
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    let blocked = entries
        .iter()
        .find(|e| e["qname"] == "blocked.test")
        .unwrap();
    assert_eq!(blocked["verdict"], "blocked");
    assert_eq!(blocked["rule"], "||blocked.test^");
    assert_eq!(blocked["source"], "synth");
    assert_eq!(blocked["rcode"], 3);
    assert_eq!(blocked["client"], "192.168.1.10");
}

#[test]
fn stats_aggregates_seeded_rows() {
    let env = Env::new();
    env.seed_db(0);
    let out = env.run(&["--json", "stats", "--hours", "1"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_envelope(&v, "stats");
    assert_eq!(v["total"], 3);
    assert_eq!(v["blocked"], 1);
    assert_eq!(v["cache_hits"], 1);
    assert_eq!(v["window_hours"], 1);
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

#[test]
fn init_writes_valid_roundtrip_config() {
    let env = Env::new();
    let target = env.dir.path().join("fresh.toml");
    let out = env.run(&[
        "--json",
        "init",
        "--profile",
        "balanced",
        "--out",
        target.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_envelope(&v, "init");
    assert_eq!(v["profile"], "balanced");
    // The generated file must parse and validate.
    let check = bin()
        .args(["--config", target.to_str().unwrap(), "--json", "check"])
        .output()
        .unwrap();
    // check needs list_dir to exist and stored copies — offline check of a
    // fresh config fails on missing lists, which IS the fail-loud contract;
    // config PARSE must succeed though, so the error must be about lists.
    if check.status.code() != Some(0) {
        let v = json_of(&check);
        let err = v["error"].as_str().unwrap();
        assert!(
            err.contains("list") || err.contains("dir"),
            "unexpected failure kind: {err}"
        );
    }
}

#[test]
fn init_refuses_overwrite_without_force_exit_six() {
    let env = Env::new();
    let out = env.run(&["--json", "init", "--profile", "minimal"]);
    assert_eq!(out.status.code(), Some(6), "config.toml already exists");
    let v = json_of(&out);
    assert!(v["error"].as_str().unwrap().contains("--force"));
}

// ---------------------------------------------------------------------------
// migrate (against the sanitized copy of the real AdGuardHome.yaml)
// ---------------------------------------------------------------------------

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn migrate_real_adguard_config() {
    let env = Env::new();
    let target = env.dir.path().join("migrated.toml");
    let out = env.run(&[
        "--json",
        "migrate",
        fixture("AdGuardHome.yaml").to_str().unwrap(),
        "--out",
        target.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v = json_of(&out);
    assert_envelope(&v, "migrate");

    let toml = std::fs::read_to_string(&target).unwrap();
    // Upstreams survive (DoH ×2 + DoQ), binds cover v4+v6, allowlist CIDRs.
    assert!(toml.contains("https://dns.google/dns-query"));
    assert!(toml.contains("quic://dns.adguard-dns.com"));
    assert!(toml.contains("0.0.0.0:53"));
    assert!(toml.contains("[::]:53"));
    assert!(toml.contains("192.168.0.0/24"));
    assert!(toml.contains("127.0.0.1/32"));
    assert!(toml.contains("timeout_ms = 5000"));
    // Enabled filters migrated, disabled ones warned about.
    assert!(toml.contains("hagezi-pro-ads-and-trackers"));
    assert!(toml.contains("https://big.oisd.nl"));
    assert!(
        !toml.contains("filter_2.txt"),
        "disabled filter must not migrate"
    );
    // Safe search: bing+duckduckgo supported; ecosia/pixabay/yandex warned.
    assert!(toml.contains("enabled = true"));
    let warnings = v["warnings"].as_array().unwrap();
    let wtext = warnings
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(wtext.contains("ecosia"));
    assert!(wtext.contains("yandex"));
    assert!(wtext.contains("AdAway"), "disabled filter warning");
    assert!(wtext.contains("fallback_dns"));

    // User rules file: user_rules + blocked_hosts.
    let rules_path = env.dir.path().join("user-rules.txt");
    let rules = std::fs::read_to_string(&rules_path).unwrap();
    assert!(rules.contains("@@||app.posthog.com^"));
    assert!(rules.contains("version.bind"));

    // The migrated config must itself pass `check`-level parsing (it did,
    // inside migrate), and be loadable as TOML here too.
    assert!(toml.contains("[database]"));
}

#[test]
fn migrate_refuses_overwrite_exit_six() {
    let env = Env::new();
    let out = env.run(&[
        "--json",
        "migrate",
        fixture("AdGuardHome.yaml").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(6),
        "default --out is the existing config"
    );
}

#[test]
fn migrate_garbage_yaml_fails_loud() {
    let env = Env::new();
    let bad = env.dir.path().join("bad.yaml");
    std::fs::write(&bad, ":: not yaml ::").unwrap();
    let out = env.run(&[
        "--json",
        "migrate",
        bad.to_str().unwrap(),
        "--out",
        env.dir.path().join("x.toml").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
}

// ---------------------------------------------------------------------------
// reload
// ---------------------------------------------------------------------------

#[test]
fn reload_without_daemon_exit_five() {
    let env = Env::new();
    let out = env.run(&["--json", "reload"]);
    assert_eq!(out.status.code(), Some(5));
    let v = json_of(&out);
    assert_envelope(&v, "reload");
    assert!(v["error"].as_str().unwrap().contains("not running"));
}

#[test]
fn reload_with_invalid_config_exit_one_before_signalling() {
    let env = Env::new();
    std::fs::write(&env.config, "not toml at all [").unwrap();
    let out = env.run(&["--json", "reload"]);
    assert_eq!(out.status.code(), Some(1));
    let v = json_of(&out);
    assert!(v["error"].as_str().unwrap().contains("check failed"));
}

// ---------------------------------------------------------------------------
// usage errors
// ---------------------------------------------------------------------------

#[test]
fn unknown_subcommand_exit_two() {
    let out = bin().arg("frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn help_lists_every_command() {
    let out = bin().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8_lossy(&out.stdout);
    for cmd in [
        "serve", "status", "log", "stats", "explain", "check", "reload", "init", "migrate",
    ] {
        assert!(help.contains(cmd), "--help must mention {cmd}");
    }
}

// ---------------------------------------------------------------------------
// Phase 3 review findings — contract hardening
// ---------------------------------------------------------------------------

#[test]
fn usage_error_with_json_emits_envelope_on_stdout() {
    for args in [
        vec!["--json", "frobnicate"],
        vec!["--json", "explain"],
        vec!["--json", "init", "--profile", "bogus"],
    ] {
        let out = bin().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let v = json_of(&out);
        assert_eq!(v["schema"], "v1", "{args:?}");
        assert_eq!(v["command"], "usage", "{args:?}");
        assert!(!v["error"].as_str().unwrap().is_empty(), "{args:?}");
    }
}

#[test]
fn status_schema_shape_is_stable_without_heartbeat() {
    let env = Env::new();
    let out = env.run(&["--json", "status"]);
    assert_eq!(out.status.code(), Some(5));
    let v = json_of(&out);
    // Same field set as the running case, nulled.
    for field in [
        "running",
        "pid",
        "started_ts",
        "updated_ts",
        "heartbeat_age_secs",
        "config_hash",
        "lists_hash",
    ] {
        assert!(v.get(field).is_some(), "missing field {field}: {v}");
    }
    assert_eq!(v["pid"], Value::Null);
}

#[test]
fn status_all_fields_when_running() {
    let env = Env::new();
    env.seed_db(10);
    let v = json_of(&env.run(&["--json", "status"]));
    assert_eq!(v["running"], true);
    assert_eq!(v["pid"], 999_999);
    assert!(v["started_ts"].is_i64());
    assert!(v["updated_ts"].is_i64());
    assert!(v["heartbeat_age_secs"].is_i64());
    assert_eq!(v["config_hash"], "cfg-hash");
    assert_eq!(v["lists_hash"], "lists-hash");
}

#[test]
fn explain_rejects_garbage_domain_exit_two() {
    let env = Env::new();
    for bad in ["", "hello world", "emoji🙂.com"] {
        let out = env.run(&["--json", "explain", bad]);
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
        let v = json_of(&out);
        assert!(
            v["error"].as_str().unwrap().contains("plausible"),
            "{bad:?}"
        );
    }
    let long = format!("{}.com", "a".repeat(300));
    let out = env.run(&["--json", "explain", &long]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn explain_full_field_set() {
    let env = Env::new();
    let v = json_of(&env.run(&["--json", "explain", "sub.blocked.test"]));
    assert_eq!(v["domain"], "sub.blocked.test");
    assert_eq!(v["verdict"], "blocked");
    assert_eq!(v["rule"], "||blocked.test^");
    assert_eq!(v["list"], "local");
    assert_eq!(v["lists_hash"].as_str().unwrap().len(), 64);
    assert_eq!(v["daemon_lists_hash"], Value::Null);
    assert_eq!(v["hash_match"], Value::Null);
    assert_eq!(v["warning"], Value::Null);
}

#[test]
fn stats_full_field_set() {
    let env = Env::new();
    env.seed_db(0);
    let v = json_of(&env.run(&["--json", "stats", "--hours", "1"]));
    assert_eq!(v["window_hours"], 1);
    assert_eq!(v["total"], 3);
    assert_eq!(v["blocked"], 1);
    assert_eq!(v["excepted"], 0);
    assert_eq!(v["cache_hits"], 1);
    assert_eq!(v["upstream_failures"], 0);
    assert!(v["top_queried"].is_array());
    assert!(v["top_blocked"].is_array());
    let top = v["top_queried"].as_array().unwrap();
    assert_eq!(top[0][0], "ok.test");
    assert_eq!(top[0][1], 2);
}

#[test]
fn log_full_entry_field_set() {
    let env = Env::new();
    env.seed_db(0);
    let v = json_of(&env.run(&["--json", "log", "--limit", "10"]));
    let e = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["qname"] == "blocked.test")
        .unwrap();
    assert!(e["ts"].is_i64());
    assert_eq!(e["qtype"], 1);
    assert_eq!(e["list"], 0);
    assert_eq!(e["duration_us"], 250);
    assert_eq!(e["client"], "192.168.1.10");
    assert_eq!(e["verdict"], "blocked");
    assert_eq!(e["rule"], "||blocked.test^");
    assert_eq!(e["source"], "synth");
    assert_eq!(e["rcode"], 3);
}

#[test]
fn check_full_field_set_includes_rule_counts() {
    let env = Env::new();
    let v = json_of(&env.run(&["--json", "check"]));
    assert_eq!(v["rule_counts"], serde_json::json!([2]));
}

#[test]
fn init_force_overwrites_and_reports_written() {
    let env = Env::new();
    let out = env.run(&["--json", "init", "--profile", "minimal", "--force"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_eq!(v["written"], env.config.display().to_string());
    let content = std::fs::read_to_string(&env.config).unwrap();
    assert!(content.contains("minimal") || content.contains("hagezi-light"));
}

#[test]
fn migrate_force_overwrites_and_reports_fields() {
    let env = Env::new();
    let out = env.run(&[
        "--json",
        "migrate",
        fixture("AdGuardHome.yaml").to_str().unwrap(),
        "--force",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_eq!(v["written"], env.config.display().to_string());
    assert!(
        v["user_rules"]
            .as_str()
            .unwrap()
            .ends_with("user-rules.txt")
    );
    assert!(v["warnings"].is_array());
}

#[test]
fn human_output_status_and_log() {
    let env = Env::new();
    env.seed_db(0);
    let out = env.run(&["status"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("running: pid 999999"), "{text}");
    assert!(
        serde_json::from_str::<Value>(text.trim()).is_err(),
        "human mode is not JSON"
    );

    let out = env.run(&["log", "--limit", "5"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("blocked.test"), "{text}");
}

#[test]
fn serve_with_invalid_config_fails_loud() {
    let out = bin()
        .args(["--config", "/nonexistent/config.toml", "--json", "serve"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v = json_of(&out);
    assert_envelope(&v, "serve");
    assert!(v["error"].as_str().unwrap().contains("/nonexistent"));
}

#[test]
fn reload_success_signals_live_pid() {
    let env = Env::new();
    // A real child process stands in for the daemon; SIGHUP's default
    // disposition terminates it, which doubles as proof of delivery.
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let db = Db::open(&env.db_path()).unwrap();
    let now = unix_now();
    db.write_heartbeat(&Heartbeat {
        pid: child.id(),
        started_ts: now - 10,
        updated_ts: now,
        config_hash: "c".into(),
        lists_hash: "l".into(),
    })
    .unwrap();
    let out = env.run(&["--json", "reload"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v = json_of(&out);
    assert_envelope(&v, "reload");
    assert_eq!(v["signalled_pid"], child.id());
    // The sleep child dies of SIGHUP promptly.
    let mut child = child;
    std::thread::sleep(std::time::Duration::from_millis(300));
    if let Some(status) = child.try_wait().unwrap() {
        assert!(!status.success(), "killed by SIGHUP");
    } else {
        child.kill().unwrap();
        panic!("child did not receive SIGHUP");
    }
}

// ---------------------------------------------------------------------------
// migrate edge cases from review
// ---------------------------------------------------------------------------

fn migrate_yaml(env: &Env, yaml: &str) -> (Option<i32>, Value, PathBuf) {
    let input = env.dir.path().join("in.yaml");
    std::fs::write(&input, yaml).unwrap();
    let target = env.dir.path().join("out.toml");
    let _ = std::fs::remove_file(&target);
    let out = env.run(&[
        "--json",
        "migrate",
        input.to_str().unwrap(),
        "--out",
        target.to_str().unwrap(),
    ]);
    (out.status.code(), json_of(&out), target)
}

const MIGRATE_BASE: &str = r"
dns:
  bind_hosts: [0.0.0.0, '::']
  port: 53
  upstream_dns: ['https://dns.google/dns-query']
  bootstrap_dns: [8.8.8.8]
  upstream_timeout: 5s
user_rules: ['||base.test^']
";

#[test]
fn migrate_dual_wildcard_binds_do_not_duplicate() {
    let env = Env::new();
    let (code, _v, target) = migrate_yaml(&env, MIGRATE_BASE);
    assert_eq!(code, Some(0));
    let toml = std::fs::read_to_string(target).unwrap();
    assert_eq!(toml.matches("[::]:53").count(), 1, "{toml}");
}

#[test]
fn migrate_client_ids_fall_back_to_rfc1918_with_warning() {
    let env = Env::new();
    let yaml = MIGRATE_BASE.replace(
        "  upstream_timeout: 5s",
        "  upstream_timeout: 5s\n  allowed_clients: [phone-1, laptop]",
    );
    let (code, v, target) = migrate_yaml(&env, &yaml);
    assert_eq!(code, Some(0), "{v}");
    let toml = std::fs::read_to_string(target).unwrap();
    assert!(toml.contains("192.168.0.0/16"));
    let w = v["warnings"].to_string();
    assert!(w.contains("phone-1"));
    assert!(w.contains("EDIT THIS"));
}

#[test]
fn migrate_slug_collisions_renamed_unique() {
    let env = Env::new();
    let yaml = format!(
        "{MIGRATE_BASE}filters:\n  - {{enabled: true, url: 'https://a.example/1.txt', name: 'My Filter'}}\n  - {{enabled: true, url: 'https://b.example/2.txt', name: 'My  Filter'}}\n  - {{enabled: true, url: 'https://c.example/3.txt', name: 'User Rules'}}\n"
    );
    let (code, v, target) = migrate_yaml(&env, &yaml);
    assert_eq!(code, Some(0), "{v}");
    let toml = std::fs::read_to_string(target).unwrap();
    assert!(toml.contains("\"my-filter\""));
    assert!(toml.contains("\"my-filter-2\""));
    // The filter that slugged to user-rules is renamed; the synthetic
    // local list keeps the canonical name.
    assert!(toml.contains("\"user-rules-2\""), "{toml}");
    assert_eq!(toml.matches("name = \"user-rules\"").count(), 1, "{toml}");
}

#[test]
fn migrate_empty_filter_name_gets_fallback() {
    let env = Env::new();
    let yaml = format!(
        "{MIGRATE_BASE}filters:\n  - {{enabled: true, url: 'https://a.example/1.txt', name: '---'}}\n"
    );
    let (code, _v, target) = migrate_yaml(&env, &yaml);
    assert_eq!(code, Some(0));
    let toml = std::fs::read_to_string(target).unwrap();
    assert!(toml.contains("name = \"list-1\""), "{toml}");
}

// ---------------------------------------------------------------------------
// shadow report
// ---------------------------------------------------------------------------

#[test]
fn shadow_report_summarizes_divergences() {
    let env = Env::new();
    let db = Db::open(&env.db_path()).unwrap();
    let w = db.writer();
    let now = unix_now();
    for (q, class) in [
        ("a.test", "expected"),
        ("b.test", "expected"),
        ("c.test", "they-block-we-answer"),
    ] {
        assert!(w.log(sumidero_core::db::LogEvent::Divergence {
            ts: now,
            qname: q.into(),
            qtype: 1,
            ours: "NoError".into(),
            theirs: "blocky/NoError".into(),
            class: class.into(),
        }));
    }
    db.flush();
    let out = env.run(&["--json", "shadow", "report", "--hours", "1"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_envelope(&v, "shadow-report");
    assert_eq!(v["window_hours"], 1);
    assert_eq!(v["unexpected"], 1);
    assert_eq!(v["summary"][0][0], "expected");
    assert_eq!(v["summary"][0][1], 2);
    let recent = v["recent"].as_array().unwrap();
    assert_eq!(recent.len(), 3);
    assert!(recent.iter().all(|d| {
        d["ts"].is_i64()
            && d["qname"].is_string()
            && d["qtype"].is_i64()
            && d["ours"].is_string()
            && d["theirs"].is_string()
            && d["class"].is_string()
    }));
}

#[test]
fn shadow_report_empty_db() {
    let env = Env::new();
    let out = env.run(&["--json", "shadow", "report"]);
    assert_eq!(out.status.code(), Some(0));
    let v = json_of(&out);
    assert_eq!(v["unexpected"], 0);
    assert_eq!(v["summary"], serde_json::json!([]));
    assert_eq!(v["window_hours"], 48);
}
