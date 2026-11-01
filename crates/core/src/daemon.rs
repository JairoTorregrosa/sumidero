//! Daemon lifecycle: start, serve, reload, refresh, report, stop.
//!
//! ```text
//! Starting ──stored copies load──▶ Serving ◀──────────────┐
//!    │                                │                    │
//!    └─a list has no copy: download───┘    refresher: SIGHUP / timer
//!       before binding (fail loud)         builds a whole new Policy and
//!                                          installs it in one swap, or
//!                                          keeps the old one and says why
//! Serving ──SIGTERM/SIGINT──▶ Draining (≤ 2 s) ──▶ flushed, exit 0
//! ```
//!
//! The DNS sockets never wait for the network when every list has a
//! stored copy: start-up filters with what is on disk and the refresher
//! downloads right after. Only a list that has never been downloaded
//! (and has no `path` seed) makes start-up wait for it, because the
//! daemon must never serve unfiltered.
//!
//! All list work runs in one refresher task, never inside the signal and
//! heartbeat loop: a 10 s download cannot delay a heartbeat or a
//! shutdown. Every outcome lands in a [`RuntimeReport`] that is written
//! to the database right away, so `sumidero status` and `reload` read
//! what happened instead of guessing.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::CoreError;
use crate::cache::Cache;
use crate::config::Config;
use crate::db::Db;
use crate::lists::{self, Fetcher, ListReport, LoadedLists};
use crate::safesearch::SafeSearch;
use crate::server::{Pipeline, Policy, serve, unix_now};
use crate::upstream::{UpstreamConfig, UpstreamPool};

/// A list whose content was last confirmed longer ago than this makes
/// the daemon `degraded`.
pub const STALE_LIST_SECS: u64 = 3 * 86_400;
/// Normal refresh period.
pub const REFRESH_EVERY: Duration = Duration::from_hours(24);
/// Refresh period while some list failed to download.
pub const RETRY_AFTER_FETCH_FAILURE: Duration = Duration::from_hours(1);
/// How long shutdown waits for in-flight queries.
const DRAIN: Duration = Duration::from_secs(2);

/// What started a list load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Startup,
    Signal,
    Timer,
}

/// One attempt to build and install a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadOutcome {
    /// Unix seconds when it finished.
    pub ts: i64,
    pub trigger: Trigger,
    pub ok: bool,
    /// Why it failed; the previous policy stayed in force.
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// What the daemon is running with, written to `daemon_stats.runtime_json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeReport {
    /// Unix seconds when the lists in force were loaded.
    pub lists_loaded_ts: i64,
    pub lists: Vec<ListReport>,
    pub lists_hash: String,
    /// Hash of the config whose lists and policy are in force.
    pub applied_config_hash: String,
    pub last_reload: Option<ReloadOutcome>,
    /// Settings changed on disk that only a restart applies.
    pub pending_restart: Vec<String>,
    /// Unix seconds of the next scheduled refresh.
    pub next_refresh_ts: i64,
}

/// One reason the daemon is `degraded`, with the operator's next step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Degraded {
    /// Stable code: `cannot_resolve`, `log_events_dropped`,
    /// `list_fetch_failed`, `list_stale`, `reload_failed`,
    /// `pending_restart`.
    pub reason: String,
    pub detail: String,
    pub next: String,
}

fn degraded(reason: &str, detail: String, next: &str) -> Degraded {
    Degraded {
        reason: reason.to_owned(),
        detail,
        next: next.to_owned(),
    }
}

/// Everything wrong with a running daemon, from its own report.
#[must_use]
pub fn degraded_reasons(
    runtime: &RuntimeReport,
    consecutive_all_failed: u64,
    log_events_dropped_recent: u64,
    now: i64,
) -> Vec<Degraded> {
    let mut out = Vec::new();
    if consecutive_all_failed > 0 {
        out.push(degraded(
            "cannot_resolve",
            format!("{consecutive_all_failed} consecutive queries found no upstream"),
            "check the WAN link and `sumidero status --json` upstreams",
        ));
    }
    if log_events_dropped_recent > 0 {
        out.push(degraded(
            "log_events_dropped",
            format!("{log_events_dropped_recent} query-log events dropped since the last sample"),
            "the SQLite writer cannot keep up; check disk latency",
        ));
    }
    let since_load = u64::try_from(now - runtime.lists_loaded_ts).unwrap_or(0);
    for list in &runtime.lists {
        if let lists::ListOrigin::StoredAfterFetchFailure { reason }
        | lists::ListOrigin::SeedAfterFetchFailure { reason } = &list.origin
        {
            out.push(degraded(
                "list_fetch_failed",
                format!("{}: {reason}", list.name),
                "the last good copy is in use; the refresher retries hourly",
            ));
        }
        if let Some(age) = list.verified_age_secs.map(|a| a + since_load)
            && age > STALE_LIST_SECS
        {
            out.push(degraded(
                "list_stale",
                format!("{}: content last confirmed {} h ago", list.name, age / 3600),
                "check the list URL; `sumidero reload` retries now",
            ));
        }
    }
    if let Some(last) = &runtime.last_reload
        && !last.ok
    {
        out.push(degraded(
            "reload_failed",
            last.error.clone().unwrap_or_default(),
            "the previous lists and policy are still in force; fix the cause and reload",
        ));
    }
    if !runtime.pending_restart.is_empty() {
        out.push(degraded(
            "pending_restart",
            runtime.pending_restart.join(", "),
            "systemctl restart sumidero",
        ));
    }
    out
}

/// Settings that differ between the running daemon's start-up config
/// and `new` and that no reload can apply.
fn restart_only_changes(started: &Config, new: &Config) -> Vec<String> {
    let mut out = Vec::new();
    if started.server.bind != new.server.bind {
        out.push("server.bind".to_owned());
    }
    if started.upstreams != new.upstreams {
        out.push("upstreams".to_owned());
    }
    if started.database != new.database {
        out.push("database".to_owned());
    }
    if started.tls != new.tls {
        out.push("tls".to_owned());
    }
    if started.cache != new.cache {
        out.push("cache".to_owned());
    }
    out
}

/// Load lists for `config` and assemble the policy they imply.
async fn build_policy(
    config: &Config,
    fetcher: Option<&Fetcher>,
) -> Result<(Policy, LoadedLists), CoreError> {
    let safesearch = SafeSearch::new(config.safe_search.enabled, &config.safe_search.providers)?;
    let mut loaded = lists::load(
        &config.effective_lists(),
        &config.filtering.list_dir,
        fetcher,
    )
    .await?;
    let engine = std::mem::take(&mut loaded.engine);
    tracing::info!(
        rules = loaded.total_rules(),
        lists = loaded.names.len(),
        hash = %loaded.hash,
        "filter engine ready"
    );
    Ok((
        Policy {
            engine: Arc::new(engine),
            safesearch: Arc::new(safesearch),
            allow: config.server.allow.clone().into(),
        },
        loaded,
    ))
}

fn outcome(trigger: Trigger, started: Instant, result: Result<(), String>) -> ReloadOutcome {
    ReloadOutcome {
        ts: unix_now(),
        trigger,
        ok: result.is_ok(),
        error: result.err(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn next_refresh(loaded: &LoadedLists) -> Duration {
    if loaded.reports.iter().any(|r| r.origin.fetch_failed()) {
        RETRY_AFTER_FETCH_FAILURE
    } else {
        REFRESH_EVERY
    }
}

/// Shared between the refresher (writer) and the heartbeat (reader).
type Shared = Arc<Mutex<RuntimeReport>>;

fn snapshot(shared: &Shared) -> RuntimeReport {
    shared.lock().expect("runtime report poisoned").clone()
}

async fn publish_runtime(db: &Arc<Db>, shared: &Shared) {
    let json = match serde_json::to_string(&snapshot(shared)) {
        Ok(json) => json,
        Err(err) => {
            tracing::error!(%err, "runtime report serialization failed");
            return;
        }
    };
    let db = Arc::clone(db);
    let result = tokio::task::spawn_blocking(move || db.write_runtime(unix_now(), &json)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::error!(%err, "runtime report write failed"),
        Err(err) => tracing::error!(%err, "runtime report task failed"),
    }
}

/// Owns every list load after start-up. Reloads arrive as configs on
/// `reloads`; the timer fires every [`REFRESH_EVERY`] (hourly while a
/// list fails to download). A failed load keeps the policy in force.
struct Refresher {
    pipeline: Arc<Pipeline<Arc<UpstreamPool>>>,
    fetcher: Fetcher,
    db: Arc<Db>,
    shared: Shared,
    /// The config the daemon started with (restart-only settings).
    started_with: Config,
    /// The config whose lists are in force.
    current: Config,
}

impl Refresher {
    async fn run(mut self, mut reloads: tokio::sync::mpsc::Receiver<Config>, first: Duration) {
        let mut deadline = tokio::time::Instant::now() + first;
        loop {
            let (trigger, new) = tokio::select! {
                msg = reloads.recv() => match msg {
                    Some(config) => (Trigger::Signal, Some(config)),
                    None => return,
                },
                () = tokio::time::sleep_until(deadline) => (Trigger::Timer, None),
            };
            let config = new.unwrap_or_else(|| self.current.clone());
            let started = Instant::now();
            let result = build_policy(&config, Some(&self.fetcher)).await;
            let wait = match result {
                Ok((policy, loaded)) => {
                    self.pipeline.install(policy);
                    let wait = next_refresh(&loaded);
                    {
                        let mut report = self.shared.lock().expect("runtime report poisoned");
                        report.lists_loaded_ts = unix_now();
                        report.lists_hash.clone_from(&loaded.hash);
                        report.lists = loaded.reports;
                        report.applied_config_hash = config.hash();
                        report.pending_restart = restart_only_changes(&self.started_with, &config);
                        report.last_reload = Some(outcome(trigger, started, Ok(())));
                    }
                    if !self
                        .shared
                        .lock()
                        .expect("runtime report poisoned")
                        .pending_restart
                        .is_empty()
                    {
                        tracing::warn!(
                            "some changed settings need a restart; filtering, allowlist and safe search were reloaded"
                        );
                    }
                    tracing::info!(?trigger, "reload complete");
                    self.current = config;
                    wait
                }
                Err(err) => {
                    tracing::error!(?trigger, %err, "reload failed; the previous lists and policy stay in force");
                    let mut report = self.shared.lock().expect("runtime report poisoned");
                    report.last_reload = Some(outcome(trigger, started, Err(err.to_string())));
                    RETRY_AFTER_FETCH_FAILURE
                }
            };
            deadline = tokio::time::Instant::now() + wait;
            self.shared
                .lock()
                .expect("runtime report poisoned")
                .next_refresh_ts = unix_now() + i64::try_from(wait.as_secs()).unwrap_or(i64::MAX);
            publish_runtime(&self.db, &self.shared).await;
        }
    }
}

/// Run the daemon from a config file: fail loud on any start-up
/// problem, serve until SIGTERM/SIGINT, reload on SIGHUP, refresh lists
/// on a timer.
///
/// # Errors
///
/// Any start-up failure: config, database, upstreams, lists, sockets.
///
/// # Panics
///
/// If the runtime report mutex is poisoned (a panic elsewhere already).
#[expect(
    clippy::too_many_lines,
    reason = "linear start-up followed by the signal loop"
)]
pub async fn run(
    config_path: &std::path::Path,
    shadow: Option<std::net::SocketAddr>,
) -> Result<(), CoreError> {
    let config = Config::load(config_path)?;
    let db = Arc::new(Db::open(&config.database.path)?);
    let started_ts = unix_now();

    let extra_roots = config.extra_roots()?;
    let pool = Arc::new(
        UpstreamPool::new(&UpstreamConfig {
            urls: config.upstreams.servers.clone(),
            bootstrap_ips: config.upstreams.bootstrap.clone(),
            timeout_ms: config.upstreams.timeout_ms,
            extra_roots: extra_roots.clone(),
            connect_budget: crate::upstream::DEFAULT_CONNECT_BUDGET,
        })
        .await?,
    );
    let fetcher = Fetcher::new(&extra_roots, Arc::clone(&pool))?;

    // Stored copies first (seconds); the network only when a list has
    // never been downloaded. Either way nothing is served unfiltered.
    let started = Instant::now();
    let (policy, loaded, refresh_in) = match build_policy(&config, None).await {
        Ok((policy, loaded)) => (policy, loaded, Duration::ZERO),
        Err(err) => {
            tracing::info!(%err, "no complete set of stored lists; downloading before serving");
            let (policy, loaded) = build_policy(&config, Some(&fetcher)).await?;
            let wait = next_refresh(&loaded);
            (policy, loaded, wait)
        }
    };
    let shared: Shared = Arc::new(Mutex::new(RuntimeReport {
        lists_loaded_ts: unix_now(),
        lists_hash: loaded.hash.clone(),
        lists: loaded.reports,
        applied_config_hash: config.hash(),
        last_reload: Some(outcome(Trigger::Startup, started, Ok(()))),
        pending_restart: Vec::new(),
        next_refresh_ts: unix_now() + i64::try_from(refresh_in.as_secs()).unwrap_or(0),
    }));

    let mut pipeline = Pipeline::from_policy(
        policy,
        Cache::with_limits(
            config.cache.max_entries,
            crate::cache::DEFAULT_MAX_BYTES,
            config.cache.serve_stale_secs,
        ),
        Arc::clone(&pool),
        db.writer(),
    );
    if let Some(addr) = shadow {
        tracing::info!(%addr, "shadow mode: mirroring queries to reference resolver");
        pipeline.set_shadow(addr);
    }
    let pipeline = Arc::new(pipeline);
    write_heartbeat(&db, started_ts, &snapshot(&shared))?;
    publish_runtime(&db, &shared).await;

    let server = serve(Arc::clone(&pipeline), &config.server.bind).await?;
    tracing::info!(udp = ?server.udp_addrs, tcp = ?server.tcp_addrs, "serving");

    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel::<Config>(1);
    let refresher = tokio::spawn(
        Refresher {
            pipeline: Arc::clone(&pipeline),
            fetcher,
            db: Arc::clone(&db),
            shared: Arc::clone(&shared),
            started_with: config.clone(),
            current: config,
        }
        .run(reload_rx, refresh_in),
    );

    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut heartbeat = tokio::time::interval(Duration::from_mins(1));
    let mut retention = tokio::time::interval(Duration::from_hours(1));
    heartbeat.tick().await;
    retention.tick().await;
    // Drop count at the previous heartbeat, so each sample reports what
    // was lost since then rather than since start.
    let mut dropped_at_last_sample: u64 = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => match Config::load(config_path) {
                Ok(new) => {
                    if reload_tx.try_send(new).is_err() {
                        tracing::warn!("a reload is already queued; this signal adds nothing");
                    }
                }
                Err(err) => {
                    tracing::error!(%err, "reload refused: the config does not load; nothing changed");
                    shared.lock().expect("runtime report poisoned").last_reload = Some(ReloadOutcome {
                        ts: unix_now(),
                        trigger: Trigger::Signal,
                        ok: false,
                        error: Some(format!("config: {err}")),
                        duration_ms: 0,
                    });
                    publish_runtime(&db, &shared).await;
                }
            },
            _ = heartbeat.tick() => {
                let report = snapshot(&shared);
                if let Err(err) = tokio::task::block_in_place(|| write_heartbeat(&db, started_ts, &report)) {
                    tracing::error!(%err, "heartbeat write failed");
                }
                publish_stats(&db, &pipeline, &report, &mut dropped_at_last_sample);
            }
            _ = retention.tick() => {
                match tokio::task::block_in_place(|| db.retention_sweep(unix_now())) {
                    Ok(deleted) if deleted > 0 => tracing::info!(deleted, "retention sweep"),
                    Ok(_) => {}
                    Err(err) => tracing::error!(%err, "retention sweep failed"),
                }
            }
        }
    }

    tracing::info!("shutting down");
    refresher.abort();
    server.shutdown().await;
    // Drain in-flight queries (bounded) so their log records reach the
    // writer before the final flush.
    let deadline = Instant::now() + DRAIN;
    while pipeline.in_flight() > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::task::block_in_place(|| db.flush());
    Ok(())
}

fn write_heartbeat(db: &Db, started_ts: i64, report: &RuntimeReport) -> Result<(), CoreError> {
    db.write_heartbeat(&crate::db::Heartbeat {
        pid: std::process::id(),
        started_ts,
        updated_ts: unix_now(),
        config_hash: report.applied_config_hash.clone(),
        lists_hash: report.lists_hash.clone(),
    })?;
    Ok(())
}

/// Counters next to the heartbeat, so a degraded daemon is visible from
/// `status` alone.
fn publish_stats(
    db: &Db,
    pipeline: &Pipeline<Arc<UpstreamPool>>,
    report: &RuntimeReport,
    dropped_at_last_sample: &mut u64,
) {
    let health = pipeline.upstream().health();
    if health.consecutive_all_failed > 0 {
        tracing::error!(
            consecutive = health.consecutive_all_failed,
            total = health.all_failed_total,
            "every upstream is failing; the daemon cannot resolve"
        );
    }
    let dropped_total = pipeline.log_events_dropped();
    let dropped_recent = dropped_total.saturating_sub(*dropped_at_last_sample);
    *dropped_at_last_sample = dropped_total;
    if dropped_recent > 0 {
        tracing::warn!(
            dropped_recent,
            dropped_total,
            "query-log events dropped: the writer queue is full"
        );
    }
    let (Ok(upstreams_json), Ok(runtime_json)) = (
        serde_json::to_string(&health),
        serde_json::to_string(report),
    ) else {
        tracing::error!("daemon stats serialization failed");
        return;
    };
    let stats = crate::db::DaemonStats {
        updated_ts: unix_now(),
        log_events_dropped: dropped_total,
        log_events_dropped_recent: dropped_recent,
        upstreams_json,
        runtime_json,
    };
    if let Err(err) = tokio::task::block_in_place(|| db.write_daemon_stats(&stats)) {
        tracing::error!(%err, "daemon stats write failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_with(list: ListReport, loaded_ago: i64, now: i64) -> RuntimeReport {
        RuntimeReport {
            lists_loaded_ts: now - loaded_ago,
            lists: vec![list],
            ..RuntimeReport::default()
        }
    }

    #[test]
    fn healthy_daemon_has_no_reasons() {
        let now = 1_000_000;
        let list = ListReport {
            name: "nsfw".into(),
            origin: lists::ListOrigin::Downloaded,
            rules: 10,
            issues: 0,
            verified_age_secs: Some(0),
        };
        assert_eq!(
            degraded_reasons(&report_with(list, 3600, now), 0, 0, now),
            []
        );
    }

    #[test]
    fn failing_nsfw_list_is_reported_and_goes_stale_after_three_days() {
        // The 2026-10-24 incident: a daily failure with one WARN line.
        let now = 10_000_000;
        let list = ListReport {
            name: "oisd-nsfw".into(),
            origin: lists::ListOrigin::StoredAfterFetchFailure {
                reason: "dns error: 0.0.0.0".into(),
            },
            rules: 10,
            issues: 0,
            verified_age_secs: Some(2 * 86_400),
        };
        let fresh = degraded_reasons(&report_with(list.clone(), 0, now), 0, 0, now);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].reason, "list_fetch_failed");
        // A day later without a successful load: also stale.
        let later = degraded_reasons(&report_with(list, 86_401, now), 0, 0, now);
        let reasons: Vec<_> = later.iter().map(|d| d.reason.as_str()).collect();
        assert_eq!(reasons, ["list_fetch_failed", "list_stale"]);
    }

    #[test]
    fn failed_reload_and_restart_only_changes_are_reasons() {
        let report = RuntimeReport {
            last_reload: Some(ReloadOutcome {
                ts: 0,
                trigger: Trigger::Signal,
                ok: false,
                error: Some("config: bad".into()),
                duration_ms: 0,
            }),
            pending_restart: vec!["upstreams".into()],
            ..RuntimeReport::default()
        };
        let reasons: Vec<_> = degraded_reasons(&report, 3, 1, 0)
            .into_iter()
            .map(|d| d.reason)
            .collect();
        assert_eq!(
            reasons,
            [
                "cannot_resolve",
                "log_events_dropped",
                "reload_failed",
                "pending_restart"
            ]
        );
    }
}
