//! `SQLite` persistence: query log, stats, heartbeat, shadow divergences.
//!
//! Single-writer design: one dedicated writer thread owns a connection;
//! the async side sends [`LogEvent`]s through a channel and never blocks
//! on disk. Reads (CLI in phase 3, stats) open their own connection.
//! WAL mode, `synchronous=NORMAL`.
//!
//! Retention: [`crate::consts::LOG_RETENTION_SECS`], swept hourly by the
//! daemon calling [`Db::retention_sweep`].

#![expect(
    clippy::module_name_repetitions,
    reason = "DbError / DbWriter are the natural public names"
)]

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rusqlite::{Connection, params};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// Errors from database operations.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Database file could not be opened or created.
    #[error("cannot open database {path}: {source}")]
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    /// A SQL statement failed.
    #[error("sql: {0}")]
    Sql(#[from] rusqlite::Error),
    /// The on-disk schema version is newer than this binary understands.
    #[error("database schema v{found} is newer than supported v{supported}")]
    SchemaTooNew { found: u32, supported: u32 },
}

/// What the filter decided for a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    Allowed,
    Blocked,
    Excepted,
}

impl VerdictKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Excepted => "excepted",
        }
    }

    fn from_db(s: &str) -> Result<Self, DbError> {
        match s {
            "allowed" => Ok(Self::Allowed),
            "blocked" => Ok(Self::Blocked),
            "excepted" => Ok(Self::Excepted),
            other => Err(DbError::Sql(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::from(format!("unknown verdict: {other}")),
            ))),
        }
    }
}

/// Where the answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseSource {
    /// Synthesized locally (NXDOMAIN block, REFUSED, safe-search CNAME).
    Synth,
    Cache,
    /// Served stale from cache while refreshing.
    Stale,
    Upstream,
    /// Upstream failed and nothing cached: SERVFAIL to the client.
    Failed,
}

impl ResponseSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Synth => "synth",
            Self::Cache => "cache",
            Self::Stale => "stale",
            Self::Upstream => "upstream",
            Self::Failed => "failed",
        }
    }

    fn from_db(s: &str) -> Result<Self, DbError> {
        match s {
            "synth" => Ok(Self::Synth),
            "cache" => Ok(Self::Cache),
            "stale" => Ok(Self::Stale),
            "upstream" => Ok(Self::Upstream),
            "failed" => Ok(Self::Failed),
            other => Err(DbError::Sql(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::from(format!("unknown source: {other}")),
            ))),
        }
    }
}

/// One row for the query log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRecord {
    /// Unix seconds.
    pub ts: i64,
    pub client: IpAddr,
    pub qname: String,
    pub qtype: u16,
    pub verdict: VerdictKind,
    /// Rule text + list index when verdict is Blocked/Excepted.
    pub rule: Option<String>,
    pub list: Option<usize>,
    pub source: ResponseSource,
    /// DNS RCODE of the answer sent to the client.
    pub rcode: u16,
    pub duration_us: u32,
}

/// Events accepted by the writer thread.
#[derive(Debug, Clone)]
pub enum LogEvent {
    Query(QueryRecord),
    /// Phase 4: a shadow-mode divergence.
    Divergence {
        ts: i64,
        qname: String,
        qtype: u16,
        ours: String,
        theirs: String,
        /// `expected` for known-benign classes (NXDOMAIN vs 0.0.0.0).
        class: String,
    },
}

/// Internal message type wrapping public events and control signals.
pub(crate) enum Msg {
    Event(LogEvent),
    Flush(oneshot::Sender<()>),
}

// Msg is not Debug because oneshot::Sender is not Debug, but we need
// DbWriter to be Debug. We implement Debug manually for DbWriter.

const WRITER_QUEUE_CAPACITY: usize = 4096;
const BATCH_SIZE: usize = 256;

/// Cheap-to-clone handle for enqueueing log events (never blocks on disk;
/// if the writer's queue is full the event is DROPPED and a counter
/// incremented — logging must not stall DNS answering).
#[derive(Clone)]
pub struct DbWriter {
    pub(crate) sender: mpsc::Sender<Msg>,
    pub(crate) drops: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for DbWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbWriter").finish_non_exhaustive()
    }
}

impl DbWriter {
    /// Enqueue without blocking; returns false if the event was dropped.
    ///
    /// When the writer queue is full the event is silently dropped and
    /// `false` is returned. The caller should count drops for monitoring.
    #[must_use]
    pub fn log(&self, event: LogEvent) -> bool {
        let ok = self.sender.try_send(Msg::Event(event)).is_ok();
        if !ok {
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        ok
    }

    /// Number of events dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.drops.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Daemon heartbeat row (single row, upserted periodically).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    pub pid: u32,
    /// Unix seconds.
    pub started_ts: i64,
    pub updated_ts: i64,
    pub config_hash: String,
    pub lists_hash: String,
}

/// Runtime counters the daemon publishes for `status` (single row,
/// upserted alongside the heartbeat).
///
/// These exist so a degraded daemon is visible without reading the
/// journal: the 2026-08-20 shadow outage — every upstream dead, seven
/// hours of SERVFAIL — would have shown up here on the first sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStats {
    /// Unix seconds.
    pub updated_ts: i64,
    /// Query-log events dropped because the writer queue was full,
    /// since the daemon started. Diagnostic only — a lifetime total can
    /// never go back down, so it must not drive an alert.
    pub log_events_dropped: u64,
    /// Events dropped since the previous sample. This is the alertable
    /// signal: non-zero means the log is losing events *now*.
    pub log_events_dropped_recent: u64,
    /// Per-upstream health, serialized from `UpstreamPool::health()`.
    pub upstreams_json: String,
}

/// Aggregate stats over a time window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub total: u64,
    pub blocked: u64,
    pub excepted: u64,
    pub cache_hits: u64,
    pub upstream_failures: u64,
    /// (qname, count), most-queried first.
    pub top_queried: Vec<(String, u64)>,
    /// (qname, count), most-blocked first.
    pub top_blocked: Vec<(String, u64)>,
}

/// One shadow-mode divergence row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceRow {
    pub ts: i64,
    pub qname: String,
    pub qtype: u16,
    pub ours: String,
    pub theirs: String,
    pub class: String,
}

/// Open database with schema management and a running writer thread.
pub struct Db {
    pub(crate) path: PathBuf,
    tx: mpsc::Sender<Msg>,
    drops: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// On-disk schema version.
///
/// v2 added `daemon_stats.log_events_dropped_recent`; see
/// [`migrate_schema`].
pub const SCHEMA_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------------------

fn init_connection(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // Writer thread, heartbeat, and retention sweep use separate write
    // connections; wait instead of failing with SQLITE_BUSY.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

fn create_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            client TEXT NOT NULL,
            qname TEXT NOT NULL,
            qtype INTEGER NOT NULL,
            verdict TEXT NOT NULL CHECK(verdict IN ('allowed','blocked','excepted')),
            rule TEXT,
            list INTEGER,
            source TEXT NOT NULL,
            rcode INTEGER NOT NULL,
            duration_us INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);

        CREATE TABLE IF NOT EXISTS heartbeat (
            id INTEGER PRIMARY KEY CHECK (id=1),
            pid INTEGER,
            started_ts INTEGER,
            updated_ts INTEGER,
            config_hash TEXT,
            lists_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS daemon_stats (
            id INTEGER PRIMARY KEY CHECK (id=1),
            updated_ts INTEGER NOT NULL,
            log_events_dropped INTEGER NOT NULL,
            log_events_dropped_recent INTEGER NOT NULL DEFAULT 0,
            upstreams_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS divergences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            qname TEXT NOT NULL,
            qtype INTEGER NOT NULL,
            ours TEXT NOT NULL,
            theirs TEXT NOT NULL,
            class TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_divergences_ts ON divergences(ts);",
    )?;
    Ok(())
}

/// Bring an older database up to [`SCHEMA_VERSION`].
///
/// `CREATE TABLE IF NOT EXISTS` cannot add a column to a table that
/// already exists, so upgrades need explicit steps. Each one is
/// idempotent and fails loudly: a migration that cannot run aborts the
/// open rather than leaving a half-shaped database behind.
fn migrate_schema(conn: &Connection, from: u32) -> Result<(), DbError> {
    if from < 2 {
        // v1 -> v2: per-sample drop count, so `status` can distinguish
        // "dropping events now" from "dropped one event hours ago".
        let has_column = conn
            .prepare("SELECT * FROM daemon_stats LIMIT 0")?
            .column_names()
            .contains(&"log_events_dropped_recent");
        if !has_column {
            conn.execute(
                "ALTER TABLE daemon_stats \
                 ADD COLUMN log_events_dropped_recent INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
    }
    Ok(())
}

fn ensure_schema_version(conn: &Connection) -> Result<(), DbError> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .ok();

    if let Some(v) = existing {
        let found: u32 = v.parse().unwrap_or(0);
        if found > SCHEMA_VERSION {
            return Err(DbError::SchemaTooNew {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found < SCHEMA_VERSION {
            migrate_schema(conn, found)?;
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION.to_string()],
            )?;
        }
    } else {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Read connection
// ---------------------------------------------------------------------------

fn open_read_conn(path: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| DbError::Open {
        path: path.to_path_buf(),
        source: e,
    })?;
    init_connection(&conn)?;
    Ok(conn)
}

fn open_write_conn(path: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open(path).map_err(|e| DbError::Open {
        path: path.to_path_buf(),
        source: e,
    })?;
    init_connection(&conn)?;
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Writer thread
// ---------------------------------------------------------------------------

fn writer_loop(path: &Path, rx: &mut mpsc::Receiver<Msg>) {
    let conn = match Connection::open(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("writer thread cannot open db: {e}");
            return;
        }
    };
    if let Err(e) = init_connection(&conn) {
        tracing::error!("writer thread pragma setup failed: {e}");
        return;
    }

    loop {
        let Some(first) = rx.blocking_recv() else {
            return; // channel closed
        };

        let mut batch: Vec<Msg> = Vec::with_capacity(BATCH_SIZE);
        batch.push(first);
        while batch.len() < BATCH_SIZE {
            match rx.try_recv() {
                Ok(msg) => batch.push(msg),
                Err(_) => break,
            }
        }

        if let Err((e, acks)) = process_batch(&conn, batch) {
            // The transaction rolled back: these records are LOST. Say so
            // loudly, and release flush waiters — flush is "writer caught
            // up", not a durability proof after an I/O failure.
            tracing::error!("writer batch failed, records lost: {e}");
            for ack in acks {
                let _ = ack.send(());
            }
        }
    }
}

/// Process a batch: insert events in a transaction, then ack flushes
/// after commit so callers know data is durable.
fn process_batch(
    conn: &Connection,
    batch: Vec<Msg>,
) -> Result<(), (rusqlite::Error, Vec<oneshot::Sender<()>>)> {
    let mut flush_acks: Vec<oneshot::Sender<()>> = Vec::new();
    match process_batch_inner(conn, batch, &mut flush_acks) {
        Ok(()) => {
            // Ack after commit so data is guaranteed on disk.
            for ack in flush_acks {
                let _ = ack.send(());
            }
            Ok(())
        }
        Err(e) => Err((e, flush_acks)),
    }
}

fn process_batch_inner(
    conn: &Connection,
    batch: Vec<Msg>,
    flush_acks: &mut Vec<oneshot::Sender<()>>,
) -> Result<(), rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;

    for msg in batch {
        match msg {
            Msg::Event(LogEvent::Query(q)) => {
                tx.execute(
                    "INSERT INTO queries (ts, client, qname, qtype, verdict, rule, list, source, rcode, duration_us) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        q.ts,
                        q.client.to_string(),
                        q.qname,
                        i64::from(q.qtype),
                        q.verdict.as_str(),
                        q.rule,
                        q.list.map(|l| i64::try_from(l).unwrap_or(i64::MAX)),
                        q.source.as_str(),
                        i64::from(q.rcode),
                        i64::from(q.duration_us),
                    ],
                )?;
            }
            Msg::Event(LogEvent::Divergence {
                ts,
                qname,
                qtype,
                ours,
                theirs,
                class,
            }) => {
                tx.execute(
                    "INSERT INTO divergences (ts, qname, qtype, ours, theirs, class) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![ts, qname, i64::from(qtype), ours, theirs, class],
                )?;
            }
            Msg::Flush(ack) => {
                flush_acks.push(ack);
            }
        }
    }

    tx.commit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Row deserialization helper
// ---------------------------------------------------------------------------

fn row_to_query_record(row: &rusqlite::Row<'_>) -> Result<QueryRecord, DbError> {
    let client_str: String = row.get(1)?;
    let qtype_i64: i64 = row.get(3)?;
    let verdict_str: String = row.get(4)?;
    let list_val: Option<i64> = row.get(6)?;
    let source_str: String = row.get(7)?;
    let rcode_i64: i64 = row.get(8)?;
    let duration_i64: i64 = row.get(9)?;

    let client = IpAddr::from_str(&client_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let qtype = u16::try_from(qtype_i64).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Integer, Box::new(e))
    })?;
    let verdict = VerdictKind::from_db(&verdict_str)?;
    let list = list_val.map(|l| usize::try_from(l).unwrap_or(usize::MAX));
    let source = ResponseSource::from_db(&source_str)?;
    let rcode = u16::try_from(rcode_i64).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Integer, Box::new(e))
    })?;
    let duration_us = u32::try_from(duration_i64).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Integer, Box::new(e))
    })?;

    Ok(QueryRecord {
        ts: row.get(0)?,
        client,
        qname: row.get(2)?,
        qtype,
        verdict,
        rule: row.get(5)?,
        list,
        source,
        rcode,
        duration_us,
    })
}

// ---------------------------------------------------------------------------
// Db impl
// ---------------------------------------------------------------------------

impl Db {
    /// Open (creating if absent), migrate schema, start the writer thread.
    /// The parent directory must exist — creating it is the installer's
    /// job, not ours (fail loud).
    ///
    /// # Errors
    ///
    /// Returns [`DbError::Open`] if the parent directory does not exist or
    /// the file cannot be created. Returns [`DbError::SchemaTooNew`] if the
    /// database was written by a newer version of sumidero.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        Self::open_with_queue_capacity(path, WRITER_QUEUE_CAPACITY)
    }

    /// Like [`Db::open`] with an explicit writer-queue capacity. Exposed so
    /// tests can pin the queue-full drop behavior with a tiny queue.
    #[doc(hidden)]
    pub fn open_with_queue_capacity(path: &Path, capacity: usize) -> Result<Self, DbError> {
        let conn = Connection::open(path).map_err(|e| DbError::Open {
            path: path.to_path_buf(),
            source: e,
        })?;
        init_connection(&conn)?;
        create_schema(&conn)?;
        ensure_schema_version(&conn)?;
        drop(conn);

        let (tx, mut rx) = mpsc::channel::<Msg>(capacity);

        let writer_path = path.to_path_buf();
        std::thread::Builder::new()
            .name("sumidero-db-writer".into())
            .spawn(move || writer_loop(&writer_path, &mut rx))
            .map_err(|e| DbError::Open {
                path: path.to_path_buf(),
                source: rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                    Some(format!("spawn writer thread: {e}")),
                ),
            })?;

        Ok(Self {
            path: path.to_path_buf(),
            tx,
            drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Handle for the daemon's hot path.
    #[must_use]
    pub fn writer(&self) -> DbWriter {
        DbWriter {
            sender: self.tx.clone(),
            drops: std::sync::Arc::clone(&self.drops),
        }
    }

    /// Upsert the single heartbeat row.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] on SQL failure.
    pub fn write_heartbeat(&self, hb: &Heartbeat) -> Result<(), DbError> {
        let conn = open_write_conn(&self.path)?;
        conn.execute(
            "INSERT OR REPLACE INTO heartbeat (id, pid, started_ts, updated_ts, config_hash, lists_hash) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                i64::from(hb.pid),
                hb.started_ts,
                hb.updated_ts,
                hb.config_hash,
                hb.lists_hash,
            ],
        )?;
        Ok(())
    }

    /// Read the heartbeat row, if present.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] on SQL failure.
    pub fn heartbeat(&self) -> Result<Option<Heartbeat>, DbError> {
        let conn = open_read_conn(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT pid, started_ts, updated_ts, config_hash, lists_hash FROM heartbeat WHERE id = 1",
        )?;
        let result = stmt.query_row([], |row| {
            let pid_i64: i64 = row.get(0)?;
            Ok(Heartbeat {
                pid: u32::try_from(pid_i64).unwrap_or(0),
                started_ts: row.get(1)?,
                updated_ts: row.get(2)?,
                config_hash: row.get(3)?,
                lists_hash: row.get(4)?,
            })
        });
        match result {
            Ok(hb) => Ok(Some(hb)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DbError::Sql(e)),
        }
    }

    /// Upsert the single daemon-stats row.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] on SQL failure.
    pub fn write_daemon_stats(&self, stats: &DaemonStats) -> Result<(), DbError> {
        let conn = open_write_conn(&self.path)?;
        conn.execute(
            "INSERT OR REPLACE INTO daemon_stats \
             (id, updated_ts, log_events_dropped, log_events_dropped_recent, upstreams_json) \
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                stats.updated_ts,
                stats.log_events_dropped.cast_signed(),
                stats.log_events_dropped_recent.cast_signed(),
                stats.upstreams_json,
            ],
        )?;
        Ok(())
    }

    /// Read the daemon-stats row, if the daemon has published one.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] on SQL failure.
    pub fn daemon_stats(&self) -> Result<Option<DaemonStats>, DbError> {
        let conn = open_read_conn(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT updated_ts, log_events_dropped, log_events_dropped_recent, upstreams_json \
             FROM daemon_stats WHERE id = 1",
        )?;
        let result = stmt.query_row([], |row| {
            let dropped: i64 = row.get(1)?;
            let recent: i64 = row.get(2)?;
            Ok(DaemonStats {
                updated_ts: row.get(0)?,
                log_events_dropped: dropped.cast_unsigned(),
                log_events_dropped_recent: recent.cast_unsigned(),
                upstreams_json: row.get(3)?,
            })
        });
        match result {
            Ok(stats) => Ok(Some(stats)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DbError::Sql(e)),
        }
    }

    /// Most recent query rows, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] on SQL failure.
    pub fn recent_queries(&self, limit: u32) -> Result<Vec<QueryRecord>, DbError> {
        let conn = open_read_conn(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT ts, client, qname, qtype, verdict, rule, list, source, rcode, duration_us \
             FROM queries ORDER BY ts DESC, id DESC LIMIT ?1",
        )?;

        let mut result = Vec::new();
        let mut rows = stmt.query(params![i64::from(limit)])?;
        while let Some(row) = rows.next()? {
            result.push(row_to_query_record(row)?);
        }
        Ok(result)
    }

    /// Aggregates for `[since_ts, now]`.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] on SQL failure.
    pub fn stats(&self, since_ts: i64) -> Result<Stats, DbError> {
        let conn = open_read_conn(&self.path)?;

        let count = |sql: &str| -> Result<u64, DbError> {
            let n: i64 = conn.query_row(sql, params![since_ts], |row| row.get(0))?;
            Ok(u64::try_from(n).unwrap_or(0))
        };

        let total = count("SELECT COUNT(*) FROM queries WHERE ts >= ?1")?;
        let blocked = count("SELECT COUNT(*) FROM queries WHERE ts >= ?1 AND verdict = 'blocked'")?;
        let excepted =
            count("SELECT COUNT(*) FROM queries WHERE ts >= ?1 AND verdict = 'excepted'")?;
        let cache_hits = count("SELECT COUNT(*) FROM queries WHERE ts >= ?1 AND source = 'cache'")?;
        let upstream_failures =
            count("SELECT COUNT(*) FROM queries WHERE ts >= ?1 AND source = 'failed'")?;

        let top_list = |sql: &str| -> Result<Vec<(String, u64)>, DbError> {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt
                .query_map(params![since_ts], |row| {
                    let name: String = row.get(0)?;
                    let cnt: i64 = row.get(1)?;
                    Ok((name, u64::try_from(cnt).unwrap_or(0)))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        };

        let top_queried = top_list(
            "SELECT qname, COUNT(*) as cnt FROM queries WHERE ts >= ?1 \
             GROUP BY qname ORDER BY cnt DESC LIMIT 10",
        )?;
        let top_blocked = top_list(
            "SELECT qname, COUNT(*) as cnt FROM queries WHERE ts >= ?1 AND verdict = 'blocked' \
             GROUP BY qname ORDER BY cnt DESC LIMIT 10",
        )?;

        Ok(Stats {
            total,
            blocked,
            excepted,
            cache_hits,
            upstream_failures,
            top_queried,
            top_blocked,
        })
    }

    /// Recent divergences, newest first.
    pub fn recent_divergences(&self, limit: u32) -> Result<Vec<DivergenceRow>, DbError> {
        let conn = open_read_conn(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT ts, qname, qtype, ours, theirs, class FROM divergences \
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map([i64::from(limit)], |r| {
                Ok(DivergenceRow {
                    ts: r.get(0)?,
                    qname: r.get(1)?,
                    qtype: u16::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                    ours: r.get(3)?,
                    theirs: r.get(4)?,
                    class: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Divergence counts per class since `since_ts`, largest first.
    pub fn divergence_summary(&self, since_ts: i64) -> Result<Vec<(String, u64)>, DbError> {
        let conn = open_read_conn(&self.path)?;
        let mut stmt = conn.prepare(
            "SELECT class, COUNT(*) FROM divergences WHERE ts >= ?1 \
             GROUP BY class ORDER BY COUNT(*) DESC",
        )?;
        let rows = stmt
            .query_map([since_ts], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.unsigned_abs()))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete rows older than the retention window; returns rows deleted.
    ///
    /// Deletes from both `queries` and `divergences` tables.
    ///
    /// # Errors
    ///
    /// Returns [`DbError`] on SQL failure.
    pub fn retention_sweep(&self, now_ts: i64) -> Result<u64, DbError> {
        let cutoff = now_ts - crate::consts::LOG_RETENTION_SECS;
        let conn = open_write_conn(&self.path)?;

        let q_deleted = conn.execute("DELETE FROM queries WHERE ts < ?1", params![cutoff])?;
        let d_deleted = conn.execute("DELETE FROM divergences WHERE ts < ?1", params![cutoff])?;

        Ok(u64::try_from(q_deleted + d_deleted).unwrap_or(0))
    }

    /// Block until every event enqueued so far is on disk (tests, shutdown).
    ///
    /// Safe to call from both sync code and within a tokio runtime (the
    /// blocking wait is offloaded to a dedicated thread when a runtime is
    /// active).
    pub fn flush(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();

        if self.tx.try_send(Msg::Flush(ack_tx)).is_ok() {
            // Wait for the writer to ack.
            Self::blocking_wait(ack_rx);
        } else {
            // Queue full — use a thread for the blocking send, then wait.
            let tx = self.tx.clone();
            let (retry_tx, retry_rx) = oneshot::channel();
            std::thread::spawn(move || {
                let _ = tx.blocking_send(Msg::Flush(retry_tx));
            });
            Self::blocking_wait(retry_rx);
        }
    }

    /// Wait on a oneshot receiver, handling both sync and async contexts.
    fn blocking_wait(rx: oneshot::Receiver<()>) {
        // If we're inside a tokio runtime, blocking_recv would panic.
        // Offload to a std thread in that case.
        if tokio::runtime::Handle::try_current().is_ok() {
            let handle = std::thread::spawn(move || {
                let _ = rx.blocking_recv();
            });
            let _ = handle.join();
        } else {
            let _ = rx.blocking_recv();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tempfile::TempDir;

    fn test_db() -> (TempDir, Db) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = Db::open(&path).unwrap();
        (dir, db)
    }

    fn sample_query(ts: i64) -> QueryRecord {
        QueryRecord {
            ts,
            client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            qname: "example.com".to_string(),
            qtype: 1,
            verdict: VerdictKind::Allowed,
            rule: None,
            list: None,
            source: ResponseSource::Upstream,
            rcode: 0,
            duration_us: 1500,
        }
    }

    // -- Schema --

    #[test]
    fn open_creates_schema_and_version() {
        let (_dir, db) = test_db();
        let conn = open_read_conn(&db.path).unwrap();

        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(tables.contains(&"queries".to_string()));
        assert!(tables.contains(&"heartbeat".to_string()));
        assert!(tables.contains(&"divergences".to_string()));
        assert!(tables.contains(&"meta".to_string()));
    }

    #[test]
    fn newer_version_refuses() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");

        {
            let conn = Connection::open(&path).unwrap();
            init_connection(&conn).unwrap();
            create_schema(&conn).unwrap();
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '99')",
                [],
            )
            .unwrap();
        }

        let err = Db::open(&path).unwrap_err();
        match err {
            DbError::SchemaTooNew { found, supported } => {
                assert_eq!(found, 99);
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected SchemaTooNew, got: {other}"),
        }
    }

    #[test]
    fn v1_database_migrates_to_current_schema() {
        // A database written before daemon_stats gained its per-sample
        // drop column must open, not fail — the shadow deployment has
        // one on disk right now.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");

        {
            let conn = Connection::open(&path).unwrap();
            init_connection(&conn).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE daemon_stats (
                     id INTEGER PRIMARY KEY CHECK (id=1),
                     updated_ts INTEGER NOT NULL,
                     log_events_dropped INTEGER NOT NULL,
                     upstreams_json TEXT NOT NULL
                 );
                 INSERT INTO daemon_stats (id, updated_ts, log_events_dropped, upstreams_json)
                     VALUES (1, 1700000000, 7, '{\"upstreams\":[]}');
                 INSERT INTO meta (key, value) VALUES ('schema_version', '1');",
            )
            .unwrap();
        }

        let db = Db::open(&path).unwrap();

        // The pre-existing row survives; the new column defaults to 0,
        // so an old row never reads as "dropping events right now".
        let stats = db.daemon_stats().unwrap().unwrap();
        assert_eq!(stats.log_events_dropped, 7);
        assert_eq!(stats.log_events_dropped_recent, 0);

        let conn = open_read_conn(&db.path).unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());

        // And the migrated database is fully writable afterwards.
        db.write_daemon_stats(&DaemonStats {
            updated_ts: 1_700_000_060,
            log_events_dropped: 9,
            log_events_dropped_recent: 2,
            upstreams_json: "{\"upstreams\":[]}".into(),
        })
        .unwrap();
        let stats = db.daemon_stats().unwrap().unwrap();
        assert_eq!(stats.log_events_dropped_recent, 2);
    }

    #[test]
    fn open_missing_parent_dir_fails() {
        let path = PathBuf::from("/nonexistent/parent/dir/test.db");
        let err = Db::open(&path).unwrap_err();
        assert!(
            matches!(err, DbError::Open { .. }),
            "expected Open error, got: {err}"
        );
    }

    // -- Roundtrip --

    #[test]
    fn log_flush_recent_queries_roundtrip_ipv6() {
        let (_dir, db) = test_db();
        let writer = db.writer();

        let q = QueryRecord {
            ts: 1_700_000_000,
            client: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            qname: "ipv6.example.com".to_string(),
            qtype: 28,
            verdict: VerdictKind::Blocked,
            rule: Some("||ipv6.example.com^".to_string()),
            list: Some(3),
            source: ResponseSource::Synth,
            rcode: 3,
            duration_us: 42,
        };

        assert!(writer.log(LogEvent::Query(q.clone())));
        db.flush();

        let rows = db.recent_queries(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], q);
    }

    #[test]
    fn recent_queries_newest_first() {
        let (_dir, db) = test_db();
        let writer = db.writer();

        for ts in [100, 300, 200] {
            assert!(writer.log(LogEvent::Query(sample_query(ts))));
        }
        db.flush();

        let rows = db.recent_queries(10).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].ts, 300);
        assert_eq!(rows[1].ts, 200);
        assert_eq!(rows[2].ts, 100);
    }

    // -- Golden string mapping --

    #[test]
    fn verdict_strings_stable() {
        assert_eq!(VerdictKind::Allowed.as_str(), "allowed");
        assert_eq!(VerdictKind::Blocked.as_str(), "blocked");
        assert_eq!(VerdictKind::Excepted.as_str(), "excepted");

        for v in [
            VerdictKind::Allowed,
            VerdictKind::Blocked,
            VerdictKind::Excepted,
        ] {
            assert_eq!(VerdictKind::from_db(v.as_str()).unwrap(), v);
        }
    }

    #[test]
    fn source_strings_stable() {
        assert_eq!(ResponseSource::Synth.as_str(), "synth");
        assert_eq!(ResponseSource::Cache.as_str(), "cache");
        assert_eq!(ResponseSource::Stale.as_str(), "stale");
        assert_eq!(ResponseSource::Upstream.as_str(), "upstream");
        assert_eq!(ResponseSource::Failed.as_str(), "failed");

        for s in [
            ResponseSource::Synth,
            ResponseSource::Cache,
            ResponseSource::Stale,
            ResponseSource::Upstream,
            ResponseSource::Failed,
        ] {
            assert_eq!(ResponseSource::from_db(s.as_str()).unwrap(), s);
        }
    }

    // -- Stats --

    #[test]
    fn stats_aggregates_correct() {
        let (_dir, db) = test_db();
        let writer = db.writer();

        let mut q = sample_query(1000);

        // 3 allowed from upstream (a.com x2, b.com x1)
        for name in ["a.com", "b.com", "a.com"] {
            q.qname = name.to_string();
            q.verdict = VerdictKind::Allowed;
            q.source = ResponseSource::Upstream;
            assert!(writer.log(LogEvent::Query(q.clone())));
        }
        // 2 blocked (bad.com x2)
        for name in ["bad.com", "bad.com"] {
            q.qname = name.to_string();
            q.verdict = VerdictKind::Blocked;
            q.source = ResponseSource::Synth;
            assert!(writer.log(LogEvent::Query(q.clone())));
        }
        // 1 excepted
        q.qname = "ok.com".to_string();
        q.verdict = VerdictKind::Excepted;
        q.source = ResponseSource::Upstream;
        assert!(writer.log(LogEvent::Query(q.clone())));
        // 1 cache hit
        q.qname = "cached.com".to_string();
        q.verdict = VerdictKind::Allowed;
        q.source = ResponseSource::Cache;
        assert!(writer.log(LogEvent::Query(q.clone())));
        // 1 failed
        q.qname = "fail.com".to_string();
        q.verdict = VerdictKind::Allowed;
        q.source = ResponseSource::Failed;
        assert!(writer.log(LogEvent::Query(q.clone())));

        db.flush();

        let stats = db.stats(0).unwrap();
        assert_eq!(stats.total, 8);
        assert_eq!(stats.blocked, 2);
        assert_eq!(stats.excepted, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.upstream_failures, 1);

        // top_queried: first entry has count >= 2
        assert!(!stats.top_queried.is_empty());
        assert_eq!(stats.top_queried[0].1, 2);

        // top_blocked: bad.com = 2
        assert_eq!(stats.top_blocked.len(), 1);
        assert_eq!(stats.top_blocked[0], ("bad.com".to_string(), 2));
    }

    // -- Retention sweep --

    #[test]
    fn retention_sweep_deletes_only_old_rows() {
        let (_dir, db) = test_db();
        let writer = db.writer();

        let now = 1_000_000;
        let old_ts = now - crate::consts::LOG_RETENTION_SECS - 1;
        let recent_ts = now - 100;

        assert!(writer.log(LogEvent::Query(sample_query(old_ts))));
        assert!(writer.log(LogEvent::Query(sample_query(recent_ts))));
        assert!(writer.log(LogEvent::Divergence {
            ts: old_ts,
            qname: "div.com".into(),
            qtype: 1,
            ours: "NXDOMAIN".into(),
            theirs: "0.0.0.0".into(),
            class: "expected".into(),
        }));
        assert!(writer.log(LogEvent::Divergence {
            ts: recent_ts,
            qname: "div2.com".into(),
            qtype: 1,
            ours: "NXDOMAIN".into(),
            theirs: "0.0.0.0".into(),
            class: "expected".into(),
        }));

        db.flush();

        let deleted = db.retention_sweep(now).unwrap();
        assert_eq!(deleted, 2);

        let rows = db.recent_queries(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ts, recent_ts);

        // recent divergence survives
        let conn = open_read_conn(&db.path).unwrap();
        let div_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM divergences", [], |r| r.get(0))
            .unwrap();
        assert_eq!(div_count, 1);
    }

    // -- Daemon stats --

    #[test]
    fn daemon_stats_roundtrip_and_upsert() {
        let (_dir, db) = test_db();
        assert_eq!(db.daemon_stats().unwrap(), None);

        let first = DaemonStats {
            updated_ts: 1_700_000_000,
            log_events_dropped: 0,
            log_events_dropped_recent: 0,
            upstreams_json: r#"[{"url":"https://dns.google/dns-query","connected":true}]"#.into(),
        };
        db.write_daemon_stats(&first).unwrap();
        assert_eq!(db.daemon_stats().unwrap(), Some(first));

        let second = DaemonStats {
            updated_ts: 1_700_000_060,
            log_events_dropped: 42,
            log_events_dropped_recent: 42,
            upstreams_json: r#"[{"url":"https://dns.google/dns-query","connected":false}]"#.into(),
        };
        db.write_daemon_stats(&second).unwrap();
        assert_eq!(db.daemon_stats().unwrap(), Some(second));
    }

    // -- Heartbeat --

    #[test]
    fn heartbeat_roundtrip_and_upsert() {
        let (_dir, db) = test_db();

        assert_eq!(db.heartbeat().unwrap(), None);

        let hb1 = Heartbeat {
            pid: 1234,
            started_ts: 1_000_000,
            updated_ts: 1_000_100,
            config_hash: "abc123".to_string(),
            lists_hash: "def456".to_string(),
        };
        db.write_heartbeat(&hb1).unwrap();
        assert_eq!(db.heartbeat().unwrap(), Some(hb1));

        let hb2 = Heartbeat {
            pid: 5678,
            started_ts: 2_000_000,
            updated_ts: 2_000_200,
            config_hash: "xyz789".to_string(),
            lists_hash: "uvw012".to_string(),
        };
        db.write_heartbeat(&hb2).unwrap();
        let read = db.heartbeat().unwrap().unwrap();
        assert_eq!(read, hb2);
        assert_ne!(read.pid, 1234);
    }

    // -- Log returns true --

    #[test]
    fn log_returns_true_normally() {
        let (_dir, db) = test_db();
        let writer = db.writer();
        // The drop path: when the internal channel is full, log() returns
        // false and the event is dropped. With a capacity of 4096 and an
        // active writer thread this is hard to trigger deterministically
        // without a test-only small-capacity constructor. We assert the
        // normal path returns true.
        assert!(writer.log(LogEvent::Query(sample_query(1000))));
        db.flush();
    }

    // -- Concurrent writers --

    #[tokio::test]
    async fn concurrent_writers_all_rows_land() {
        let (_dir, db) = test_db();
        let w1 = db.writer();
        let w2 = db.writer();

        let count_per_task: i64 = 50;

        let h1 = tokio::spawn(async move {
            for i in 0..count_per_task {
                let mut q = sample_query(1000 + i);
                q.qname = format!("task1-{i}.com");
                let _ = w1.log(LogEvent::Query(q));
            }
        });
        let h2 = tokio::spawn(async move {
            for i in 0..count_per_task {
                let mut q = sample_query(2000 + i);
                q.qname = format!("task2-{i}.com");
                let _ = w2.log(LogEvent::Query(q));
            }
        });

        h1.await.unwrap();
        h2.await.unwrap();
        db.flush();

        let rows = db.recent_queries(200).unwrap();
        assert_eq!(rows.len(), usize::try_from(count_per_task * 2).unwrap());
    }

    // -- Divergence --

    #[test]
    fn divergence_stored_and_swept() {
        let (_dir, db) = test_db();
        let writer = db.writer();

        assert!(writer.log(LogEvent::Divergence {
            ts: 5000,
            qname: "test.com".into(),
            qtype: 1,
            ours: "NXDOMAIN".into(),
            theirs: "0.0.0.0".into(),
            class: "expected".into(),
        }));
        db.flush();

        let conn = open_read_conn(&db.path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM divergences", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn retention_sweep_keeps_row_exactly_at_cutoff() {
        let (_tmp, db) = test_db();
        let now = 2_000_000_000i64;
        let cutoff = now - crate::consts::LOG_RETENTION_SECS;
        let w = db.writer();
        assert!(w.log(LogEvent::Query(sample_query(cutoff)))); // kept: DELETE uses <
        assert!(w.log(LogEvent::Query(sample_query(cutoff - 1)))); // deleted
        db.flush();
        let deleted = db.retention_sweep(now).unwrap();
        assert_eq!(deleted, 1);
        let rows = db.recent_queries(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ts, cutoff);
    }

    #[tokio::test]
    async fn queue_full_drops_and_counts() {
        // Capacity-1 queue with the writer stalled behind a long batch is
        // racy to arrange; instead pin the drop accounting directly: fill
        // a tiny channel whose receiver is never drained.
        let (tx, _rx) = tokio::sync::mpsc::channel::<Msg>(1);
        let writer = DbWriter {
            sender: tx,
            drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        };
        assert!(writer.log(LogEvent::Query(sample_query(1))));
        assert!(!writer.log(LogEvent::Query(sample_query(2))), "queue full");
        assert!(!writer.log(LogEvent::Query(sample_query(3))));
        assert_eq!(writer.dropped(), 2);
    }

    #[test]
    fn divergence_read_apis() {
        let (_tmp, db) = test_db();
        let w = db.writer();
        for (q, class) in [
            ("a.test", "expected"),
            ("b.test", "expected"),
            ("c.test", "they-block-we-allow"),
        ] {
            assert!(w.log(LogEvent::Divergence {
                ts: 1000,
                qname: q.into(),
                qtype: 1,
                ours: "nxdomain".into(),
                theirs: "0.0.0.0".into(),
                class: class.into(),
            }));
        }
        db.flush();
        let rows = db.recent_divergences(2).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].qname, "c.test", "newest first");
        assert_eq!(rows[0].class, "they-block-we-allow");
        let summary = db.divergence_summary(0).unwrap();
        assert_eq!(summary[0], ("expected".to_string(), 2));
        assert_eq!(summary[1], ("they-block-we-allow".to_string(), 1));
        assert!(db.divergence_summary(2000).unwrap().is_empty());
    }
}
