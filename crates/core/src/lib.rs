//! sumidero daemon library.
//!
//! DNS server pipeline: client allowlist → filter → safe-search rewrite →
//! cache → parallel encrypted upstreams, with a `SQLite` query log and
//! SIGHUP-driven reload. The filesystem is the control plane: TOML config
//! in, `SQLite` out. See `DESIGN.md` at the repo root.
//!
//! # Fail loud
//!
//! Missing or invalid configuration, or a configured blocklist that cannot
//! be fetched and has no last-good disk copy, refuses to start the daemon.
//! No module in this crate substitutes silent defaults for required input.

pub mod cache;
pub mod config;
pub mod db;
pub mod lists;
pub mod safesearch;
pub mod server;
pub mod shadow;
pub mod upstream;

/// Fixed engineering calls from the settled design (not configurable).
pub mod consts {
    /// Query-log retention: rows older than this are deleted hourly.
    pub const LOG_RETENTION_SECS: i64 = 7 * 24 * 3600;
    /// Blocklists are refreshed this often (with `ETag` revalidation).
    pub const LIST_UPDATE_SECS: u64 = 24 * 3600;
    // Cache TTL constants live in [`crate::cache`], next to the logic
    // they govern (MIN_TTL_SECS, STALE_WINDOW_SECS).
}

/// Top-level daemon error. Every variant is a startup or runtime failure
/// that must surface loudly; none are recoverable-by-default.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("configuration: {0}")]
    Config(#[from] config::ConfigError),
    #[error("blocklists: {0}")]
    Lists(#[from] lists::ListError),
    #[error("database: {0}")]
    Db(#[from] db::DbError),
    #[error("upstreams: {0}")]
    Upstream(#[from] upstream::Error),
    #[error("safe-search: {0}")]
    SafeSearch(#[from] safesearch::ConfigError),
    #[error("server: {0}")]
    Io(#[from] std::io::Error),
}
