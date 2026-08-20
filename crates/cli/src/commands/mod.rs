//! One module per subcommand, plus shared plumbing.

pub mod check;
pub mod explain;
pub mod init;
pub mod log;
pub mod migrate;
pub mod reload;
pub mod serve;
pub mod shadow_report;
pub mod stats;
pub mod status;

use std::path::Path;

use sumidero_core::config::Config;
use sumidero_core::db::Db;

/// Load and validate the config, mapping errors to a printable string.
pub(crate) fn load_config(path: &Path) -> Result<Config, String> {
    Config::load(path).map_err(|e| e.to_string())
}

/// Open the database named by the config.
pub(crate) fn open_db(config: &Config) -> Result<Db, String> {
    Db::open(&config.database.path).map_err(|e| e.to_string())
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}
