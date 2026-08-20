//! TOML configuration: parse, validate, expand profiles. Fail loud.
//!
//! Rules:
//! - Unknown keys are errors (`deny_unknown_fields`): a typo must not
//!   silently disable a feature.
//! - Required fields have no defaults. Optional sections are `Option`.
//! - `Config::load` performs semantic validation beyond serde: non-empty
//!   binds/allowlist/upstreams, resolvable list sources, absolute paths.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    /// Semantic validation failure (empty required list, relative path,
    /// unknown profile/list name, nonsensical value).
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Fully validated runtime configuration.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub filtering: FilteringConfig,
    pub upstreams: UpstreamsConfig,
    pub database: DatabaseConfig,
    #[serde(default, skip_serializing_if = "is_default_safe_search")]
    pub safe_search: SafeSearchConfig,
}

fn is_default_safe_search(s: &SafeSearchConfig) -> bool {
    !s.enabled && s.providers.is_empty()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Sockets to bind, v4 and v6 (e.g. `["0.0.0.0:53", "[::]:53"]`).
    pub bind: Vec<SocketAddr>,
    /// Client networks allowed to query. Everything else is refused.
    pub allow: Vec<IpNet>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FilteringConfig {
    /// Base profile expanding to named lists; `lists` adds to or —
    /// by reusing a name — overrides individual profile entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub lists: Vec<ListSource>,
    /// Directory holding downloaded list copies (absolute).
    pub list_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Minimal,
    Balanced,
    Strict,
}

/// One blocklist: a stable name plus where it comes from.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListSource {
    pub name: String,
    /// HTTPS URL to fetch; `None` for purely local lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Local file path (absolute); used instead of / as seed for `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamsConfig {
    /// Upstream resolver URLs: `https://…/dns-query` (`DoH`) or
    /// `quic://host[:port]` (`DoQ`). All are queried in parallel.
    pub servers: Vec<String>,
    /// Plain IPs used to resolve the upstream hostnames themselves.
    pub bootstrap: Vec<std::net::IpAddr>,
    /// Per-attempt timeout in milliseconds.
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// `SQLite` file path (absolute). Parent directory must exist.
    pub path: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafeSearchConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Providers to force; empty + enabled = all supported providers.
    #[serde(default)]
    pub providers: Vec<String>,
}

impl Config {
    /// Read, parse, and validate. Any problem is an error — never a default.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Read` if the file cannot be read,
    /// `ConfigError::Parse` on syntax errors, or `ConfigError::Invalid`
    /// on semantic violations.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::from_toml(&text, path)
    }

    /// Parse + validate from a TOML string (used by `load` and `check`).
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Parse` on TOML syntax errors,
    /// or `ConfigError::Invalid` on semantic violations.
    pub fn from_toml(text: &str, origin: &Path) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: origin.to_path_buf(),
            source: Box::new(e),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// The effective list set: profile expansion with `lists` overrides
    /// applied (same `name` replaces the profile entry). Order is stable:
    /// profile lists first (profile order), then extras (config order).
    #[must_use]
    pub fn effective_lists(&self) -> Vec<ListSource> {
        let mut result: Vec<ListSource> =
            self.filtering.profile.map_or_else(Vec::new, Profile::lists);

        for extra in &self.filtering.lists {
            if let Some(pos) = result.iter().position(|l| l.name == extra.name) {
                result[pos] = extra.clone();
            } else {
                result.push(extra.clone());
            }
        }
        result
    }

    /// SHA-256 of the canonical serialized config, hex — for the heartbeat.
    ///
    /// # Stability caveat
    ///
    /// The hash is computed from the TOML re-serialization of the config
    /// struct. It is stable across runs with the same serde/toml version
    /// and struct layout, but may change on crate upgrades or field
    /// reordering. It is intended for runtime comparison (heartbeat vs.
    /// `explain`), not for long-term persistence.
    ///
    /// # Panics
    ///
    /// Panics if a validated `Config` cannot be serialized to TOML, which
    /// should never happen for a well-formed config.
    #[must_use]
    pub fn hash(&self) -> String {
        let canonical = toml::to_string(self)
            .expect("Config serialization should never fail on a validated config");
        let digest = Sha256::digest(canonical.as_bytes());
        hex_encode(&digest)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // server.bind non-empty
        if self.server.bind.is_empty() {
            return Err(ConfigError::Invalid(
                "server.bind: must not be empty".into(),
            ));
        }
        // server.allow non-empty
        if self.server.allow.is_empty() {
            return Err(ConfigError::Invalid(
                "server.allow: must not be empty".into(),
            ));
        }
        // upstreams.servers non-empty, each https:// or quic://
        if self.upstreams.servers.is_empty() {
            return Err(ConfigError::Invalid(
                "upstreams.servers: must not be empty".into(),
            ));
        }
        for s in &self.upstreams.servers {
            if !s.starts_with("https://") && !s.starts_with("quic://") {
                return Err(ConfigError::Invalid(format!(
                    "upstreams.servers: {s}: must use https:// or quic:// scheme"
                )));
            }
        }
        // upstreams.bootstrap non-empty
        if self.upstreams.bootstrap.is_empty() {
            return Err(ConfigError::Invalid(
                "upstreams.bootstrap: must not be empty".into(),
            ));
        }
        // timeout_ms in 100..=30000
        if !(100..=30_000).contains(&self.upstreams.timeout_ms) {
            return Err(ConfigError::Invalid(format!(
                "upstreams.timeout_ms: {} is not in 100..=30000",
                self.upstreams.timeout_ms
            )));
        }
        // database.path absolute
        if !self.database.path.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "database.path: {} must be absolute",
                self.database.path.display()
            )));
        }
        // filtering.list_dir absolute
        if !self.filtering.list_dir.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "filtering.list_dir: {} must be absolute",
                self.filtering.list_dir.display()
            )));
        }
        // filtering must yield at least one effective list
        let effective = self.effective_lists();
        if effective.is_empty() {
            return Err(ConfigError::Invalid(
                "filtering: must have at least one list (set profile or lists)".into(),
            ));
        }
        // List names must be unique and non-empty. Reusing a PROFILE list
        // name is the documented override mechanism, but two entries in
        // `filtering.lists` sharing a name would silently drop one — check
        // the raw extras, not the post-override effective set.
        let mut seen = std::collections::HashSet::new();
        for ls in &self.filtering.lists {
            if ls.name.is_empty() {
                return Err(ConfigError::Invalid(
                    "filtering.lists: a list has an empty name".into(),
                ));
            }
            if !seen.insert(&ls.name) {
                return Err(ConfigError::Invalid(format!(
                    "filtering.lists: duplicate list name '{}'",
                    ls.name
                )));
            }
        }
        // validate each list source
        for ls in &effective {
            if ls.url.is_none() && ls.path.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "filtering.lists: '{}' has neither url nor path",
                    ls.name
                )));
            }
            if let Some(url) = &ls.url
                && !url.starts_with("https://")
            {
                return Err(ConfigError::Invalid(format!(
                    "filtering.lists: '{}' url '{}' must use https://",
                    ls.name, url
                )));
            }
            if let Some(path) = &ls.path
                && !path.is_absolute()
            {
                return Err(ConfigError::Invalid(format!(
                    "filtering.lists: '{}' path {} must be absolute",
                    ls.name,
                    path.display()
                )));
            }
        }
        Ok(())
    }
}

impl Profile {
    /// The named lists this profile expands to (hagezi tiers).
    #[must_use]
    pub fn lists(self) -> Vec<ListSource> {
        match self {
            Self::Minimal => vec![hagezi_light()],
            Self::Balanced => vec![hagezi_pro()],
            Self::Strict => vec![hagezi_pro(), hagezi_tif()],
        }
    }
}

fn hagezi_light() -> ListSource {
    ListSource {
        name: "hagezi-light".into(),
        url: Some(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt".into(),
        ),
        path: None,
    }
}

fn hagezi_pro() -> ListSource {
    ListSource {
        name: "hagezi-pro".into(),
        url: Some(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt".into(),
        ),
        path: None,
    }
}

fn hagezi_tif() -> ListSource {
    ListSource {
        name: "hagezi-tif".into(),
        url: Some(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt".into(),
        ),
        path: None,
    }
}

/// Render a commented starter config for `sumidero init --profile <p>`.
///
/// The returned TOML is fully commented and round-trips through
/// `Config::from_toml` for every profile.
#[must_use]
pub fn starter_config(profile: Profile) -> String {
    let profile_name = match profile {
        Profile::Minimal => "minimal",
        Profile::Balanced => "balanced",
        Profile::Strict => "strict",
    };
    format!(
        r#"# sumidero configuration
# Generated for profile: {profile_name}
# See DESIGN.md for details.

[server]
# Sockets to bind (v4 + v6).
bind = ["0.0.0.0:53", "[::]:53"]
# Client networks allowed to query; everything else is refused.
allow = ["192.168.0.0/16", "127.0.0.0/8", "::1/128"]

[filtering]
# Base profile: minimal, balanced, or strict.
# Each profile expands to a curated set of blocklists (hagezi tiers).
profile = "{profile_name}"
# Additional or overriding lists:
# [[filtering.lists]]
# name = "my-custom-list"
# url = "https://example.com/list.txt"
# Directory for downloaded list copies (must be absolute).
list_dir = "/var/lib/sumidero/lists"

[upstreams]
# DoH / DoQ upstream resolvers, queried in parallel.
servers = [
  "https://dns.cloudflare.com/dns-query",
  "https://dns.google/dns-query",
]
# Plain IPs for bootstrapping upstream hostname resolution.
bootstrap = ["1.1.1.1", "9.9.9.9"]
# Per-attempt timeout in milliseconds (100..=30000).
timeout_ms = 3000

[database]
# SQLite file for query log and stats (must be absolute).
path = "/var/lib/sumidero/sumidero.sqlite"
"#
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(s, "{b:02x}").expect("writing to String never fails");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_toml() -> String {
        r#"
[server]
bind = ["0.0.0.0:53", "[::]:53"]
allow = ["192.168.0.0/16", "127.0.0.0/8"]

[filtering]
profile = "balanced"
list_dir = "/var/lib/sumidero/lists"

[upstreams]
servers = ["https://dns.cloudflare.com/dns-query"]
bootstrap = ["1.1.1.1"]
timeout_ms = 3000

[database]
path = "/var/lib/sumidero/sumidero.sqlite"
"#
        .into()
    }

    fn origin() -> PathBuf {
        PathBuf::from("/etc/sumidero/config.toml")
    }

    #[test]
    fn parse_valid_config() {
        let cfg = Config::from_toml(&valid_toml(), &origin()).unwrap();
        assert_eq!(cfg.server.bind.len(), 2);
        assert_eq!(cfg.upstreams.timeout_ms, 3000);
    }

    #[test]
    fn parse_error_has_path_context() {
        let err = Config::from_toml("not valid toml {{", &origin()).unwrap_err();
        match err {
            ConfigError::Parse { path, .. } => {
                assert_eq!(path, origin());
            }
            other => panic!("expected Parse, got {other}"),
        }
    }

    #[test]
    fn unknown_key_rejected() {
        let toml = valid_toml() + "\n[extra_section]\nfoo = 1\n";
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn empty_bind_rejected() {
        let toml = valid_toml().replace(r#"bind = ["0.0.0.0:53", "[::]:53"]"#, "bind = []");
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("bind"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn empty_allow_rejected() {
        let toml =
            valid_toml().replace(r#"allow = ["192.168.0.0/16", "127.0.0.0/8"]"#, "allow = []");
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("allow"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn empty_servers_rejected() {
        let toml = valid_toml().replace(
            r#"servers = ["https://dns.cloudflare.com/dns-query"]"#,
            "servers = []",
        );
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("servers"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn bad_upstream_scheme_rejected() {
        let toml = valid_toml().replace(
            "https://dns.cloudflare.com/dns-query",
            "http://dns.cloudflare.com/dns-query",
        );
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => {
                assert!(msg.contains("https://") || msg.contains("quic://"), "{msg}");
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn quic_upstream_accepted() {
        let toml = valid_toml().replace(
            "https://dns.cloudflare.com/dns-query",
            "quic://dns.example.com",
        );
        Config::from_toml(&toml, &origin()).unwrap();
    }

    #[test]
    fn empty_bootstrap_rejected() {
        let toml = valid_toml().replace(r#"bootstrap = ["1.1.1.1"]"#, "bootstrap = []");
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("bootstrap"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn timeout_too_low_rejected() {
        let toml = valid_toml().replace("timeout_ms = 3000", "timeout_ms = 50");
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("timeout_ms"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn timeout_too_high_rejected() {
        let toml = valid_toml().replace("timeout_ms = 3000", "timeout_ms = 99999");
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("timeout_ms"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn relative_db_path_rejected() {
        let toml = valid_toml().replace(
            r#"path = "/var/lib/sumidero/sumidero.sqlite""#,
            r#"path = "relative/sumidero.sqlite""#,
        );
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("database.path"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn relative_list_dir_rejected() {
        let toml = valid_toml().replace(
            r#"list_dir = "/var/lib/sumidero/lists""#,
            r#"list_dir = "lists""#,
        );
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("list_dir"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn no_profile_no_lists_rejected() {
        let toml = valid_toml().replace("profile = \"balanced\"", "");
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("filtering"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn list_without_url_or_path_rejected() {
        let toml = valid_toml().replace("profile = \"balanced\"", "")
            + "\n[[filtering.lists]]\nname = \"broken\"\n";
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("broken"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn list_with_http_url_rejected() {
        let toml = valid_toml().replace("profile = \"balanced\"", "")
            + "\n[[filtering.lists]]\nname = \"bad\"\nurl = \"http://example.com/list.txt\"\n";
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => {
                assert!(msg.contains("https://"), "{msg}");
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn list_with_relative_path_rejected() {
        let toml = valid_toml().replace("profile = \"balanced\"", "")
            + "\n[[filtering.lists]]\nname = \"local\"\npath = \"relative/list.txt\"\n";
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        match err {
            ConfigError::Invalid(msg) => assert!(msg.contains("absolute"), "{msg}"),
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[test]
    fn list_with_path_only_valid() {
        let toml = valid_toml().replace("profile = \"balanced\"", "")
            + "\n[[filtering.lists]]\nname = \"local\"\npath = \"/etc/sumidero/my.txt\"\n";
        Config::from_toml(&toml, &origin()).unwrap();
    }

    #[test]
    fn profile_minimal_lists() {
        let lists = Profile::Minimal.lists();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].name, "hagezi-light");
    }

    #[test]
    fn profile_balanced_lists() {
        let lists = Profile::Balanced.lists();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].name, "hagezi-pro");
    }

    #[test]
    fn profile_strict_lists() {
        let lists = Profile::Strict.lists();
        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0].name, "hagezi-pro");
        assert_eq!(lists[1].name, "hagezi-tif");
    }

    #[test]
    fn effective_lists_profile_only() {
        let cfg = Config::from_toml(&valid_toml(), &origin()).unwrap();
        let effective = cfg.effective_lists();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].name, "hagezi-pro");
    }

    #[test]
    fn effective_lists_override_replaces_in_place() {
        // strict has [hagezi-pro, hagezi-tif]; override hagezi-pro url
        let toml = valid_toml().replace("profile = \"balanced\"", "profile = \"strict\"")
            + r#"
[[filtering.lists]]
name = "hagezi-pro"
url = "https://example.com/custom-pro.txt"
"#;
        let cfg = Config::from_toml(&toml, &origin()).unwrap();
        let effective = cfg.effective_lists();
        assert_eq!(effective.len(), 2);
        assert_eq!(effective[0].name, "hagezi-pro");
        assert_eq!(
            effective[0].url.as_deref(),
            Some("https://example.com/custom-pro.txt")
        );
        assert_eq!(effective[1].name, "hagezi-tif");
    }

    #[test]
    fn effective_lists_extras_appended() {
        let toml = valid_toml()
            + r#"
[[filtering.lists]]
name = "my-extra"
url = "https://example.com/extra.txt"
"#;
        let cfg = Config::from_toml(&toml, &origin()).unwrap();
        let effective = cfg.effective_lists();
        assert_eq!(effective.len(), 2);
        assert_eq!(effective[0].name, "hagezi-pro");
        assert_eq!(effective[1].name, "my-extra");
    }

    #[test]
    fn hash_deterministic() {
        let cfg = Config::from_toml(&valid_toml(), &origin()).unwrap();
        let h1 = cfg.hash();
        let h2 = cfg.hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn hash_changes_with_config() {
        let cfg1 = Config::from_toml(&valid_toml(), &origin()).unwrap();
        let toml2 = valid_toml().replace("timeout_ms = 3000", "timeout_ms = 5000");
        let cfg2 = Config::from_toml(&toml2, &origin()).unwrap();
        assert_ne!(cfg1.hash(), cfg2.hash());
    }

    #[test]
    fn starter_config_roundtrips_all_profiles() {
        for profile in [Profile::Minimal, Profile::Balanced, Profile::Strict] {
            let text = starter_config(profile);
            let cfg = Config::from_toml(&text, &origin())
                .unwrap_or_else(|e| panic!("starter_config({profile:?}) failed: {e}"));
            assert_eq!(cfg.filtering.profile, Some(profile));
            assert_eq!(cfg.server.bind.len(), 2);
            assert_eq!(cfg.server.allow.len(), 3);
            assert_eq!(cfg.upstreams.servers.len(), 2);
            assert_eq!(cfg.upstreams.bootstrap.len(), 2);
            assert_eq!(cfg.upstreams.timeout_ms, 3000);
        }
    }

    #[test]
    fn safe_search_defaults_when_absent() {
        let cfg = Config::from_toml(&valid_toml(), &origin()).unwrap();
        assert!(!cfg.safe_search.enabled);
        assert!(cfg.safe_search.providers.is_empty());
    }

    #[test]
    fn load_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, valid_toml()).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.upstreams.timeout_ms, 3000);
    }

    #[test]
    fn load_missing_file_is_read_error() {
        let err = Config::load(std::path::Path::new("/nonexistent/config.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    #[test]
    fn empty_allow_in_config_error_message_names_key() {
        let toml =
            valid_toml().replace(r#"allow = ["192.168.0.0/16", "127.0.0.0/8"]"#, "allow = []");
        let err = Config::from_toml(&toml, &origin()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("allow"), "error should name the key: {msg}");
    }

    #[test]
    fn duplicate_list_names_rejected() {
        let toml = r#"
[server]
bind = ["127.0.0.1:53"]
allow = ["127.0.0.0/8"]
[filtering]
list_dir = "/var/lib/s"
[[filtering.lists]]
name = "dup"
url = "https://a.example/l.txt"
[[filtering.lists]]
name = "dup"
url = "https://b.example/l.txt"
[upstreams]
servers = ["https://dns.example/dns-query"]
bootstrap = ["1.1.1.1"]
timeout_ms = 3000
[database]
path = "/var/lib/s.sqlite"
"#;
        let err = Config::from_toml(toml, std::path::Path::new("t")).unwrap_err();
        assert!(err.to_string().contains("duplicate list name"), "{err}");
    }

    #[test]
    fn empty_list_name_rejected() {
        let toml = r#"
[server]
bind = ["127.0.0.1:53"]
allow = ["127.0.0.0/8"]
[filtering]
list_dir = "/var/lib/s"
[[filtering.lists]]
name = ""
url = "https://a.example/l.txt"
[upstreams]
servers = ["https://dns.example/dns-query"]
bootstrap = ["1.1.1.1"]
timeout_ms = 3000
[database]
path = "/var/lib/s.sqlite"
"#;
        let err = Config::from_toml(toml, std::path::Path::new("t")).unwrap_err();
        assert!(err.to_string().contains("empty name"), "{err}");
    }
}
