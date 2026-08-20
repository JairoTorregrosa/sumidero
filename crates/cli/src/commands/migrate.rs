//! `sumidero migrate <AdGuardHome.yaml>` — one-shot config conversion.
//!
//! Maps what sumidero v1 supports; everything it cannot carry over is
//! reported as an explicit warning, never silently dropped.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::json;
use sumidero_core::config::Config;

use crate::output::{emit, fail};

// ── Partial AdGuardHome.yaml shape (unknown fields ignored) ─────────

#[derive(Debug, Default, Deserialize)]
struct Agh {
    #[serde(default)]
    dns: AghDns,
    #[serde(default)]
    filters: Vec<AghFilter>,
    #[serde(default)]
    user_rules: Vec<String>,
    #[serde(default)]
    filtering: AghFiltering,
    #[serde(default)]
    dhcp: AghDhcp,
    #[serde(default)]
    tls: AghTls,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AghDns {
    bind_hosts: Vec<String>,
    port: u16,
    upstream_dns: Vec<String>,
    fallback_dns: Vec<String>,
    bootstrap_dns: Vec<IpAddr>,
    upstream_timeout: String,
    allowed_clients: Vec<String>,
    blocked_hosts: Vec<String>,
    ratelimit: u64,
}

impl Default for AghDns {
    fn default() -> Self {
        Self {
            bind_hosts: vec!["0.0.0.0".into()],
            port: 53,
            upstream_dns: Vec::new(),
            fallback_dns: Vec::new(),
            bootstrap_dns: Vec::new(),
            upstream_timeout: "5s".into(),
            allowed_clients: Vec::new(),
            blocked_hosts: Vec::new(),
            ratelimit: 0,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct AghFilter {
    #[serde(default)]
    enabled: bool,
    url: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Default, Deserialize)]
struct AghFiltering {
    #[serde(default)]
    safe_search: AghSafeSearch,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors AdGuard's YAML shape verbatim"
)]
struct AghSafeSearch {
    enabled: bool,
    google: bool,
    youtube: bool,
    bing: bool,
    duckduckgo: bool,
    ecosia: bool,
    pixabay: bool,
    yandex: bool,
}

#[derive(Debug, Default, Deserialize)]
struct AghDhcp {
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Default, Deserialize)]
struct AghTls {
    #[serde(default)]
    enabled: bool,
}

// ── Conversion ──────────────────────────────────────────────────────

pub(crate) struct Migration {
    pub toml: String,
    pub warnings: Vec<String>,
    /// Content for the local user-rules list referenced by the config.
    pub user_rules: Option<String>,
}

fn slug(name: &str) -> String {
    let mut s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    s.trim_matches('-').to_string()
}

fn parse_go_duration_ms(s: &str) -> Option<u64> {
    if let Some(ms) = s.strip_suffix("ms") {
        return ms.parse().ok();
    }
    if let Some(secs) = s.strip_suffix('s') {
        return secs.parse::<u64>().ok().map(|v| v * 1000);
    }
    None
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear mapping pass over every AdGuard section"
)]
pub(crate) fn convert(
    yaml: &str,
    list_dir: &Path,
    db_path: &Path,
    user_rules_path: &Path,
) -> Result<Migration, String> {
    let agh: Agh = serde_yaml::from_str(yaml).map_err(|e| format!("cannot parse YAML: {e}"))?;
    let mut warnings = Vec::new();

    // Binds.
    let mut bind = Vec::new();
    for host in &agh.dns.bind_hosts {
        let ip: IpAddr = host.parse().map_err(|e| format!("bind host {host}: {e}"))?;
        bind.push(SocketAddr::new(ip, agh.dns.port).to_string());
        if ip == IpAddr::from([0, 0, 0, 0]) {
            // AdGuard's 0.0.0.0 implicitly covers v6; sumidero binds both
            // explicitly (settled: bind v4+v6).
            bind.push(format!("[::]:{}", agh.dns.port));
        }
    }
    bind.dedup();
    let mut seen_binds = std::collections::HashSet::new();
    bind.retain(|b| seen_binds.insert(b.clone()));

    // Upstreams: only DoH/DoQ survive.
    let mut servers = Vec::new();
    for u in &agh.dns.upstream_dns {
        if u.starts_with("https://") || u.starts_with("quic://") {
            servers.push(u.clone());
        } else {
            warnings.push(format!(
                "upstream {u} skipped: sumidero v1 supports only https:// (DoH) and quic:// (DoQ)"
            ));
        }
    }
    if servers.is_empty() {
        return Err("no usable upstream (need at least one https:// or quic:// server)".into());
    }
    if !agh.dns.fallback_dns.is_empty() {
        warnings.push(
            "fallback_dns has no equivalent: sumidero races all upstreams in parallel".into(),
        );
    }
    if agh.dns.bootstrap_dns.is_empty() {
        return Err("bootstrap_dns is empty; sumidero requires bootstrap IPs".into());
    }

    let timeout_ms = parse_go_duration_ms(&agh.dns.upstream_timeout).unwrap_or_else(|| {
        warnings.push(format!(
            "cannot parse upstream_timeout {:?}; using 5000 ms",
            agh.dns.upstream_timeout
        ));
        5000
    });

    // Allowlist: bare IPs become host networks.
    let mut allow = Vec::new();
    if agh.dns.allowed_clients.is_empty() {
        warnings.push(
            "allowed_clients is empty: AdGuard would answer everyone; sumidero requires an \
             explicit allowlist — defaulting to RFC1918 + loopback, EDIT THIS"
                .into(),
        );
        allow.extend(
            [
                "192.168.0.0/16",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "127.0.0.0/8",
                "::1/128",
            ]
            .map(String::from),
        );
    }
    for client in &agh.dns.allowed_clients {
        if client.contains('/') {
            allow.push(client.clone());
        } else {
            match client.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => allow.push(format!("{ip}/32")),
                Ok(IpAddr::V6(ip)) => allow.push(format!("{ip}/128")),
                Err(_) => warnings.push(format!(
                    "allowed client {client:?} skipped: not an IP or CIDR (client IDs are not \
                     supported)"
                )),
            }
        }
    }
    if allow.is_empty() {
        warnings.push(
            "no allowed client survived the conversion; defaulting to RFC1918 + loopback, \
             EDIT THIS"
                .into(),
        );
        allow.extend(
            [
                "192.168.0.0/16",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "127.0.0.0/8",
                "::1/128",
            ]
            .map(String::from),
        );
    }

    // Lists. Names must be unique, non-empty, and must not collide with
    // the synthetic "user-rules" list added below.
    let mut lists: Vec<(String, String)> = Vec::new();
    let mut used_names: std::collections::HashSet<String> =
        std::collections::HashSet::from(["user-rules".to_string()]);
    for (i, f) in agh.filters.iter().enumerate() {
        if f.enabled {
            let mut name = slug(&f.name);
            if name.is_empty() {
                name = format!("list-{}", i + 1);
            }
            let base = name.clone();
            let mut n = 2;
            while !used_names.insert(name.clone()) {
                name = format!("{base}-{n}");
                n += 1;
            }
            if name != base {
                warnings.push(format!(
                    "filter {:?} renamed to {name:?} to keep list names unique",
                    f.name
                ));
            }
            lists.push((name, f.url.clone()));
        } else {
            warnings.push(format!("disabled filter {:?} not migrated", f.name));
        }
    }

    // User rules + blocked_hosts become a local list.
    let mut rules = agh.user_rules.clone();
    rules.extend(agh.dns.blocked_hosts.iter().cloned());
    let user_rules = if rules.is_empty() {
        None
    } else {
        Some(format!(
            "! migrated from AdGuardHome.yaml (user_rules + blocked_hosts)\n{}\n",
            rules.join("\n")
        ))
    };

    // Safe search.
    let ss = &agh.filtering.safe_search;
    let mut providers = Vec::new();
    let mut safe_search_enabled = false;
    if ss.enabled {
        for (on, name) in [
            (ss.google, "google"),
            (ss.youtube, "youtube"),
            (ss.bing, "bing"),
            (ss.duckduckgo, "duckduckgo"),
        ] {
            if on {
                providers.push(name.to_string());
            }
        }
        for (on, name) in [
            (ss.ecosia, "ecosia"),
            (ss.pixabay, "pixabay"),
            (ss.yandex, "yandex"),
        ] {
            if on {
                warnings.push(format!(
                    "safe-search provider {name} is not supported in v1"
                ));
            }
        }
        safe_search_enabled = !providers.is_empty();
        if ss.enabled && providers.is_empty() {
            warnings.push(
                "safe_search was enabled but no supported provider is active; disabled".into(),
            );
        }
    }

    if agh.dhcp.enabled {
        warnings.push("DHCP is enabled in AdGuard but out of scope for sumidero".into());
    }
    if agh.tls.enabled {
        warnings.push("TLS serving (DoT/DoH server) is out of scope for sumidero v1".into());
    }
    if agh.dns.ratelimit > 0 {
        warnings.push("ratelimit has no equivalent in sumidero v1".into());
    }
    warnings.push(
        "web UI, query-log settings, and statistics settings do not apply: sumidero's control \
         plane is the config file + SQLite + CLI"
            .into(),
    );

    if lists.is_empty() && user_rules.is_none() {
        return Err(
            "nothing to filter with: no enabled filters and no user rules in the AdGuard \
             config; start from `sumidero init --profile` instead"
                .into(),
        );
    }

    // Assemble TOML and prove it loads.
    let mut toml =
        String::from("# sumidero config — generated by `sumidero migrate` from AdGuardHome.yaml\n");
    for w in &warnings {
        let _ = writeln!(toml, "# WARNING: {w}");
    }
    toml.push_str("\n[server]\n");
    let _ = writeln!(toml, "bind = {bind:?}");
    let _ = writeln!(toml, "allow = {allow:?}");
    toml.push_str("\n[filtering]\n");
    let _ = writeln!(toml, "list_dir = {:?}", list_dir.display().to_string());
    for (name, url) in &lists {
        let _ = writeln!(
            toml,
            "\n[[filtering.lists]]\nname = {name:?}\nurl = {url:?}"
        );
    }
    if user_rules.is_some() {
        let _ = writeln!(
            toml,
            "\n[[filtering.lists]]\nname = \"user-rules\"\npath = {:?}",
            user_rules_path.display().to_string()
        );
    }
    toml.push_str("\n[upstreams]\n");
    let _ = writeln!(toml, "servers = {servers:?}");
    let _ = writeln!(
        toml,
        "bootstrap = {:?}",
        agh.dns
            .bootstrap_dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    let _ = writeln!(toml, "timeout_ms = {timeout_ms}");
    toml.push_str("\n[database]\n");
    let _ = writeln!(toml, "path = {:?}", db_path.display().to_string());
    toml.push_str("\n[safe_search]\n");
    let _ = writeln!(toml, "enabled = {safe_search_enabled}");
    let _ = writeln!(toml, "providers = {providers:?}");

    // Fail loud: the generated config must parse and validate.
    Config::from_toml(&toml, Path::new("<migrated>"))
        .map_err(|e| format!("generated config failed validation (bug): {e}"))?;

    Ok(Migration {
        toml,
        warnings,
        user_rules,
    })
}

pub fn run(config: &Path, json: bool, input: &Path, out: Option<&Path>, force: bool) -> ExitCode {
    let target = out.unwrap_or(config);
    if target.exists() && !force {
        return fail(
            json,
            "migrate",
            &format!("{} exists; pass --force to overwrite", target.display()),
            6,
        );
    }
    let yaml = match std::fs::read_to_string(input) {
        Ok(y) => y,
        Err(e) => {
            return fail(
                json,
                "migrate",
                &format!("cannot read {}: {e}", input.display()),
                1,
            );
        }
    };
    let parent: PathBuf = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    // The path is embedded in the generated config, which requires
    // absolute list paths — resolve relative --out targets.
    let user_rules_path = std::path::absolute(parent.join("user-rules.txt"))
        .unwrap_or_else(|_| parent.join("user-rules.txt"));

    let migration = match convert(
        &yaml,
        Path::new("/var/lib/sumidero/lists"),
        Path::new("/var/lib/sumidero/sumidero.sqlite"),
        &user_rules_path,
    ) {
        Ok(m) => m,
        Err(e) => return fail(json, "migrate", &e, 1),
    };

    if let Some(rules) = &migration.user_rules
        && let Err(e) = std::fs::write(&user_rules_path, rules)
    {
        return fail(
            json,
            "migrate",
            &format!("cannot write {}: {e}", user_rules_path.display()),
            1,
        );
    }
    if let Err(e) = std::fs::write(target, &migration.toml) {
        return fail(
            json,
            "migrate",
            &format!("cannot write {}: {e}", target.display()),
            1,
        );
    }

    let human = format!(
        "wrote {}{}\n{} warnings:\n  {}",
        target.display(),
        migration
            .user_rules
            .as_ref()
            .map(|_| format!(" and {}", user_rules_path.display()))
            .unwrap_or_default(),
        migration.warnings.len(),
        migration.warnings.join("\n  ")
    );
    emit(
        json,
        "migrate",
        json!({
            "written": target.display().to_string(),
            "user_rules": migration.user_rules.is_some().then(|| user_rules_path.display().to_string()),
            "warnings": migration.warnings,
        }),
        &human,
    )
}
