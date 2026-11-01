//! Blocklist acquisition and engine building. Fail loud.
//!
//! For each [`crate::config::ListSource`] (in `effective_lists` order):
//! - `path` only: read the file; unreadable = error.
//! - `url` set, online ([`Fetcher`] given): `GET` with `If-None-Match`
//!   against the stored `ETag`. A 200 whose body holds at least one rule
//!   replaces `list_dir/<name>.txt` atomically (temp file + rename); a
//!   304 marks the stored copy as verified now (its mtime). Any failure
//!   falls back to the stored copy, then to `path` as a seed, and says
//!   so in the list's [`ListOrigin`]; with neither it is a hard
//!   [`ListError`]: the daemon never starts half-filtering.
//! - `url` set, offline (no fetcher; `check`, `explain`): stored copy,
//!   then `path` seed.
//!
//! List hosts are resolved through the daemon's own encrypted upstreams
//! ([`Fetcher::new`]), never through the host resolver: a filtering host
//! resolver (Cloudflare Families answers `0.0.0.0` for `nsfw.oisd.nl`)
//! must not be able to starve the filter of the very list that blocks
//! what it blocks.
//!
//! The combined hash is SHA-256 over each list's raw bytes in order;
//! the daemon heartbeat and `explain` compare it.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sumidero_filter::{IssueReason, LineIssue};

use crate::config::ListSource;
use crate::upstream::UpstreamPool;

/// Largest list body accepted. The biggest list in use (`OISD` big) is
/// ~10 MB; this cap keeps a broken or hostile host from exhausting the
/// daemon's memory budget.
pub const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;
/// TCP + TLS connect budget for one list host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest silence between two reads of a list body.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Whole-request budget for one list.
const REQUEST_TIMEOUT: Duration = Duration::from_mins(3);

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("list {name}: cannot fetch {url} and no stored copy exists: {reason}")]
    Unavailable {
        name: String,
        url: String,
        reason: String,
    },
    #[error("list {name}: cannot read {path}: {source}")]
    Read {
        name: String,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("list {name}: has neither url nor path")]
    NoSource { name: String },
    #[error("list_dir {0} does not exist or is not writable")]
    ListDir(PathBuf),
    #[error("list_dir {path} could not be created: {source}")]
    ListDirCreate {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot build the list HTTP client: {0}")]
    Client(String),
}

/// Where a list's rules came from on this load. `as_str` values are
/// stable reason codes (logs, `status`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case")]
pub enum ListOrigin {
    /// 200: a new body was stored.
    Downloaded,
    /// 304: the stored copy is confirmed current.
    NotModified,
    /// The fetch failed; the last stored copy is in use.
    StoredAfterFetchFailure { reason: String },
    /// The fetch failed and there is no stored copy; the `path` seed is
    /// in use.
    SeedAfterFetchFailure { reason: String },
    /// A `path`-only list.
    LocalFile,
    /// Offline load (`check`, `explain`): stored copy.
    StoredOffline,
    /// Offline load, no stored copy: `path` seed.
    SeedOffline,
}

impl ListOrigin {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Downloaded => "downloaded",
            Self::NotModified => "not_modified",
            Self::StoredAfterFetchFailure { .. } => "stored_after_fetch_failure",
            Self::SeedAfterFetchFailure { .. } => "seed_after_fetch_failure",
            Self::LocalFile => "local_file",
            Self::StoredOffline => "stored_offline",
            Self::SeedOffline => "seed_offline",
        }
    }

    /// True when a fetch was attempted and failed.
    #[must_use]
    pub fn fetch_failed(&self) -> bool {
        matches!(
            self,
            Self::StoredAfterFetchFailure { .. } | Self::SeedAfterFetchFailure { .. }
        )
    }
}

/// What one load did with one list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListReport {
    pub name: String,
    #[serde(flatten)]
    pub origin: ListOrigin,
    pub rules: usize,
    pub issues: usize,
    /// Seconds since the content in use was last confirmed against its
    /// URL (download or 304). `None` for local files.
    pub verified_age_secs: Option<u64>,
}

/// A built engine plus provenance.
#[derive(Debug)]
pub struct LoadedLists {
    pub engine: sumidero_filter::Engine,
    /// List names, in engine list-index order.
    pub names: Vec<String>,
    /// SHA-256 (hex) over all lists' raw bytes, in order.
    pub hash: String,
    /// Parse issues per list name.
    pub issues: Vec<(String, LineIssue)>,
    /// One report per list, same order as `names`.
    pub reports: Vec<ListReport>,
}

impl LoadedLists {
    #[must_use]
    pub fn total_rules(&self) -> usize {
        self.reports.iter().map(|r| r.rules).sum()
    }
}

/// HTTPS client for list downloads: public web PKI plus
/// `[tls] extra_roots`, list hosts resolved through the upstream pool,
/// bounded connect/read/total time and body size.
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: reqwest::Client,
}

impl Fetcher {
    /// # Errors
    ///
    /// [`ListError::Client`] if a root certificate is unusable or the
    /// TLS backend cannot initialise.
    pub fn new(
        extra_roots: &[rustls::pki_types::CertificateDer<'static>],
        upstreams: Arc<UpstreamPool>,
    ) -> Result<Self, ListError> {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("sumidero/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(UpstreamResolver(upstreams)));
        for cert in extra_roots {
            let cert = reqwest::Certificate::from_der(cert.as_ref())
                .map_err(|e| ListError::Client(format!("tls.extra_roots: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }
        builder
            .build()
            .map(|client| Self { client })
            .map_err(|e| ListError::Client(e.to_string()))
    }
}

/// Resolves list hosts with A + AAAA queries through the upstream pool.
struct UpstreamResolver(Arc<UpstreamPool>);

impl reqwest::dns::Resolve for UpstreamResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let pool = Arc::clone(&self.0);
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let (v4, v6) = tokio::join!(
                lookup(&pool, &host, RecordType::A),
                lookup(&pool, &host, RecordType::AAAA)
            );
            let mut addrs: Vec<SocketAddr> = Vec::new();
            let mut errors = Vec::new();
            for result in [v4, v6] {
                match result {
                    Ok(ips) => addrs.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, 0))),
                    Err(e) => errors.push(e),
                }
            }
            if addrs.is_empty() {
                let why = if errors.is_empty() {
                    "no A/AAAA records".to_owned()
                } else {
                    errors.join("; ")
                };
                return Err(format!("{host}: not resolvable through the upstreams: {why}").into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(addrs)
        })
    }
}

async fn lookup(pool: &UpstreamPool, host: &str, qtype: RecordType) -> Result<Vec<IpAddr>, String> {
    let name = Name::from_ascii(format!("{}.", host.trim_end_matches('.')))
        .map_err(|e| format!("{host}: {e}"))?;
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(name, qtype));
    query.metadata.recursion_desired = true;
    let answer = pool.resolve(&query).await.map_err(|e| e.to_string())?;
    if answer.metadata.response_code != ResponseCode::NoError {
        return Err(format!("{qtype} {}", answer.metadata.response_code));
    }
    Ok(answer
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect())
}

/// Load all lists and compile the engine. `fetcher: None` is an offline
/// load: stored copies and seeds only, nothing is created or written.
///
/// # Errors
///
/// `ListError::ListDir`/`ListDirCreate` for an unusable `list_dir`,
/// `ListError::NoSource` if a list has neither url nor path,
/// `ListError::Unavailable` if a list has no usable content at all, or
/// `ListError::Read` if a file cannot be read.
///
/// # Panics
///
/// If a blocking compile task panics (a bug, propagated).
pub async fn load(
    sources: &[ListSource],
    list_dir: &Path,
    fetcher: Option<&Fetcher>,
) -> Result<LoadedLists, ListError> {
    // The daemon owns this directory (under systemd it lives inside
    // `StateDirectory`, empty on first start): creating it is part of
    // starting up, and failure aborts. Offline loads never create it,
    // so a misconfigured path is reported rather than materialised.
    if fetcher.is_some() && !list_dir.is_dir() {
        std::fs::create_dir_all(list_dir).map_err(|source| ListError::ListDirCreate {
            path: list_dir.to_path_buf(),
            source,
        })?;
    }
    if !list_dir.is_dir() {
        return Err(ListError::ListDir(list_dir.to_path_buf()));
    }
    if fetcher.is_some() {
        let probe = list_dir.join(".sumidero-probe");
        if std::fs::write(&probe, b"").is_err() {
            return Err(ListError::ListDir(list_dir.to_path_buf()));
        }
        let _ = std::fs::remove_file(&probe);
    }

    // Memory-critical host: one list at a time. Fetch its text, compile
    // it into the builder off the async runtime (hundreds of ms of CPU
    // for a big list must not stall DNS serving), drop the text before
    // the next list. Peak transient stays near one list's size.
    let mut builder = sumidero_filter::EngineBuilder::new();
    let mut names = Vec::with_capacity(sources.len());
    let mut all_issues: Vec<(String, LineIssue)> = Vec::new();
    let mut reports = Vec::with_capacity(sources.len());
    let mut hasher = Sha256::new();

    for source in sources {
        let acquired = acquire_list(source, list_dir, fetcher).await?;
        let name = source.name.clone();
        let raw = acquired.text;
        let (b, issues, count, h) = tokio::task::spawn_blocking(move || {
            let mut hasher = hasher;
            hasher.update(raw.as_bytes());
            let mut builder = builder;
            let added = builder.add_list_text(&raw);
            drop(raw);
            (builder, added.issues, added.rules, hasher)
        })
        .await
        .expect("list compile task panicked");
        builder = b;
        hasher = h;
        log_issue_summary(&name, &issues);
        let report = ListReport {
            name: name.clone(),
            origin: acquired.origin,
            rules: count,
            issues: issues.len(),
            verified_age_secs: acquired.verified_age_secs,
        };
        log_report(&report);
        all_issues.extend(issues.into_iter().map(|i| (name.clone(), i)));
        reports.push(report);
        names.push(name);
    }

    Ok(LoadedLists {
        engine: tokio::task::spawn_blocking(move || builder.build())
            .await
            .expect("engine finish task panicked"),
        names,
        hash: hex_encode(&hasher.finalize()),
        issues: all_issues,
        reports,
    })
}

/// One log line per list with rejected lines: counts per reason plus
/// three examples, instead of one line per rejected rule.
fn log_issue_summary(list: &str, issues: &[LineIssue]) {
    if issues.is_empty() {
        return;
    }
    let mut counts: Vec<(IssueReason, usize)> = Vec::new();
    for issue in issues {
        match counts.iter_mut().find(|(r, _)| *r == issue.reason) {
            Some((_, n)) => *n += 1,
            None => counts.push((issue.reason, 1)),
        }
    }
    let by_reason = counts
        .iter()
        .map(|(r, n)| format!("{r}={n}"))
        .collect::<Vec<_>>()
        .join(",");
    let examples = issues
        .iter()
        .take(3)
        .map(|i| format!("line {}: {}", i.line, i.text))
        .collect::<Vec<_>>()
        .join(" | ");
    tracing::warn!(
        list,
        rejected = issues.len(),
        by_reason,
        examples,
        next = "unsupported syntax is skipped; nothing to do unless a rule you rely on is listed",
        "blocklist lines rejected"
    );
}

fn log_report(r: &ListReport) {
    let age_h = r.verified_age_secs.map(|s| s / 3600);
    match &r.origin {
        ListOrigin::StoredAfterFetchFailure { reason }
        | ListOrigin::SeedAfterFetchFailure { reason } => {
            tracing::warn!(
                list = %r.name,
                origin = r.origin.as_str(),
                reason,
                verified_age_h = age_h,
                rules = r.rules,
                next = "check the list URL and that the upstreams resolve its host",
                "list fetch failed; serving the last good copy"
            );
        }
        _ => tracing::info!(
            list = %r.name,
            origin = r.origin.as_str(),
            verified_age_h = age_h,
            rules = r.rules,
            "list loaded"
        ),
    }
}

struct Acquired {
    text: String,
    origin: ListOrigin,
    verified_age_secs: Option<u64>,
}

fn read(name: &str, path: &Path) -> Result<String, ListError> {
    std::fs::read_to_string(path).map_err(|source| ListError::Read {
        name: name.to_owned(),
        path: path.to_path_buf(),
        source,
    })
}

/// Seconds since `path` was last modified (= last verified).
fn age_of(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
    Some(
        SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default()
            .as_secs(),
    )
}

/// Acquire the raw text for one list source.
async fn acquire_list(
    source: &ListSource,
    list_dir: &Path,
    fetcher: Option<&Fetcher>,
) -> Result<Acquired, ListError> {
    let name = source.name.as_str();
    let Some(url) = source.url.as_deref() else {
        let Some(path) = &source.path else {
            return Err(ListError::NoSource {
                name: name.to_owned(),
            });
        };
        return Ok(Acquired {
            text: read(name, path)?,
            origin: ListOrigin::LocalFile,
            verified_age_secs: None,
        });
    };

    let stored_path = list_dir.join(format!("{name}.txt"));
    let etag_path = list_dir.join(format!("{name}.etag"));
    let seed = source.path.as_ref().filter(|p| p.is_file());

    let Some(fetcher) = fetcher else {
        if stored_path.is_file() {
            return Ok(Acquired {
                text: read(name, &stored_path)?,
                origin: ListOrigin::StoredOffline,
                verified_age_secs: age_of(&stored_path),
            });
        }
        if let Some(seed) = seed {
            return Ok(Acquired {
                text: read(name, seed)?,
                origin: ListOrigin::SeedOffline,
                verified_age_secs: None,
            });
        }
        return Err(ListError::Unavailable {
            name: name.to_owned(),
            url: url.to_owned(),
            reason: "offline load and no stored copy".into(),
        });
    };

    match fetch_with_etag(&fetcher.client, url, &stored_path, &etag_path).await {
        Ok(acquired) => Ok(acquired),
        Err(reason) => {
            if stored_path.is_file() {
                return Ok(Acquired {
                    text: read(name, &stored_path)?,
                    verified_age_secs: age_of(&stored_path),
                    origin: ListOrigin::StoredAfterFetchFailure { reason },
                });
            }
            if let Some(seed) = seed {
                return Ok(Acquired {
                    text: read(name, seed)?,
                    verified_age_secs: None,
                    origin: ListOrigin::SeedAfterFetchFailure { reason },
                });
            }
            Err(ListError::Unavailable {
                name: name.to_owned(),
                url: url.to_owned(),
                reason,
            })
        }
    }
}

/// `GET` with `If-None-Match`. `Err(reason)` on any failure; the stored
/// copy is only ever replaced by a body that holds rules.
async fn fetch_with_etag(
    client: &reqwest::Client,
    url: &str,
    stored_path: &Path,
    etag_path: &Path,
) -> Result<Acquired, String> {
    let mut request = client.get(url);
    // An ETag is only meaningful while its body is on disk.
    if stored_path.is_file()
        && let Ok(etag) = std::fs::read_to_string(etag_path)
        && !etag.trim().is_empty()
    {
        request = request.header(reqwest::header::IF_NONE_MATCH, etag.trim());
    }

    let mut response = request.send().await.map_err(|e| error_chain(&e))?;
    let status = response.status();

    if status == reqwest::StatusCode::NOT_MODIFIED {
        let text = std::fs::read_to_string(stored_path)
            .map_err(|e| format!("304 but the stored copy is unreadable: {e}"))?;
        // Record the confirmation: the stored copy's mtime is the
        // moment its content was last known to be current.
        let touched = std::fs::File::options()
            .append(true)
            .open(stored_path)
            .and_then(|f| f.set_modified(SystemTime::now()));
        if let Err(e) = touched {
            tracing::warn!(path = %stored_path.display(), error = %e, "cannot mark stored list as verified");
        }
        return Ok(Acquired {
            text,
            origin: ListOrigin::NotModified,
            verified_age_secs: Some(0),
        });
    }
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_LIST_BYTES as u64)
    {
        return Err(format!("body larger than {MAX_LIST_BYTES} bytes"));
    }
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| error_chain(&e))? {
        if body.len() + chunk.len() > MAX_LIST_BYTES {
            return Err(format!("body larger than {MAX_LIST_BYTES} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    let text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    };

    // A captive portal or an HTML error page served with 200 must not
    // replace the last good copy.
    let counts = sumidero_filter::count_rules(&text);
    if counts.rules == 0 {
        return Err(format!(
            "body holds no rules ({} rejected lines): refusing to store it",
            counts.issues
        ));
    }

    // Atomic replace: a crash mid-write must never leave a truncated
    // stored copy. The ETag is written only after its body.
    match write_atomic(stored_path, text.as_bytes()) {
        Ok(()) => match etag {
            Some(etag) => {
                if let Err(e) = write_atomic(etag_path, etag.as_bytes()) {
                    tracing::warn!(path = %etag_path.display(), error = %e, "cannot store ETag");
                    let _ = std::fs::remove_file(etag_path);
                }
            }
            None => {
                let _ = std::fs::remove_file(etag_path);
            }
        },
        Err(e) => {
            tracing::error!(
                path = %stored_path.display(),
                error = %e,
                next = "check free space and permissions on list_dir",
                "cannot persist the downloaded list; it is used from memory only"
            );
            let _ = std::fs::remove_file(etag_path);
        }
    }

    Ok(Acquired {
        text,
        origin: ListOrigin::Downloaded,
        verified_age_secs: Some(0),
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// `reqwest` errors hide the cause (DNS, TLS, timeout) in `source()`.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(cause) = cur {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        cur = cause.source();
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        write!(s, "{b:02x}").expect("writing to String never fails");
    }
    s
}
