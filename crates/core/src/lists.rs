//! Blocklist acquisition and engine building. Fail loud.
//!
//! For each [`crate::config::ListSource`] (in `effective_lists` order):
//! - `path` set: read the file; unreadable = error.
//! - `url` set: fetch with `If-None-Match` against the stored `ETag`.
//!   Success stores body + `ETag` under `list_dir/<name>.txt` / `.etag`.
//!   Fetch failure falls back to the stored copy WITH a loud warning;
//!   fetch failure with no stored copy is a hard [`ListError`] — the
//!   daemon must not start half-filtering (settled design).
//! - Both set: `path` seeds the first run, `url` refreshes thereafter.
//!
//! Parse issues from each list are reported (logged + returned), never
//! swallowed. The combined hash is SHA-256 over each list's raw bytes in
//! order — the daemon heartbeat and `explain` compare it.

use std::path::Path;

use sha2::{Digest, Sha256};
use sumidero_filter::LineIssue;

use crate::config::ListSource;

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
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("list {name}: has neither url nor path")]
    NoSource { name: String },
    #[error("list_dir {0} does not exist or is not writable")]
    ListDir(std::path::PathBuf),
    #[error("list_dir {path} could not be created: {source}")]
    ListDirCreate {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
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
    /// Per-list rule counts, same order as `names`.
    pub rule_counts: Vec<usize>,
}

/// Load all lists and compile the engine. `offline` skips fetching and
/// uses stored copies only (used by `check` and tests).
///
/// # Errors
///
/// Returns `ListError::ListDir` if `list_dir` does not exist,
/// `ListError::NoSource` if a list has neither url nor path,
/// `ListError::Unavailable` if a list cannot be fetched and has no
/// stored copy, or `ListError::Read` if a path-only list is unreadable.
///
/// # Panics
///
/// Panics if the `reqwest` client builder fails with default settings,
/// which should not happen under normal operation.
pub async fn load(
    sources: &[ListSource],
    list_dir: &Path,
    offline: bool,
) -> Result<LoadedLists, ListError> {
    // Validate list_dir exists and (when online) is writable.
    //
    // The daemon owns this directory — under the shipped systemd unit it
    // lives inside `StateDirectory`, which exists on first start but is
    // empty. Creating it is part of starting up, not a silent fallback:
    // if creation fails the OS error is propagated and startup aborts.
    // `offline` (`check`) never creates anything, so a misconfigured
    // path is still reported rather than materialised.
    if !offline && !list_dir.is_dir() {
        std::fs::create_dir_all(list_dir).map_err(|source| ListError::ListDirCreate {
            path: list_dir.to_path_buf(),
            source,
        })?;
    }
    if !list_dir.is_dir() {
        return Err(ListError::ListDir(list_dir.to_path_buf()));
    }
    if !offline {
        let probe = list_dir.join(".sumidero-probe");
        if std::fs::write(&probe, b"").is_err() {
            return Err(ListError::ListDir(list_dir.to_path_buf()));
        }
        let _ = std::fs::remove_file(&probe);
    }

    let client = if offline {
        None
    } else {
        Some(
            reqwest::Client::builder()
                .build()
                .expect("reqwest client builder should not fail with default settings"),
        )
    };

    // Memory-critical host: process ONE list at a time — fetch its raw
    // text, then parse and compact it into the builder off the async
    // runtime (>100ms of pure CPU per big list must not stall DNS
    // serving), dropping the raw body and the parsed Vec<Rule> before
    // the next list is fetched. Peak transient stays near one list's
    // parse instead of the whole set's.
    let mut builder = sumidero_filter::EngineBuilder::new();
    let mut names = Vec::with_capacity(sources.len());
    let mut all_issues: Vec<(String, LineIssue)> = Vec::new();
    let mut rule_counts = Vec::with_capacity(sources.len());
    let mut hasher = Sha256::new();

    for source in sources {
        let raw = acquire_list(source, list_dir, offline, client.as_ref()).await?;
        let name = source.name.clone();
        let (b, issues, count, h) = tokio::task::spawn_blocking(move || {
            let mut hasher = hasher;
            hasher.update(raw.as_bytes());
            // Stream the list straight into compact storage: no Vec<Rule>
            // for a multi-million-line list (memory-critical host).
            let mut builder = builder;
            let added = builder.add_list_text(&raw);
            drop(raw);
            let mut issues = Vec::new();
            for issue in added.issues {
                tracing::warn!(
                    list = %name,
                    line = issue.line,
                    text = %issue.text,
                    reason = %issue.reason,
                    "parse issue in list"
                );
                issues.push((name.clone(), issue));
            }
            (builder, issues, added.rules, hasher)
        })
        .await
        .expect("list compile task panicked");
        builder = b;
        hasher = h;
        all_issues.extend(issues);
        rule_counts.push(count);
        names.push(source.name.clone());
    }

    Ok(LoadedLists {
        engine: tokio::task::spawn_blocking(move || builder.build())
            .await
            .expect("engine finish task panicked"),
        names,
        hash: hex_encode(&hasher.finalize()),
        issues: all_issues,
        rule_counts,
    })
}

/// Acquire the raw text for one list source.
async fn acquire_list(
    source: &ListSource,
    list_dir: &Path,
    offline: bool,
    client: Option<&reqwest::Client>,
) -> Result<String, ListError> {
    if source.url.is_none() && source.path.is_none() {
        return Err(ListError::NoSource {
            name: source.name.clone(),
        });
    }

    let stored_path = list_dir.join(format!("{}.txt", source.name));
    let etag_path = list_dir.join(format!("{}.etag", source.name));

    // Path-only list (no url): read the file directly each time
    if source.url.is_none()
        && let Some(path) = &source.path
    {
        return std::fs::read_to_string(path).map_err(|e| ListError::Read {
            name: source.name.clone(),
            path: path.clone(),
            source: e,
        });
    }

    // Has a URL
    if offline {
        // offline mode: use stored copy, then path fallback
        if stored_path.is_file() {
            return std::fs::read_to_string(&stored_path).map_err(|e| ListError::Read {
                name: source.name.clone(),
                path: stored_path,
                source: e,
            });
        }
        if let Some(path) = &source.path
            && path.is_file()
        {
            return std::fs::read_to_string(path).map_err(|e| ListError::Read {
                name: source.name.clone(),
                path: path.clone(),
                source: e,
            });
        }
        return Err(ListError::Unavailable {
            name: source.name.clone(),
            url: source.url.clone().unwrap_or_default(),
            reason: "offline".into(),
        });
    }

    // Online mode: fetch with ETag
    let url = source.url.as_deref().expect("url is Some here");
    let client = client.expect("client is Some when not offline");

    let fetch_result = fetch_with_etag(client, url, &stored_path, &etag_path).await;

    match fetch_result {
        Ok(text) => Ok(text),
        Err(reason) => {
            // Fetch failed; try stored copy
            if stored_path.is_file() {
                tracing::warn!(
                    list = %source.name,
                    url = %url,
                    reason = %reason,
                    "fetch failed, using stored copy"
                );
                return std::fs::read_to_string(&stored_path).map_err(|e| ListError::Read {
                    name: source.name.clone(),
                    path: stored_path,
                    source: e,
                });
            }
            // No stored copy; try path seed
            if let Some(path) = &source.path
                && path.is_file()
            {
                tracing::warn!(
                    list = %source.name,
                    url = %url,
                    reason = %reason,
                    "fetch failed, using path seed"
                );
                return std::fs::read_to_string(path).map_err(|e| ListError::Read {
                    name: source.name.clone(),
                    path: path.clone(),
                    source: e,
                });
            }
            Err(ListError::Unavailable {
                name: source.name.clone(),
                url: url.to_string(),
                reason,
            })
        }
    }
}

/// Fetch a URL with `If-None-Match` `ETag` support.
/// Returns `Ok(text)` on success or 304-with-stored-copy.
/// Returns `Err(reason)` on any failure.
async fn fetch_with_etag(
    client: &reqwest::Client,
    url: &str,
    stored_path: &Path,
    etag_path: &Path,
) -> Result<String, String> {
    let mut request = client.get(url);

    // Send If-None-Match if we have a stored etag
    if let Ok(etag) = std::fs::read_to_string(etag_path) {
        let etag = etag.trim().to_string();
        if !etag.is_empty() {
            request = request.header("If-None-Match", etag);
        }
    }

    let response = request.send().await.map_err(|e| e.to_string())?;

    let status = response.status();

    if status == reqwest::StatusCode::NOT_MODIFIED {
        // 304: use stored copy
        return std::fs::read_to_string(stored_path)
            .map_err(|e| format!("304 but stored copy unreadable: {e}"));
    }

    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }

    // Extract etag before consuming the response
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let body = response.text().await.map_err(|e| e.to_string())?;

    // Sanity-check the payload BEFORE persisting: a captive portal or an
    // HTML error page served with 200 would otherwise overwrite the last
    // good copy with garbage and silently disable filtering.
    let parsed = sumidero_filter::parse_list(&body);
    if parsed.rules.is_empty() {
        return Err(format!(
            "fetched content contains no rules ({} rejected lines) — refusing to store it",
            parsed.issues.len()
        ));
    }

    // Store body and etag — a body-write failure is logged loudly and the
    // etag is NOT written (a stored etag without a stored body would make
    // every future revalidation 304 against a copy that does not exist).
    match std::fs::write(stored_path, &body) {
        Ok(()) => {
            if let Some(etag) = etag {
                let _ = std::fs::write(etag_path, etag);
            }
        }
        Err(e) => {
            tracing::warn!(
                path = %stored_path.display(),
                error = %e,
                "cannot persist fetched list to disk"
            );
            let _ = std::fs::remove_file(etag_path);
        }
    }

    Ok(body)
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
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    /// Minimal HTTP server on 127.0.0.1:0 that serves a fixed response.
    /// Returns (url, handle). Drop handle to stop.
    fn spawn_http_server(body: &str, etag: Option<&str>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/list.txt");
        let body = body.to_string();
        let etag = etag.map(String::from);

        let handle = std::thread::spawn(move || {
            // Accept up to 5 connections for test flexibility
            for stream in listener.incoming().take(5) {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();

                // Check for If-None-Match
                let has_matching_etag = etag.as_ref().is_some_and(|et| {
                    request.lines().any(|line| {
                        line.to_ascii_lowercase().starts_with("if-none-match:")
                            && line.contains(et.as_str())
                    })
                });

                if has_matching_etag {
                    let response = "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let etag_header = etag
                        .as_ref()
                        .map(|e| format!("ETag: {e}\r\n"))
                        .unwrap_or_default();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{etag_header}Connection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        });

        (url, handle)
    }

    /// Spawn a server that always returns an error.
    fn spawn_error_server() -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/list.txt");

        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(3) {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let response = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
        });

        (url, handle)
    }

    fn list_content() -> &'static str {
        "||ads.example.com^\n||tracker.example.com^\n"
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn fresh_fetch_stores_body_and_etag() {
        let (url, _handle) = spawn_http_server(list_content(), Some("\"abc123\""));
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some(url),
            path: None,
        }];
        let result = rt().block_on(load(&sources, dir.path(), false)).unwrap();
        assert_eq!(result.names, vec!["test-list"]);
        assert_eq!(result.rule_counts, vec![2]);
        assert!(dir.path().join("test-list.txt").exists());
        assert!(dir.path().join("test-list.etag").exists());
        let stored_etag = std::fs::read_to_string(dir.path().join("test-list.etag")).unwrap();
        assert_eq!(stored_etag.trim(), "\"abc123\"");
    }

    #[test]
    fn etag_304_reuses_stored_copy() {
        let (url, _handle) = spawn_http_server(list_content(), Some("\"v1\""));
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some(url),
            path: None,
        }];
        // First fetch populates the store
        let r1 = rt().block_on(load(&sources, dir.path(), false)).unwrap();
        // Second fetch should get 304
        let r2 = rt().block_on(load(&sources, dir.path(), false)).unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert_eq!(r2.rule_counts, vec![2]);
    }

    #[test]
    fn fetch_fail_uses_stored_copy() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-populate a stored copy
        std::fs::write(dir.path().join("test-list.txt"), list_content()).unwrap();

        let (url, _handle) = spawn_error_server();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some(url),
            path: None,
        }];

        let result = rt().block_on(load(&sources, dir.path(), false)).unwrap();
        assert_eq!(result.rule_counts, vec![2]);
    }

    #[test]
    fn fetch_fail_no_stored_copy_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let (url, _handle) = spawn_error_server();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some(url),
            path: None,
        }];

        let err = rt()
            .block_on(load(&sources, dir.path(), false))
            .unwrap_err();
        assert!(matches!(err, ListError::Unavailable { .. }));
    }

    #[test]
    fn offline_mode_uses_stored_copy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test-list.txt"), list_content()).unwrap();

        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some("https://example.com/list.txt".into()),
            path: None,
        }];

        let result = rt().block_on(load(&sources, dir.path(), true)).unwrap();
        assert_eq!(result.rule_counts, vec![2]);
    }

    #[test]
    fn offline_mode_no_stored_copy_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some("https://example.com/list.txt".into()),
            path: None,
        }];

        let err = rt().block_on(load(&sources, dir.path(), true)).unwrap_err();
        match err {
            ListError::Unavailable { reason, .. } => {
                assert_eq!(reason, "offline");
            }
            other => panic!("expected Unavailable, got {other}"),
        }
    }

    #[test]
    fn path_only_list_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let list_file = dir.path().join("my-list.txt");
        std::fs::write(&list_file, list_content()).unwrap();
        let list_dir = tempfile::tempdir().unwrap();

        let sources = vec![ListSource {
            name: "local".into(),
            url: None,
            path: Some(list_file),
        }];

        let result = rt()
            .block_on(load(&sources, list_dir.path(), false))
            .unwrap();
        assert_eq!(result.rule_counts, vec![2]);
    }

    #[test]
    fn path_only_list_missing_file_is_error() {
        let list_dir = tempfile::tempdir().unwrap();
        let sources = vec![ListSource {
            name: "local".into(),
            url: None,
            path: Some(std::path::PathBuf::from("/nonexistent/list.txt")),
        }];

        let err = rt()
            .block_on(load(&sources, list_dir.path(), false))
            .unwrap_err();
        assert!(matches!(err, ListError::Read { .. }));
    }

    #[test]
    fn both_path_and_url_stored_copy_takes_precedence() {
        // When fetch fails but stored copy exists, stored copy wins over path seed
        let dir = tempfile::tempdir().unwrap();
        let stored_content = "||stored.example.com^\n";
        std::fs::write(dir.path().join("test-list.txt"), stored_content).unwrap();

        let seed_file = dir.path().join("seed.txt");
        let seed_content = "||seed.example.com^\n";
        std::fs::write(&seed_file, seed_content).unwrap();

        let (url, _handle) = spawn_error_server();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some(url),
            path: Some(seed_file),
        }];

        let result = rt().block_on(load(&sources, dir.path(), false)).unwrap();
        // Should use stored copy, not path seed
        let verdict = result.engine.verdict("stored.example.com");
        assert!(matches!(verdict, sumidero_filter::Verdict::Block { .. }));
        // Seed domain should NOT match (stored was used instead)
        let verdict_seed = result.engine.verdict("seed.example.com");
        assert!(matches!(verdict_seed, sumidero_filter::Verdict::NoMatch));
    }

    #[test]
    fn both_path_and_url_path_seed_fallback() {
        // When no stored copy and fetch fails, fall back to path seed
        let dir = tempfile::tempdir().unwrap();
        let seed_file = dir.path().join("seed.txt");
        let seed_content = "||seed.example.com^\n";
        std::fs::write(&seed_file, seed_content).unwrap();

        let (url, _handle) = spawn_error_server();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some(url),
            path: Some(seed_file),
        }];

        let result = rt().block_on(load(&sources, dir.path(), false)).unwrap();
        let verdict = result.engine.verdict("seed.example.com");
        assert!(matches!(verdict, sumidero_filter::Verdict::Block { .. }));
    }

    #[test]
    fn no_source_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![ListSource {
            name: "broken".into(),
            url: None,
            path: None,
        }];
        let err = rt()
            .block_on(load(&sources, dir.path(), false))
            .unwrap_err();
        assert!(matches!(err, ListError::NoSource { .. }));
    }

    #[test]
    fn hash_stability() {
        let dir = tempfile::tempdir().unwrap();
        let list_file = dir.path().join("my-list.txt");
        std::fs::write(&list_file, list_content()).unwrap();
        let list_dir = tempfile::tempdir().unwrap();

        let sources = vec![ListSource {
            name: "local".into(),
            url: None,
            path: Some(list_file),
        }];

        let r1 = rt()
            .block_on(load(&sources, list_dir.path(), false))
            .unwrap();
        let r2 = rt()
            .block_on(load(&sources, list_dir.path(), false))
            .unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert_eq!(r1.hash.len(), 64);
    }

    #[test]
    fn engine_blocks_domain_from_loaded_list() {
        let (url, _handle) = spawn_http_server("||ads.example.com^\n||tracker.test.org^\n", None);
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some(url),
            path: None,
        }];

        let result = rt().block_on(load(&sources, dir.path(), false)).unwrap();
        assert!(matches!(
            result.engine.verdict("ads.example.com"),
            sumidero_filter::Verdict::Block { .. }
        ));
        assert!(matches!(
            result.engine.verdict("sub.ads.example.com"),
            sumidero_filter::Verdict::Block { .. }
        ));
        assert!(matches!(
            result.engine.verdict("clean.example.com"),
            sumidero_filter::Verdict::NoMatch
        ));
    }

    #[test]
    fn list_dir_missing_is_error() {
        // Online, a missing list_dir is created (see
        // `missing_list_dir_is_created_online`) — but only where the
        // daemon may write. A path it cannot create under is still fatal.
        let sources = vec![ListSource {
            name: "test".into(),
            url: Some("https://example.com/list.txt".into()),
            path: None,
        }];
        let err = rt()
            .block_on(load(&sources, Path::new("/nonexistent/dir"), false))
            .unwrap_err();
        assert!(
            matches!(err, ListError::ListDirCreate { .. }),
            "expected ListDirCreate, got {err}"
        );
    }

    #[test]
    fn names_and_rule_counts_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let list1 = dir.path().join("a.txt");
        let list2 = dir.path().join("b.txt");
        std::fs::write(&list1, "||one.com^\n").unwrap();
        std::fs::write(&list2, "||two.com^\n||three.com^\n").unwrap();
        let list_dir = tempfile::tempdir().unwrap();

        let sources = vec![
            ListSource {
                name: "alpha".into(),
                url: None,
                path: Some(list1),
            },
            ListSource {
                name: "beta".into(),
                url: None,
                path: Some(list2),
            },
        ];

        let result = rt()
            .block_on(load(&sources, list_dir.path(), false))
            .unwrap();
        assert_eq!(result.names, vec!["alpha", "beta"]);
        assert_eq!(result.rule_counts, vec![1, 2]);
    }

    #[test]
    fn parse_issues_reported() {
        let dir = tempfile::tempdir().unwrap();
        let list_file = dir.path().join("issues.txt");
        // A cosmetic rule should produce a parse issue
        std::fs::write(&list_file, "||ok.com^\n##.banner\n").unwrap();
        let list_dir = tempfile::tempdir().unwrap();

        let sources = vec![ListSource {
            name: "issue-list".into(),
            url: None,
            path: Some(list_file),
        }];

        let result = rt()
            .block_on(load(&sources, list_dir.path(), false))
            .unwrap();
        assert_eq!(result.rule_counts, vec![1]);
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].0, "issue-list");
    }

    #[test]
    fn offline_mode_path_seed_fallback() {
        // When offline with url+path and no stored copy, use path seed
        let dir = tempfile::tempdir().unwrap();
        let seed_file = dir.path().join("seed.txt");
        std::fs::write(&seed_file, "||seed.example.com^\n").unwrap();
        let list_dir = tempfile::tempdir().unwrap();

        let sources = vec![ListSource {
            name: "test-list".into(),
            url: Some("https://example.com/list.txt".into()),
            path: Some(seed_file),
        }];

        let result = rt()
            .block_on(load(&sources, list_dir.path(), true))
            .unwrap();
        assert_eq!(result.rule_counts, vec![1]);
    }

    #[test]
    fn hash_differs_by_list_order() {
        let dir = tempfile::tempdir().unwrap();
        let file_a = dir.path().join("a.txt");
        let file_b = dir.path().join("b.txt");
        std::fs::write(&file_a, "||alpha.com^\n").unwrap();
        std::fs::write(&file_b, "||beta.com^\n").unwrap();
        let list_dir = tempfile::tempdir().unwrap();

        let sources_ab = vec![
            ListSource {
                name: "a".into(),
                url: None,
                path: Some(file_a.clone()),
            },
            ListSource {
                name: "b".into(),
                url: None,
                path: Some(file_b.clone()),
            },
        ];
        let sources_ba = vec![
            ListSource {
                name: "b".into(),
                url: None,
                path: Some(file_b),
            },
            ListSource {
                name: "a".into(),
                url: None,
                path: Some(file_a),
            },
        ];

        let r_ab = rt()
            .block_on(load(&sources_ab, list_dir.path(), false))
            .unwrap();
        let r_ba = rt()
            .block_on(load(&sources_ba, list_dir.path(), false))
            .unwrap();
        assert_ne!(r_ab.hash, r_ba.hash, "hash must depend on list order");
    }

    #[cfg(unix)]
    #[test]
    fn list_dir_not_writable_is_error_online() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let sources = vec![ListSource {
            name: "test".into(),
            url: Some("https://example.com/list.txt".into()),
            path: None,
        }];
        let err = rt()
            .block_on(load(&sources, dir.path(), false))
            .unwrap_err();
        assert!(matches!(err, ListError::ListDir(_)));

        // Restore permissions so tempdir cleanup works
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn missing_list_dir_is_created_online() {
        // A fresh install under systemd's DynamicUser gets an empty
        // StateDirectory: /var/lib/sumidero exists, /var/lib/sumidero/
        // lists does not. Refusing to start there would make the
        // documented install path fail on first boot.
        let dir = tempfile::tempdir().unwrap();
        let list_dir = dir.path().join("lists");
        assert!(!list_dir.exists());

        let sources = vec![ListSource {
            name: "test".into(),
            url: Some("https://192.0.2.1/list.txt".into()),
            path: None,
        }];
        // The fetch fails (TEST-NET-1 is unroutable) and there is no
        // stored copy, so loading still errors — but on the list, not on
        // the directory, which must now exist.
        let err = rt().block_on(load(&sources, &list_dir, false)).unwrap_err();
        assert!(
            matches!(err, ListError::Unavailable { .. }),
            "expected a list error, got {err}"
        );
        assert!(list_dir.is_dir(), "list_dir should have been created");
    }

    #[test]
    fn missing_list_dir_is_not_created_offline() {
        // `check` validates; it must never materialise state.
        let dir = tempfile::tempdir().unwrap();
        let list_dir = dir.path().join("lists");

        let sources = vec![ListSource {
            name: "test".into(),
            url: Some("https://example.com/list.txt".into()),
            path: None,
        }];
        let err = rt().block_on(load(&sources, &list_dir, true)).unwrap_err();
        assert!(matches!(err, ListError::ListDir(_)));
        assert!(!list_dir.exists(), "check must not create list_dir");
    }

    #[test]
    fn uncreatable_list_dir_fails_loudly_with_the_os_error() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file where a directory component must be.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let list_dir = blocker.join("lists");

        let sources = vec![ListSource {
            name: "test".into(),
            url: Some("https://example.com/list.txt".into()),
            path: None,
        }];
        let err = rt().block_on(load(&sources, &list_dir, false)).unwrap_err();
        match err {
            ListError::ListDirCreate { path, source } => {
                assert_eq!(path, list_dir);
                // The OS reason must survive to the operator, not be
                // flattened into "does not exist or is not writable".
                assert!(!source.to_string().is_empty());
            }
            other => panic!("expected ListDirCreate, got {other}"),
        }
    }
}
