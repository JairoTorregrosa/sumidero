//! Blocklist acquisition against a real HTTPS list host whose name is
//! resolved through a real `DoH` upstream (both from `sumidero-testkit`).

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sumidero_core::config::ListSource;
use sumidero_core::lists::{self, Fetcher, ListError, ListOrigin};
use sumidero_core::upstream::{UpstreamConfig, UpstreamPool};
use sumidero_testkit::{DnsUpstream, ListHost, ListMode, Pki};

const LIST: &str = "! Title: test\n||ads.example^\n||tracker.example^\n";

struct Net {
    pki: Arc<Pki>,
    upstream: DnsUpstream,
    host: ListHost,
    fetcher: Fetcher,
    dir: tempfile::TempDir,
}

/// A `DoH` upstream that knows `lists.test`, a list host serving `LIST`
/// as `/l.txt`, and a fetcher trusting the test CA.
async fn net() -> Net {
    let pki = Arc::new(Pki::new());
    let upstream = DnsUpstream::start(Arc::clone(&pki)).await;
    upstream.add_a("lists.test", &[Ipv4Addr::LOCALHOST]);
    let host = ListHost::start(&pki).await;
    host.put("l.txt", LIST);
    let fetcher = fetcher_trusting(&pki, &upstream, true).await;
    Net {
        pki,
        upstream,
        host,
        fetcher,
        dir: tempfile::tempdir().unwrap(),
    }
}

/// The pool always trusts the test CA (it reaches the test upstream);
/// `trust` decides whether the list fetcher does.
async fn fetcher_trusting(pki: &Pki, upstream: &DnsUpstream, trust: bool) -> Fetcher {
    let cfg = sumidero_core::config::TlsConfig {
        extra_roots: vec![pki.ca_pem_path().to_path_buf()],
    };
    let roots = sumidero_core::config::read_extra_roots(&cfg).unwrap();
    let pool = UpstreamPool::new(&UpstreamConfig {
        urls: vec![upstream.doh_url()],
        bootstrap_ips: vec![],
        timeout_ms: 3000,
        extra_roots: roots.clone(),
    })
    .await
    .unwrap();
    let fetcher_roots = if trust { roots } else { Vec::new() };
    Fetcher::new(&fetcher_roots, Arc::new(pool)).unwrap()
}

fn src(name: &str, url: Option<String>, path: Option<&Path>) -> ListSource {
    ListSource {
        name: name.into(),
        url,
        path: path.map(Path::to_path_buf),
    }
}

#[tokio::test]
async fn list_host_is_resolved_through_the_upstreams_not_the_host_resolver() {
    // `lists.test` exists only in the test upstream's zone: the load can
    // only succeed if the fetcher asked the upstream. In production this
    // is what keeps a filtering host resolver (1.1.1.3 answers 0.0.0.0
    // for nsfw.oisd.nl) from starving the NSFW list.
    let n = net().await;
    let sources = [src("nsfw", Some(n.host.named_url("l.txt")), None)];
    let loaded = lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    assert_eq!(loaded.reports[0].origin, ListOrigin::Downloaded);
    assert_eq!(loaded.reports[0].rules, 2);
    assert!(n.upstream.names().iter().any(|q| q == "lists.test"));
    assert!(matches!(
        loaded.engine.verdict("x.ads.example"),
        sumidero_filter::Verdict::Block { .. }
    ));
}

#[tokio::test]
async fn second_load_revalidates_with_etag_and_marks_the_copy_verified() {
    let n = net().await;
    let sources = [src("l", Some(n.host.url("l.txt")), None)];
    let first = lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    assert_eq!(first.reports[0].origin, ListOrigin::Downloaded);
    let stored = n.dir.path().join("l.txt");
    assert_eq!(std::fs::read_to_string(&stored).unwrap(), LIST);
    assert!(n.dir.path().join("l.etag").is_file());

    // Age the stored copy, then revalidate: 304 resets its age.
    let old = SystemTime::now() - Duration::from_hours(5 * 24);
    std::fs::File::options()
        .append(true)
        .open(&stored)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let second = lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    assert_eq!(second.reports[0].origin, ListOrigin::NotModified);
    assert_eq!(second.hash, first.hash);
    let age = SystemTime::now()
        .duration_since(std::fs::metadata(&stored).unwrap().modified().unwrap())
        .unwrap();
    assert!(
        age < Duration::from_mins(1),
        "304 must refresh the verified time"
    );
    assert_eq!(n.host.requests(), 2);
}

#[tokio::test]
async fn host_failure_serves_the_last_good_copy_and_says_how_old_it_is() {
    let n = net().await;
    let sources = [src("l", Some(n.host.url("l.txt")), None)];
    lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    let stored = n.dir.path().join("l.txt");
    let old = SystemTime::now() - Duration::from_hours(7 * 24);
    std::fs::File::options()
        .append(true)
        .open(&stored)
        .unwrap()
        .set_modified(old)
        .unwrap();

    n.host.set_mode(ListMode::Status(503));
    let loaded = lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    let r = &loaded.reports[0];
    assert!(
        matches!(&r.origin, ListOrigin::StoredAfterFetchFailure { reason } if reason.contains("503"))
    );
    assert!(r.origin.fetch_failed());
    assert!(r.verified_age_secs.unwrap() >= 7 * 86_400);
    assert!(matches!(
        loaded.engine.verdict("ads.example"),
        sumidero_filter::Verdict::Block { .. }
    ));
}

#[tokio::test]
async fn captive_portal_page_never_replaces_the_stored_list() {
    let n = net().await;
    let sources = [src("l", Some(n.host.url("l.txt")), None)];
    lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    // Drop the ETag so the portal's 200 is not short-circuited by a 304.
    std::fs::remove_file(n.dir.path().join("l.etag")).unwrap();

    n.host.set_mode(ListMode::CaptivePortal);
    let loaded = lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    assert!(matches!(&loaded.reports[0].origin,
        ListOrigin::StoredAfterFetchFailure { reason } if reason.contains("no rules")));
    assert_eq!(
        std::fs::read_to_string(n.dir.path().join("l.txt")).unwrap(),
        LIST
    );
}

#[tokio::test]
async fn untrusted_certificate_is_a_fetch_failure() {
    let n = net().await;
    let strict = fetcher_trusting(&n.pki, &n.upstream, false).await;
    let sources = [src("l", Some(n.host.url("l.txt")), None)];
    let err = lists::load(&sources, n.dir.path(), Some(&strict))
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, ListError::Unavailable { .. }), "{msg}");
    assert!(msg.to_ascii_lowercase().contains("certificate"), "{msg}");
}

#[tokio::test]
async fn first_start_without_network_or_copy_is_fatal_but_a_seed_saves_it() {
    let n = net().await;
    n.host.set_mode(ListMode::Status(500));
    let sources = [src("l", Some(n.host.url("l.txt")), None)];
    let err = lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap_err();
    assert!(matches!(err, ListError::Unavailable { .. }));

    let seed = n.dir.path().join("seed.txt");
    std::fs::write(&seed, "||seeded.example^\n").unwrap();
    let sources = [src("l", Some(n.host.url("l.txt")), Some(&seed))];
    let loaded = lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    assert!(matches!(
        loaded.reports[0].origin,
        ListOrigin::SeedAfterFetchFailure { .. }
    ));
    assert!(matches!(
        loaded.engine.verdict("seeded.example"),
        sumidero_filter::Verdict::Block { .. }
    ));
}

#[tokio::test]
async fn offline_load_reads_stored_copies_and_never_touches_the_network() {
    let n = net().await;
    let sources = [src("l", Some(n.host.url("l.txt")), None)];
    lists::load(&sources, n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    let before = n.host.requests();
    let loaded = lists::load(&sources, n.dir.path(), None).await.unwrap();
    assert_eq!(loaded.reports[0].origin, ListOrigin::StoredOffline);
    assert_eq!(n.host.requests(), before);

    let empty = tempfile::tempdir().unwrap();
    let err = lists::load(&sources, empty.path(), None).await.unwrap_err();
    assert!(matches!(err, ListError::Unavailable { .. }));
}

#[tokio::test]
async fn local_rules_file_is_read_every_load() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("user-rules.txt");
    std::fs::write(&rules, "||mask.icloud.com^\n").unwrap();
    let sources = [src("user", None, Some(&rules))];
    let loaded = lists::load(&sources, dir.path(), None).await.unwrap();
    assert_eq!(loaded.reports[0].origin, ListOrigin::LocalFile);
    assert!(matches!(
        loaded.engine.verdict("mask.icloud.com"),
        sumidero_filter::Verdict::Block { .. }
    ));

    std::fs::remove_file(&rules).unwrap();
    assert!(matches!(
        lists::load(&sources, dir.path(), None).await.unwrap_err(),
        ListError::Read { .. }
    ));
}

#[tokio::test]
async fn list_dir_is_created_online_only() {
    let n = net().await;
    let missing = n.dir.path().join("state/lists");
    let sources = [src("l", Some(n.host.url("l.txt")), None)];
    assert!(matches!(
        lists::load(&sources, &missing, None).await.unwrap_err(),
        ListError::ListDir(_)
    ));
    assert!(!missing.exists());
    lists::load(&sources, &missing, Some(&n.fetcher))
        .await
        .unwrap();
    assert!(missing.join("l.txt").is_file());
}

#[tokio::test]
async fn hash_names_and_reports_follow_list_order() {
    let n = net().await;
    n.host.put("b.txt", "||b.example^\n##.cosmetic\n");
    let a = src("a", Some(n.host.url("l.txt")), None);
    let b = src("b", Some(n.host.url("b.txt")), None);
    let ab = lists::load(&[a.clone(), b.clone()], n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    let ba = lists::load(&[b, a], n.dir.path(), Some(&n.fetcher))
        .await
        .unwrap();
    assert_eq!(ab.names, ["a", "b"]);
    assert_eq!(ab.reports[1].rules, 1);
    assert_eq!(ab.reports[1].issues, 1);
    assert_ne!(ab.hash, ba.hash);
    assert_eq!(ab.total_rules(), 3);
}
