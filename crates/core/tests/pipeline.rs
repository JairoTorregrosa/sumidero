//! Pipeline behaviour against a real `DoH` upstream (`sumidero-testkit`)
//! and a real temp database. No stand-ins: the upstream is a
//! `hickory-server` speaking HTTP/2 + TLS on 127.0.0.1.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use ipnet::IpNet;
use sumidero_core::cache::Cache;
use sumidero_core::db::Db;
use sumidero_core::safesearch::SafeSearch;
use sumidero_core::server::{Pipeline, client_allowed, synth_block_response};
use sumidero_core::upstream::{UpstreamConfig, UpstreamPool};
use sumidero_filter::{EngineBuilder, parse_list};
use sumidero_testkit::{DnsUpstream, Mode, Pki};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
const OUTSIDER: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

fn query(name: &str, rtype: RecordType) -> Message {
    let mut msg = Message::new(4242, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    msg.metadata.recursion_desired = true;
    msg
}

struct Fixture {
    pipeline: Pipeline<UpstreamPool>,
    up: DnsUpstream,
    db: Db,
    pki: Arc<Pki>,
    _tmp: tempfile::TempDir,
}

/// A pipeline filtering with `rules`, Google safe search on, resolving
/// through a fresh test upstream; `timeout_ms` bounds each upstream try.
async fn fixture_with(rules: &str, safe_search: SafeSearch, timeout_ms: u64) -> Fixture {
    let pki = Arc::new(Pki::new());
    let up = DnsUpstream::start(Arc::clone(&pki)).await;
    let roots = sumidero_core::config::read_extra_roots(&sumidero_core::config::TlsConfig {
        extra_roots: vec![pki.ca_pem_path().to_path_buf()],
    })
    .unwrap();
    let pool = UpstreamPool::new(&UpstreamConfig {
        urls: vec![up.doh_url()],
        bootstrap_ips: vec![],
        timeout_ms,
        extra_roots: roots,
    })
    .await
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("test.sqlite")).unwrap();
    let parsed = parse_list(rules);
    assert!(parsed.issues.is_empty(), "{:?}", parsed.issues);
    let mut builder = EngineBuilder::new();
    builder.add_list(&parsed.rules);
    let pipeline = Pipeline::new(
        builder.build(),
        vec!["test-list".to_string()],
        Cache::new(1024),
        safe_search,
        pool,
        db.writer(),
        vec!["192.168.0.0/16".parse::<IpNet>().unwrap()],
    );
    Fixture {
        pipeline,
        up,
        db,
        pki,
        _tmp: tmp,
    }
}

async fn fixture(rules: &str) -> Fixture {
    fixture_with(rules, SafeSearch::new(true, &["google"]).unwrap(), 3000).await
}

/// The upstream accepts queries and never answers (the 2026-08-20
/// outage shape); each try gives up after 300 ms.
async fn down(rules: &str) -> Fixture {
    let f = fixture_with(rules, SafeSearch::new(true, &["google"]).unwrap(), 300).await;
    f.up.set_mode(Mode::Hang);
    f
}

/// The upstream signs its answers for clients that set DO, the way a
/// validating resolver answers the DO-bit query sumidero always sends.
async fn signed() -> Fixture {
    let f = fixture("").await;
    f.up.set_signed(true);
    f
}

// ---------------------------------------------------------------------------
// pure helpers
// ---------------------------------------------------------------------------

#[test]
fn client_allowed_matches_networks() {
    let allow: Vec<IpNet> = vec![
        "192.168.0.0/16".parse().unwrap(),
        "::1/128".parse().unwrap(),
    ];
    assert!(client_allowed(&allow, CLIENT));
    assert!(client_allowed(&allow, "::1".parse().unwrap()));
    assert!(!client_allowed(&allow, OUTSIDER));
    assert!(!client_allowed(&allow, "2001:db8::1".parse().unwrap()));
}

#[test]
fn block_response_is_nxdomain_with_soa() {
    let req = query("ads.example.com.", RecordType::A);
    let resp = synth_block_response(&req);
    assert_eq!(resp.metadata.id, req.metadata.id);
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(resp.metadata.message_type, MessageType::Response);
    assert_eq!(resp.queries, req.queries);
    assert_eq!(resp.answers.len(), 0);
    let soa = &resp.authorities[0];
    assert_eq!(soa.data.record_type(), RecordType::SOA);
    assert_eq!(soa.ttl, sumidero_core::server::BLOCK_SOA_TTL);
    match &soa.data {
        RData::SOA(soa) => {
            assert_eq!(soa.mname.to_ascii(), sumidero_core::server::BLOCK_SOA_MNAME);
        }
        other => panic!("expected SOA rdata, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// pipeline verdicts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disallowed_client_refused_and_upstream_untouched() {
    let f = fixture("||blocked.test^").await;
    let resp = f
        .pipeline
        .handle_at(
            &query("allowed.test.", RecordType::A),
            OUTSIDER,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    assert_eq!(f.up.asked("allowed.test"), 0);
}

#[tokio::test]
async fn any_query_refused() {
    let f = fixture("||blocked.test^").await;
    let resp = f
        .pipeline
        .handle_at(
            &query("allowed.test.", RecordType::ANY),
            CLIENT,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    assert_eq!(f.up.asked("allowed.test"), 0);
}

#[tokio::test]
async fn blocked_domain_gets_nxdomain_case_insensitive() {
    let f = fixture("||blocked.test^").await;
    for name in ["blocked.test.", "sub.BLOCKED.test."] {
        let resp = f
            .pipeline
            .handle_at(&query(name, RecordType::A), CLIENT, Instant::now())
            .await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "{name}"
        );
        assert_eq!(resp.authorities[0].data.record_type(), RecordType::SOA);
    }
    assert!(!f.up.names().iter().any(|n| n.ends_with("blocked.test")));
}

#[tokio::test]
async fn excepted_domain_resolves_upstream() {
    let f = fixture("||blocked.test^\n@@safe.blocked.test").await;
    let resp = f
        .pipeline
        .handle_at(
            &query("safe.blocked.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(f.up.asked("safe.blocked.test"), 1);
}

#[tokio::test]
async fn allowed_domain_answer_preserves_request_id() {
    let f = fixture("||blocked.test^").await;
    f.up.add_a("allowed.test", &[Ipv4Addr::new(1, 2, 3, 4)]);
    let resp = f
        .pipeline
        .handle_at(
            &query("allowed.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.id, 4242);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    match &resp.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(1, 2, 3, 4)),
        other => panic!("expected A, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// cache interplay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn second_query_served_from_cache() {
    let f = fixture("||blocked.test^").await;
    let q = query("cached.test.", RecordType::A);
    let now = Instant::now();
    let r1 = f.pipeline.handle_at(&q, CLIENT, now).await;
    let r2 = f.pipeline.handle_at(&q, CLIENT, now).await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        f.up.asked("cached.test"),
        1,
        "second hit must come from cache"
    );
}

#[tokio::test]
async fn upstream_failure_yields_servfail() {
    let f = down("||blocked.test^").await;
    let resp = f
        .pipeline
        .handle_at(
            &query("allowed.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn blocked_still_blocked_when_upstream_down() {
    let f = down("||blocked.test^").await;
    let resp = f
        .pipeline
        .handle_at(
            &query("blocked.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
}

// ---------------------------------------------------------------------------
// safe-search
// ---------------------------------------------------------------------------

#[tokio::test]
async fn safesearch_answers_cname_plus_target_records() {
    let f = fixture("||blocked.test^").await;
    let resp = f
        .pipeline
        .handle_at(
            &query("www.google.com.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let cname = &resp.answers[0];
    assert_eq!(cname.data.record_type(), RecordType::CNAME);
    match &cname.data {
        RData::CNAME(target) => {
            assert_eq!(target.0.to_ascii(), "forcesafesearch.google.com.");
        }
        other => panic!("expected CNAME, got {other:?}"),
    }
    // The target's A record is appended (resolved through the upstream).
    assert!(
        resp.answers
            .iter()
            .any(|r| r.data.record_type() == RecordType::A),
        "target address should be appended"
    );
}

// ---------------------------------------------------------------------------
// query log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_query_lands_in_the_log() {
    let f = fixture("||blocked.test^").await;
    f.pipeline
        .handle_at(
            &query("blocked.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    f.pipeline
        .handle_at(
            &query("allowed.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    f.pipeline
        .handle_at(&query("x.test.", RecordType::A), OUTSIDER, Instant::now())
        .await;
    f.db.flush();
    let rows = f.db.recent_queries(10).unwrap();
    assert_eq!(rows.len(), 3);
    let blocked = rows.iter().find(|r| r.qname == "blocked.test").unwrap();
    assert_eq!(blocked.verdict, sumidero_core::db::VerdictKind::Blocked);
    assert_eq!(blocked.rule.as_deref(), Some("||blocked.test^"));
    assert_eq!(blocked.list, Some(0));
    let allowed = rows.iter().find(|r| r.qname == "allowed.test").unwrap();
    assert_eq!(allowed.verdict, sumidero_core::db::VerdictKind::Allowed);
    assert_eq!(allowed.source, sumidero_core::db::ResponseSource::Upstream);
}

// ---------------------------------------------------------------------------
// engine swap (reload)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn swap_engine_changes_verdicts_without_restart() {
    let f = fixture("||blocked.test^").await;
    let q = query("newly-blocked.test.", RecordType::A);
    let r1 = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    let parsed = parse_list("||newly-blocked.test^");
    let mut b = EngineBuilder::new();
    b.add_list(&parsed.rules);
    f.pipeline.swap_engine(b.build(), vec!["v2".to_string()]);
    let r2 = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NXDomain);
}

// ---------------------------------------------------------------------------
// Phase 2 review findings — added coverage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_question_gets_formerr_and_is_logged() {
    let f = fixture("||blocked.test^").await;
    let empty = Message::new(9, MessageType::Query, OpCode::Query);
    let resp = f.pipeline.handle_at(&empty, CLIENT, Instant::now()).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);
    f.db.flush();
    let rows = f.db.recent_queries(5).unwrap();
    assert_eq!(rows.len(), 1, "FormErr must be logged too");
    assert_eq!(rows[0].qname, "");
}

#[tokio::test]
async fn response_sources_cache_and_failed_land_in_log() {
    let f = fixture("||blocked.test^").await;
    let q = query("cached.test.", RecordType::A);
    let now = Instant::now();
    f.pipeline.handle_at(&q, CLIENT, now).await;
    f.pipeline.handle_at(&q, CLIENT, now).await;
    f.db.flush();
    let rows = f.db.recent_queries(5).unwrap();
    assert!(
        rows.iter()
            .any(|r| r.source == sumidero_core::db::ResponseSource::Cache),
        "cache-served row must be logged as cache: {rows:?}"
    );

    let f2 = down("||blocked.test^").await;
    f2.pipeline
        .handle_at(&query("down.test.", RecordType::A), CLIENT, Instant::now())
        .await;
    f2.db.flush();
    let rows = f2.db.recent_queries(5).unwrap();
    assert_eq!(rows[0].source, sumidero_core::db::ResponseSource::Failed);
    assert_eq!(rows[0].rcode, 2, "SERVFAIL rcode");
}

#[tokio::test]
async fn stale_hit_serves_and_refreshes_once() {
    let f = fixture("||blocked.test^").await;
    f.up.set_ttl(600);
    let q = query("stale.test.", RecordType::A);
    let t0 = Instant::now();
    f.pipeline.handle_at(&q, CLIENT, t0).await;
    assert_eq!(f.up.asked("stale.test"), 1);

    // Upstream TTL is 600s (>= min-TTL clamp); stale window is 1800s.
    let t_stale = t0 + std::time::Duration::from_secs(650);
    let r = f.pipeline.handle_at(&q, CLIENT, t_stale).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    // Second stale hit immediately after: refresh must be deduplicated.
    let r2 = f.pipeline.handle_at(&q, CLIENT, t_stale).await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);

    // Let the background refresh land.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        f.up.asked("stale.test"),
        2,
        "exactly one background refresh for two stale hits"
    );

    f.db.flush();
    let rows = f.db.recent_queries(10).unwrap();
    assert!(
        rows.iter()
            .any(|r| r.source == sumidero_core::db::ResponseSource::Stale),
        "stale-served rows must be logged as stale: {rows:?}"
    );
}

#[tokio::test]
async fn safesearch_youtube_and_aaaa() {
    let f = fixture_with(
        "||blocked.test^",
        SafeSearch::new::<&str>(true, &[]).unwrap(),
        3000,
    )
    .await;
    let pipeline = &f.pipeline;
    for (name, target) in [
        ("m.youtube.com.", "restrictmoderate.youtube.com."),
        ("duckduckgo.com.", "safe.duckduckgo.com."),
    ] {
        let resp = pipeline
            .handle_at(&query(name, RecordType::AAAA), CLIENT, Instant::now())
            .await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError, "{name}");
        match &resp.answers[0].data {
            RData::CNAME(t) => assert_eq!(t.0.to_ascii(), target, "{name}"),
            other => panic!("expected CNAME for {name}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn policy_swap_applies_new_allowlist_and_safesearch() {
    let f = fixture("||blocked.test^").await;
    // OUTSIDER refused before the swap.
    let r = f
        .pipeline
        .handle_at(&query("a.test.", RecordType::A), OUTSIDER, Instant::now())
        .await;
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);
    f.pipeline.swap_policy(
        SafeSearch::new::<&str>(false, &[]).unwrap(),
        vec!["8.8.8.0/24".parse::<IpNet>().unwrap()],
    );
    // Now OUTSIDER is allowed and www.google.com is no longer rewritten.
    let r = f
        .pipeline
        .handle_at(
            &query("www.google.com.", RecordType::A),
            OUTSIDER,
            Instant::now(),
        )
        .await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(
        r.answers
            .iter()
            .all(|a| a.data.record_type() != RecordType::CNAME),
        "safe-search disabled after swap"
    );
    // And CLIENT (192.168/16) is now refused.
    let r = f
        .pipeline
        .handle_at(&query("a.test.", RecordType::A), CLIENT, Instant::now())
        .await;
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn edns_opt_echoed_when_request_has_edns() {
    let f = fixture("||blocked.test^").await;
    let mut q = query("blocked.test.", RecordType::A);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(4096);
    q.set_edns(edns);
    let resp = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert!(resp.edns.is_some(), "EDNS request must get an OPT back");

    let plain = query("blocked.test.", RecordType::A);
    let resp = f.pipeline.handle_at(&plain, CLIENT, Instant::now()).await;
    assert!(resp.edns.is_none(), "non-EDNS request must not grow an OPT");
}

// ---------------------------------------------------------------------------
// DNSSEC record hygiene (RFC 6840 §5.9)
//
// We always set the DO bit on our upstream queries, so upstream answers
// carry RRSIGs regardless of what the client asked for. Observed on the
// live shadow before this was wired: `dig` without `+dnssec` came back
// with RRSIG records for cloudflare.com, nlnetlabs.nl and
// internetsociety.org.
// ---------------------------------------------------------------------------

/// Build a query carrying an OPT record, with the DO bit as given.
fn edns_query(name: &str, rtype: RecordType, dnssec_ok: bool) -> Message {
    let mut msg = query(name, rtype);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(dnssec_ok);
    msg.set_edns(edns);
    msg
}

fn has_rrsig(msg: &Message) -> bool {
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
        .any(|r| r.record_type() == RecordType::RRSIG)
}

#[tokio::test]
async fn rrsig_stripped_when_client_did_not_set_do() {
    let f = signed().await;

    // EDNS client, DO clear: the OPT comes back, the signatures do not.
    let q = edns_query("signed.test.", RecordType::A, false);
    let resp = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert!(!has_rrsig(&resp), "RRSIG leaked to a client with DO clear");
    assert!(!resp.answers.is_empty(), "the A record must survive");
    assert!(resp.edns.is_some(), "EDNS client still gets an OPT");
    assert!(
        !resp.edns.as_ref().unwrap().flags().dnssec_ok,
        "response must not claim DO when the client did not ask"
    );
}

#[tokio::test]
async fn rrsig_kept_when_client_set_do() {
    let f = signed().await;

    let q = edns_query("signed.test.", RecordType::A, true);
    let resp = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert!(has_rrsig(&resp), "a DO client must still get its RRSIGs");
    assert!(resp.edns.as_ref().unwrap().flags().dnssec_ok);
}

#[tokio::test]
async fn plain_client_gets_no_opt_even_from_a_signed_upstream_answer() {
    let f = signed().await;

    // No OPT in the request: RFC 6891 §6.1.1 forbids one in the response,
    // even though the upstream answer we adopted carried one.
    let q = query("signed.test.", RecordType::A);
    let resp = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert!(resp.edns.is_none(), "plain-DNS client must get no OPT back");
    assert!(!has_rrsig(&resp), "RRSIG leaked to a plain-DNS client");
    assert!(!resp.answers.is_empty(), "the A record must survive");
}

#[tokio::test]
async fn one_cache_entry_serves_both_do_and_plain_clients() {
    let f = signed().await;

    // A DO client fills the cache with the signed answer...
    let signed = edns_query("shared.test.", RecordType::A, true);
    let resp = f.pipeline.handle_at(&signed, CLIENT, Instant::now()).await;
    assert!(has_rrsig(&resp));
    assert_eq!(f.up.asked("shared.test"), 1);

    // ...and a plain client served from that same entry gets it stripped,
    // without a second upstream query.
    let plain = edns_query("shared.test.", RecordType::A, false);
    let resp = f.pipeline.handle_at(&plain, CLIENT, Instant::now()).await;
    assert!(
        !has_rrsig(&resp),
        "cache hit leaked RRSIG to a DO-clear client"
    );
    assert_ne!(resp.answers, [] as [hickory_proto::rr::Record; 0]);
    assert_eq!(
        f.up.asked("shared.test"),
        1,
        "stripping must not cost an extra upstream query"
    );
}

// ---------------------------------------------------------------------------
// shadow mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shadow_records_expected_and_real_divergences() {
    let mut f = fixture("||blocked.test^").await;
    // The reference resolver (an AdGuard Home look-alike on plain UDP)
    // answers 0.0.0.0 for blocked.test AND extra.test, which we do not
    // block.
    let reference = DnsUpstream::start(Arc::clone(&f.pki)).await;
    reference.add_a("blocked.test", &[Ipv4Addr::UNSPECIFIED]);
    reference.add_a("extra.test", &[Ipv4Addr::UNSPECIFIED]);
    f.pipeline.set_shadow(reference.udp_addr());
    let (pipeline, db) = (&f.pipeline, &f.db);

    // blocked.test: we NXDOMAIN, they 0.0.0.0 -> class "expected".
    pipeline
        .handle_at(
            &query("blocked.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    // extra.test: we answer an address, they 0.0.0.0 -> they-block-we-answer.
    pipeline
        .handle_at(&query("extra.test.", RecordType::A), CLIENT, Instant::now())
        .await;
    // plain.test: both answer an address -> same outcome, no divergence.
    pipeline
        .handle_at(&query("plain.test.", RecordType::A), CLIENT, Instant::now())
        .await;

    // Let the fire-and-forget comparisons land.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    db.flush();
    let rows = db.recent_divergences(10).unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let expected = rows.iter().find(|r| r.qname == "blocked.test").unwrap();
    assert_eq!(expected.class, "expected");
    assert!(expected.ours.starts_with("blocked/"));
    let theirs = rows.iter().find(|r| r.qname == "extra.test").unwrap();
    assert_eq!(theirs.class, "they-block-we-answer");
    assert!(!rows.iter().any(|r| r.qname == "plain.test"));
}

// ---------------------------------------------------------------------------
// load defects (2026-08-20 review): single-flight + admission control
// ---------------------------------------------------------------------------

/// Many simultaneous misses for the same name must share one upstream
/// lookup instead of each doing full independent upstream work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_share_one_upstream_lookup() {
    let f = fixture("").await;
    f.up.set_mode(Mode::Delay(Duration::from_millis(100)));
    let pipeline = Arc::new(f.pipeline);

    let mut handles = Vec::new();
    for _ in 0..50 {
        let p = Arc::clone(&pipeline);
        handles.push(tokio::spawn(async move {
            p.handle(&query("example.com.", RecordType::A), CLIENT)
                .await
        }));
    }
    for h in handles {
        let resp = h.await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(!resp.answers.is_empty(), "every waiter must get the answer");
    }
    assert_eq!(
        f.up.asked("example.com"),
        1,
        "50 simultaneous misses for one name must collapse into one lookup"
    );
}

/// A failed shared lookup must fail every waiter (SERVFAIL), not hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_share_a_failure_too() {
    let f = down("").await;
    let pipeline = Arc::new(f.pipeline);

    let mut handles = Vec::new();
    for _ in 0..20 {
        let p = Arc::clone(&pipeline);
        handles.push(tokio::spawn(async move {
            p.handle(&query("down.example.com.", RecordType::A), CLIENT)
                .await
        }));
    }
    for h in handles {
        let resp = h.await.unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    }
    assert_eq!(f.up.asked("down.example.com"), 1);
}

/// Load above the admission cap must be shed with SERVFAIL immediately,
/// never queued as unbounded in-flight work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_cap_sheds_excess_load_with_servfail() {
    use sumidero_core::server::MAX_IN_FLIGHT_QUERIES;

    // An upstream slow enough that admitted queries are still in flight
    // when the excess arrives.
    let f = fixture_with("", SafeSearch::new::<&str>(false, &[]).unwrap(), 60_000).await;
    f.up.set_mode(Mode::Hang);
    let pipeline = Arc::new(f.pipeline);

    let mut handles = Vec::new();
    for i in 0..MAX_IN_FLIGHT_QUERIES + 100 {
        let p = Arc::clone(&pipeline);
        let name = format!("n{i}.example.com.");
        handles.push(tokio::spawn(async move {
            p.handle(&query(&name, RecordType::A), CLIENT).await
        }));
    }

    // The excess queries must come back SERVFAIL fast, while the
    // admitted ones are still waiting on the (hung) upstream.
    let mut shed = 0usize;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    for h in handles {
        // Admitted queries are (correctly) still blocked on the hung
        // upstream and time out here; keep scanning — the shed ones
        // resolved already.
        if let Ok(resp) = tokio::time::timeout_at(deadline, h).await {
            let resp = resp.unwrap();
            assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
            shed += 1;
        }
    }
    assert!(
        shed >= 100,
        "excess load must be shed with SERVFAIL, got {shed} fast answers"
    );
    assert!(
        pipeline.in_flight() <= MAX_IN_FLIGHT_QUERIES,
        "in-flight work must stay bounded, saw {}",
        pipeline.in_flight()
    );
}

// ---------------------------------------------------------------------------
// TTL fidelity and the resolution-failure cache (RFC 2308, 8767, 9520)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn short_ttl_answer_goes_stale_on_time_and_is_refreshed_in_the_background() {
    let f = fixture("").await;
    f.up.set_ttl(30);
    let q = query("cdn.test.", RecordType::A);
    let t0 = Instant::now();
    let first = f.pipeline.handle_at(&q, CLIENT, t0).await;
    assert_eq!(first.answers[0].ttl, 30);

    let fresh = f
        .pipeline
        .handle_at(&q, CLIENT, t0 + Duration::from_secs(20))
        .await;
    assert_eq!(fresh.answers[0].ttl, 10, "fresh hits count the TTL down");
    assert_eq!(f.up.asked("cdn.test"), 1);

    // Past the published TTL: served at once with TTL 30, refreshed behind.
    let stale = f
        .pipeline
        .handle_at(&q, CLIENT, t0 + Duration::from_secs(31))
        .await;
    assert_eq!(stale.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        stale.answers[0].ttl,
        sumidero_core::cache::STALE_ANSWER_TTL_SECS
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(f.up.asked("cdn.test"), 2, "one background refresh");
}

#[tokio::test]
async fn broken_name_is_asked_once_per_hold_not_once_per_query() {
    let f = fixture("").await;
    f.up.set_mode(Mode::ServFail);
    let q = query("broken.test.", RecordType::A);
    let t0 = Instant::now();
    let first = f.pipeline.handle_at(&q, CLIENT, t0).await;
    assert_eq!(first.metadata.response_code, ResponseCode::ServFail);
    for s in [1, 2, 4] {
        let r = f
            .pipeline
            .handle_at(&q, CLIENT, t0 + Duration::from_secs(s))
            .await;
        assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    }
    assert_eq!(
        f.up.asked("broken.test"),
        1,
        "held for 5 s after the first failure"
    );

    // The hold ends; the next failure doubles it to 10 s.
    let t1 = t0 + Duration::from_secs(5);
    f.pipeline.handle_at(&q, CLIENT, t1).await;
    assert_eq!(f.up.asked("broken.test"), 2);
    f.pipeline
        .handle_at(&q, CLIENT, t1 + Duration::from_secs(9))
        .await;
    assert_eq!(f.up.asked("broken.test"), 2);

    // Other types of the same name are not held.
    f.pipeline
        .handle_at(&query("broken.test.", RecordType::AAAA), CLIENT, t1)
        .await;
    assert_eq!(f.up.asked("broken.test"), 3);

    f.db.flush();
    let rows = f.db.recent_queries(10).unwrap();
    assert_eq!(
        rows.iter()
            .filter(|r| r.source == sumidero_core::db::ResponseSource::FailureCached)
            .count(),
        4
    );
}

#[tokio::test]
async fn upstream_outage_answers_repeats_instantly_instead_of_timing_out_again() {
    let f = down("").await;
    let q = query("anything.test.", RecordType::A);
    let t0 = Instant::now();
    let started = Instant::now();
    assert_eq!(
        f.pipeline
            .handle_at(&q, CLIENT, t0)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "the first one waits for the timeout"
    );
    let started = Instant::now();
    let r = f
        .pipeline
        .handle_at(&q, CLIENT, t0 + Duration::from_secs(1))
        .await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "the repeat is answered from the hold"
    );
}

#[tokio::test]
async fn stale_answer_beats_a_failure_hold() {
    let f = fixture_with("", SafeSearch::new::<&str>(false, &[]).unwrap(), 300).await;
    f.up.set_ttl(60);
    let q = query("known.test.", RecordType::A);
    let t0 = Instant::now();
    f.pipeline.handle_at(&q, CLIENT, t0).await;

    f.up.set_mode(Mode::Hang);
    for s in [61, 62, 3600] {
        let r = f
            .pipeline
            .handle_at(&q, CLIENT, t0 + Duration::from_secs(s))
            .await;
        assert_eq!(r.metadata.response_code, ResponseCode::NoError, "+{s}s");
        assert_ne!(r.answers.len(), 0, "+{s}s");
    }
}
