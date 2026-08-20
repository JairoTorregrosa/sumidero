//! Pipeline behavior with a mock upstream and a real temp database.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::IpNet;
use sumidero_core::cache::Cache;
use sumidero_core::db::Db;
use sumidero_core::safesearch::SafeSearch;
use sumidero_core::server::{Pipeline, Upstream, client_allowed, synth_block_response};
use sumidero_core::upstream::Error as UpstreamError;
use sumidero_filter::{EngineBuilder, parse_list};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
const OUTSIDER: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

/// Mock upstream: answers A 1.2.3.4 for anything, counts calls.
#[derive(Clone)]
struct MockUpstream {
    calls: Arc<AtomicUsize>,
    fail: bool,
    /// Delay before answering, to simulate a slow or hung upstream.
    delay_ms: u64,
    /// Panic on this many leading resolve calls (0 = never), to test
    /// that a dying lookup task cannot wedge shared state.
    panic_times: usize,
    /// Answer like a DNSSEC-signed zone: RRSIG alongside the A record,
    /// plus an OPT with DO set, the way a real upstream replies to the
    /// DO-bit query we always send.
    signed: bool,
}

impl MockUpstream {
    fn ok() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
            delay_ms: 0,
            panic_times: 0,
            signed: false,
        }
    }
    fn failing() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: true,
            delay_ms: 0,
            panic_times: 0,
            signed: false,
        }
    }
    fn signed() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
            delay_ms: 0,
            panic_times: 0,
            signed: true,
        }
    }
    fn slow(delay_ms: u64) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
            delay_ms,
            panic_times: 0,
            signed: false,
        }
    }
}

impl Upstream for MockUpstream {
    async fn resolve(&self, query: &Message) -> Result<Message, UpstreamError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }
        assert!(
            call >= self.panic_times,
            "injected panic: resolve call {call} dies"
        );
        if self.fail {
            return Err(UpstreamError::AllFailed(vec!["mock down".into()]));
        }
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = ResponseCode::NoError;
        for q in &query.queries {
            resp.add_query(q.clone());
            resp.add_answer(Record::from_rdata(
                q.name.clone(),
                600,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            ));
            if self.signed {
                resp.add_answer(Record::from_rdata(
                    q.name.clone(),
                    600,
                    RData::Unknown {
                        code: RecordType::RRSIG,
                        rdata: hickory_proto::rr::rdata::NULL::with(vec![0xde, 0xad, 0xbe, 0xef]),
                    },
                ));
            }
        }
        if self.signed {
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(true);
            resp.set_edns(edns);
        }
        Ok(resp)
    }
}

fn query(name: &str, rtype: RecordType) -> Message {
    let mut msg = Message::new(4242, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    msg.metadata.recursion_desired = true;
    msg
}

struct Fixture {
    pipeline: Pipeline<MockUpstream>,
    calls: Arc<AtomicUsize>,
    db: Db,
    _tmp: tempfile::TempDir,
}

fn fixture_with(rules: &str, upstream: MockUpstream) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("test.sqlite")).unwrap();
    let parsed = parse_list(rules);
    assert!(parsed.issues.is_empty(), "{:?}", parsed.issues);
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    let calls = Arc::clone(&upstream.calls);
    let pipeline = Pipeline::new(
        builder.build(),
        vec!["test-list".to_string()],
        Cache::new(128),
        SafeSearch::new(true, &["google"]).unwrap(),
        upstream,
        db.writer(),
        vec!["192.168.0.0/16".parse::<IpNet>().unwrap()],
    );
    Fixture {
        pipeline,
        calls,
        db,
        _tmp: tmp,
    }
}

fn fixture(rules: &str) -> Fixture {
    fixture_with(rules, MockUpstream::ok())
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
    let f = fixture("||blocked.test^");
    let resp = f
        .pipeline
        .handle_at(
            &query("allowed.test.", RecordType::A),
            OUTSIDER,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn any_query_refused() {
    let f = fixture("||blocked.test^");
    let resp = f
        .pipeline
        .handle_at(
            &query("allowed.test.", RecordType::ANY),
            CLIENT,
            Instant::now(),
        )
        .await;
    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn blocked_domain_gets_nxdomain_case_insensitive() {
    let f = fixture("||blocked.test^");
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
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn excepted_domain_resolves_upstream() {
    let f = fixture("||blocked.test^\n@@safe.blocked.test");
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
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn allowed_domain_answer_preserves_request_id() {
    let f = fixture("||blocked.test^");
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
    let f = fixture("||blocked.test^");
    let q = query("cached.test.", RecordType::A);
    let now = Instant::now();
    let r1 = f.pipeline.handle_at(&q, CLIENT, now).await;
    let r2 = f.pipeline.handle_at(&q, CLIENT, now).await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        1,
        "second hit must come from cache"
    );
}

#[tokio::test]
async fn upstream_failure_yields_servfail() {
    let f = fixture_with("||blocked.test^", MockUpstream::failing());
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
    let f = fixture_with("||blocked.test^", MockUpstream::failing());
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
    let f = fixture("||blocked.test^");
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
    // The target's A record is appended (resolved via the mock upstream).
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
    let f = fixture("||blocked.test^");
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
    let f = fixture("||blocked.test^");
    let q = query("newly-blocked.test.", RecordType::A);
    let r1 = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert_eq!(r1.metadata.response_code, ResponseCode::NoError);
    let parsed = parse_list("||newly-blocked.test^");
    let mut b = EngineBuilder::new();
    b.add_list(parsed.rules);
    f.pipeline.swap_engine(b.build(), vec!["v2".to_string()]);
    let r2 = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NXDomain);
}

// ---------------------------------------------------------------------------
// Phase 2 review findings — added coverage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_question_gets_formerr_and_is_logged() {
    let f = fixture("||blocked.test^");
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
    let f = fixture("||blocked.test^");
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

    let f2 = fixture_with("||blocked.test^", MockUpstream::failing());
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
    let f = fixture("||blocked.test^");
    let q = query("stale.test.", RecordType::A);
    let t0 = Instant::now();
    f.pipeline.handle_at(&q, CLIENT, t0).await;
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);

    // Mock TTL is 600s (>= min-TTL clamp); stale window is 1800s.
    let t_stale = t0 + std::time::Duration::from_secs(650);
    let r = f.pipeline.handle_at(&q, CLIENT, t_stale).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    // Second stale hit immediately after: refresh must be deduplicated.
    let r2 = f.pipeline.handle_at(&q, CLIENT, t_stale).await;
    assert_eq!(r2.metadata.response_code, ResponseCode::NoError);

    // Let the background refresh land.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
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
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("t.sqlite")).unwrap();
    let parsed = parse_list("||blocked.test^");
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    let pipeline = Pipeline::new(
        builder.build(),
        vec!["l".into()],
        Cache::new(16),
        SafeSearch::new(true, &[]).unwrap(),
        MockUpstream::ok(),
        db.writer(),
        vec!["192.168.0.0/16".parse::<IpNet>().unwrap()],
    );
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
    let f = fixture("||blocked.test^");
    // OUTSIDER refused before the swap.
    let r = f
        .pipeline
        .handle_at(&query("a.test.", RecordType::A), OUTSIDER, Instant::now())
        .await;
    assert_eq!(r.metadata.response_code, ResponseCode::Refused);
    f.pipeline.swap_policy(
        SafeSearch::new(false, &[]).unwrap(),
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
    let f = fixture("||blocked.test^");
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
    let f = fixture_with("", MockUpstream::signed());

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
    let f = fixture_with("", MockUpstream::signed());

    let q = edns_query("signed.test.", RecordType::A, true);
    let resp = f.pipeline.handle_at(&q, CLIENT, Instant::now()).await;
    assert!(has_rrsig(&resp), "a DO client must still get its RRSIGs");
    assert!(resp.edns.as_ref().unwrap().flags().dnssec_ok);
}

#[tokio::test]
async fn plain_client_gets_no_opt_even_from_a_signed_upstream_answer() {
    let f = fixture_with("", MockUpstream::signed());

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
    let f = fixture_with("", MockUpstream::signed());

    // A DO client fills the cache with the signed answer...
    let signed = edns_query("shared.test.", RecordType::A, true);
    let resp = f.pipeline.handle_at(&signed, CLIENT, Instant::now()).await;
    assert!(has_rrsig(&resp));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);

    // ...and a plain client served from that same entry gets it stripped,
    // without a second upstream query.
    let plain = edns_query("shared.test.", RecordType::A, false);
    let resp = f.pipeline.handle_at(&plain, CLIENT, Instant::now()).await;
    assert!(
        !has_rrsig(&resp),
        "cache hit leaked RRSIG to a DO-clear client"
    );
    assert!(!resp.answers.is_empty());
    assert_eq!(
        f.calls.load(Ordering::SeqCst),
        1,
        "stripping must not cost an extra upstream query"
    );
}

// ---------------------------------------------------------------------------
// shadow mode
// ---------------------------------------------------------------------------

/// A fake `AdGuard` on 127.0.0.1: answers 0.0.0.0 for names in its blocklist,
/// 5.6.7.8 otherwise.
async fn spawn_fake_adguard(blocked: &'static [&'static str]) -> std::net::SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(req) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
            resp.metadata.response_code = ResponseCode::NoError;
            for q in &req.queries {
                resp.add_query(q.clone());
                let name = q.name.to_ascii().to_lowercase();
                let ip = if blocked.iter().any(|b| name.starts_with(b)) {
                    Ipv4Addr::UNSPECIFIED
                } else {
                    Ipv4Addr::new(5, 6, 7, 8)
                };
                resp.add_answer(Record::from_rdata(q.name.clone(), 60, RData::A(A(ip))));
            }
            let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

#[tokio::test]
async fn shadow_records_expected_and_real_divergences() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("shadow.sqlite")).unwrap();
    let parsed = parse_list("||blocked.test^");
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    // Reference blocks blocked.test (0.0.0.0 style) AND extra.test, which
    // we do not block.
    let reference = spawn_fake_adguard(&["blocked.test", "extra.test"]).await;
    let mut pipeline = Pipeline::new(
        builder.build(),
        vec!["l".into()],
        Cache::new(16),
        SafeSearch::new(false, &[]).unwrap(),
        MockUpstream::ok(),
        db.writer(),
        vec!["192.168.0.0/16".parse::<IpNet>().unwrap()],
    );
    pipeline.set_shadow(reference);

    // blocked.test: we NXDOMAIN, they 0.0.0.0 -> class "expected".
    pipeline
        .handle_at(
            &query("blocked.test.", RecordType::A),
            CLIENT,
            Instant::now(),
        )
        .await;
    // extra.test: we answer 1.2.3.4, they 0.0.0.0 -> they-block-we-answer.
    pipeline
        .handle_at(&query("extra.test.", RecordType::A), CLIENT, Instant::now())
        .await;
    // plain.test: we 1.2.3.4, they 5.6.7.8 -> same outcome, no divergence.
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
    let f = fixture_with("", MockUpstream::slow(100));
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
        f.calls.load(Ordering::SeqCst),
        1,
        "50 simultaneous misses for one name must collapse into one lookup"
    );
}

/// A failed shared lookup must fail every waiter (SERVFAIL), not hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_share_a_failure_too() {
    let mut upstream = MockUpstream::failing();
    upstream.delay_ms = 100;
    let f = fixture_with("", upstream);
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
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
}

/// Load above the admission cap must be shed with SERVFAIL immediately,
/// never queued as unbounded in-flight work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_cap_sheds_excess_load_with_servfail() {
    use sumidero_core::server::MAX_IN_FLIGHT_QUERIES;

    // An upstream slow enough that admitted queries are still in flight
    // when the excess arrives.
    let f = fixture_with("", MockUpstream::slow(60_000));
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

/// A panicking lookup leader must not strand its followers or leave the
/// single-flight key behind: followers get SERVFAIL, and the next miss
/// for the name starts a fresh lookup that succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_panic_does_not_strand_future_queries() {
    let mut upstream = MockUpstream::slow(50);
    upstream.panic_times = 1;
    let f = fixture_with("", upstream);
    let pipeline = Arc::new(f.pipeline);

    let mut handles = Vec::new();
    for _ in 0..5 {
        let p = Arc::clone(&pipeline);
        handles.push(tokio::spawn(async move {
            p.handle(&query("wedge.example.com.", RecordType::A), CLIENT)
                .await
        }));
    }
    for h in handles {
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), h)
            .await
            .expect("waiters of a dead leader must not hang")
            .unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    }

    // The key must have been cleaned up: a later query for the same
    // name becomes a fresh leader and gets a real answer.
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        pipeline.handle(&query("wedge.example.com.", RecordType::A), CLIENT),
    )
    .await
    .expect("a fresh miss after a leader panic must not hang");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(!resp.answers.is_empty());
}
