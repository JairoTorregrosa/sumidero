//! The upstream pool against real `DoH` and `DoQ` servers
//! (`sumidero-testkit`): races, outages, reconnects, health.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use sumidero_core::upstream::{Error, UpstreamConfig, UpstreamPool};
use sumidero_testkit::{DnsUpstream, Mode, Pki};

fn roots(pki: &Pki) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    sumidero_core::config::read_extra_roots(&sumidero_core::config::TlsConfig {
        extra_roots: vec![pki.ca_pem_path().to_path_buf()],
    })
    .unwrap()
}

async fn pool(
    pki: &Pki,
    urls: Vec<String>,
    timeout_ms: u64,
    budget: Duration,
) -> Result<UpstreamPool, Error> {
    UpstreamPool::new(&UpstreamConfig {
        urls,
        bootstrap_ips: vec![],
        timeout_ms,
        extra_roots: roots(pki),
        connect_budget: budget,
    })
    .await
}

fn query(name: &str) -> Message {
    let mut q = Message::new(4242, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(
        Name::from_ascii(format!("{name}.")).unwrap(),
        RecordType::A,
    ));
    q
}

async fn two() -> (Arc<Pki>, DnsUpstream, DnsUpstream) {
    let pki = Arc::new(Pki::new());
    let a = DnsUpstream::start(Arc::clone(&pki)).await;
    let b = DnsUpstream::start(Arc::clone(&pki)).await;
    (pki, a, b)
}

#[tokio::test]
async fn resolves_over_doh_and_doq_and_keeps_the_client_id() {
    let pki = Arc::new(Pki::new());
    let up = DnsUpstream::start(Arc::clone(&pki)).await;
    for url in [up.doh_url(), up.doq_url()] {
        let p = pool(&pki, vec![url.clone()], 3000, Duration::from_secs(5))
            .await
            .unwrap();
        let answer = p.resolve(&query("example.test")).await.unwrap();
        assert_eq!(
            answer.metadata.id, 4242,
            "{url}: DoQ sends id 0, the client gets its own back"
        );
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert!(!answer.answers.is_empty(), "{url}");
    }
}

#[tokio::test]
async fn queries_ask_for_dnssec_records() {
    let pki = Arc::new(Pki::new());
    let up = DnsUpstream::start(Arc::clone(&pki)).await;
    up.set_signed(true); // signs only when the query carries DO
    let p = pool(&pki, vec![up.doh_url()], 3000, Duration::from_secs(5))
        .await
        .unwrap();
    let mut q = query("signed.test");
    q.set_edns(Edns::new()); // DO clear from the client
    let answer = p.resolve(&q).await.unwrap();
    assert!(
        answer
            .answers
            .iter()
            .any(|r| r.record_type() == RecordType::RRSIG)
    );
}

#[tokio::test]
async fn the_fastest_upstream_answers() {
    let (pki, slow, fast) = two().await;
    slow.set_mode(Mode::Delay(Duration::from_millis(800)));
    let p = pool(
        &pki,
        vec![slow.doh_url(), fast.doq_url()],
        3000,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let started = Instant::now();
    p.resolve(&query("race.test")).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn servfail_from_one_upstream_is_covered_by_the_other_and_counted() {
    let (pki, broken, good) = two().await;
    broken.set_mode(Mode::ServFail);
    let p = pool(
        &pki,
        vec![broken.doh_url(), good.doh_url()],
        3000,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let answer = p.resolve(&query("x.test")).await.unwrap();
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    tokio::time::sleep(Duration::from_millis(100)).await; // let the losing leg report
    let health = p.health();
    assert_eq!(health.upstreams[0].failures, 1);
    assert_eq!(health.upstreams[1].failures, 0);
    assert_eq!(health.consecutive_all_failed, 0);
}

#[tokio::test]
async fn every_upstream_failing_is_one_error_naming_each() {
    let (pki, a, b) = two().await;
    a.set_mode(Mode::ServFail);
    b.set_mode(Mode::Hang);
    let p = pool(
        &pki,
        vec![a.doh_url(), b.doq_url()],
        300,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let Err(Error::AllFailed(reasons)) = p.resolve(&query("x.test")).await else {
        panic!("expected AllFailed");
    };
    assert_eq!(reasons.len(), 2, "{reasons:?}");
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("SERVFAIL") || r.contains("Server Failure")),
        "{reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r.contains("timed out")),
        "{reasons:?}"
    );
    assert_eq!(p.health().consecutive_all_failed, 1);

    a.set_mode(Mode::Answer);
    p.resolve(&query("y.test")).await.unwrap();
    assert_eq!(
        p.health().consecutive_all_failed,
        0,
        "one answer clears the streak"
    );
}

#[tokio::test]
async fn upstream_down_at_boot_does_not_delay_start_and_joins_when_it_comes_up() {
    let (pki, mut late, up) = two().await;
    late.stop().await;
    let started = Instant::now();
    let p = pool(
        &pki,
        vec![late.doh_url(), up.doh_url()],
        2000,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "start waited {:?}",
        started.elapsed()
    );
    assert_eq!(p.health().upstreams[0].state, "down");
    assert!(p.health().upstreams[0].last_error.is_some());

    late.restart().await;
    // The down upstream is retried on demand (backoff starts at 500 ms).
    let deadline = Instant::now() + Duration::from_secs(10);
    while late.asked("join.test") == 0 {
        assert!(
            Instant::now() < deadline,
            "the late upstream never joined: {:?}",
            p.health()
        );
        p.resolve(&query("join.test")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(p.health().upstreams[0].state, "connected");
}

#[tokio::test]
async fn no_reachable_upstream_at_boot_fails_loud_within_the_budget() {
    let (pki, mut a, mut b) = two().await;
    a.stop().await;
    b.stop().await;
    let started = Instant::now();
    let err = pool(
        &pki,
        vec![a.doh_url(), b.doq_url()],
        500,
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    let msg = err.to_string();
    assert!(
        msg.contains(&a.doh_url()) && msg.contains(&b.doq_url()),
        "{msg}"
    );
}

#[tokio::test]
async fn restarted_upstream_is_reconnected_within_the_query_that_finds_it_dead() {
    let pki = Arc::new(Pki::new());
    let mut up = DnsUpstream::start(Arc::clone(&pki)).await;
    let p = pool(&pki, vec![up.doh_url()], 3000, Duration::from_secs(5))
        .await
        .unwrap();
    p.resolve(&query("before.test")).await.unwrap();

    // The provider restarts: every open connection dies.
    up.restart().await;
    for i in 0..20 {
        let answer = p.resolve(&query(&format!("after{i}.test"))).await;
        assert!(answer.is_ok(), "query {i} after the restart: {answer:?}");
    }
    assert!(p.health().upstreams[0].reconnects >= 1, "{:?}", p.health());
}

#[tokio::test]
async fn hung_connection_is_torn_down_and_the_upstream_recovers() {
    let pki = Arc::new(Pki::new());
    let up = DnsUpstream::start(Arc::clone(&pki)).await;
    let p = pool(&pki, vec![up.doq_url()], 300, Duration::from_secs(5))
        .await
        .unwrap();
    up.set_mode(Mode::Hang);
    assert!(p.resolve(&query("stuck.test")).await.is_err());
    up.set_mode(Mode::Answer);
    // Within the probation the next build may wait; it must come back.
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if p.resolve(&query("ok.test")).await.is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never recovered: {:?}",
            p.health()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(p.health().upstreams[0].consecutive_failures, 0);
}
