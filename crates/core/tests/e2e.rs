//! End-to-end: real UDP/TCP clients against the assembled server on
//! 127.0.0.1:0 (no root, ufw-safe), resolving through a real `DoH`
//! upstream from `sumidero-testkit`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use ipnet::IpNet;
use sumidero_core::cache::Cache;
use sumidero_core::db::{Db, VerdictKind};
use sumidero_core::safesearch::SafeSearch;
use sumidero_core::server::{Pipeline, RunningServer, serve};
use sumidero_core::upstream::{UpstreamConfig, UpstreamPool};
use sumidero_filter::{EngineBuilder, parse_list};
use sumidero_testkit::{DnsUpstream, Pki, free_port, query_tcp, query_udp};

struct Env {
    server: RunningServer,
    up: DnsUpstream,
    db: Db,
    _pki: Arc<Pki>,
    _tmp: tempfile::TempDir,
}

async fn pipeline(up: &DnsUpstream, pki: &Pki, db: &Db, rules: &str) -> Pipeline<UpstreamPool> {
    let roots = sumidero_core::config::read_extra_roots(&sumidero_core::config::TlsConfig {
        extra_roots: vec![pki.ca_pem_path().to_path_buf()],
    })
    .unwrap();
    let pool = UpstreamPool::new(&UpstreamConfig {
        urls: vec![up.doh_url()],
        bootstrap_ips: vec![],
        timeout_ms: 3000,
        extra_roots: roots,
    })
    .await
    .unwrap();
    let parsed = parse_list(rules);
    assert!(parsed.issues.is_empty(), "{:?}", parsed.issues);
    let mut builder = EngineBuilder::new();
    builder.add_list(&parsed.rules);
    Pipeline::new(
        builder.build(),
        vec!["e2e".to_string()],
        Cache::new(64),
        SafeSearch::new::<&str>(false, &[]).unwrap(),
        pool,
        db.writer(),
        vec![
            "127.0.0.0/8".parse::<IpNet>().unwrap(),
            "::1/128".parse::<IpNet>().unwrap(),
        ],
    )
}

/// Serve `||blocked.test^` on `binds`.
async fn start_on(binds: &[SocketAddr]) -> Env {
    let pki = Arc::new(Pki::new());
    let up = DnsUpstream::start(Arc::clone(&pki)).await;
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("e2e.sqlite")).unwrap();
    let p = pipeline(&up, &pki, &db, "||blocked.test^").await;
    let server = serve(Arc::new(p), binds).await.unwrap();
    Env {
        server,
        up,
        db,
        _pki: pki,
        _tmp: tmp,
    }
}

async fn start() -> Env {
    start_on(&["127.0.0.1:0".parse().unwrap()]).await
}

#[tokio::test]
async fn udp_end_to_end_blocked_and_allowed() {
    let env = start().await;
    env.up.add_a("allowed.test", &[Ipv4Addr::new(9, 9, 9, 9)]);
    let addr = env.server.udp_addrs[0];

    let blocked = query_udp(addr, "blocked.test", RecordType::A).await;
    assert_eq!(blocked.rcode, ResponseCode::NXDomain);
    assert_eq!(blocked.records.len(), 0, "{:?}", blocked.records);

    let allowed = query_udp(addr, "allowed.test", RecordType::A).await;
    assert_eq!(allowed.rcode, ResponseCode::NoError);
    assert_eq!(
        allowed.addrs(),
        [std::net::IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]
    );
    assert_eq!(
        env.up.asked("blocked.test"),
        0,
        "blocked names never leave the house"
    );

    env.db.flush();
    let rows = env.db.recent_queries(10).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|r| r.qname == "blocked.test" && r.verdict == VerdictKind::Blocked)
    );
    assert!(
        rows.iter()
            .any(|r| r.qname == "allowed.test" && r.verdict == VerdictKind::Allowed)
    );
    env.server.shutdown().await;
}

#[tokio::test]
async fn tcp_end_to_end() {
    let env = start().await;
    let addr = env.server.tcp_addrs[0];
    assert_eq!(
        query_tcp(addr, "blocked.test", RecordType::A).await.rcode,
        ResponseCode::NXDomain
    );
    assert_eq!(
        query_tcp(addr, "allowed.test", RecordType::A).await.rcode,
        ResponseCode::NoError
    );
    env.server.shutdown().await;
}

#[tokio::test]
async fn udp_oversized_answer_gets_truncated_and_tcp_carries_it_whole() {
    let env = start().await;
    let many: Vec<Ipv4Addr> = (0..60u8).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
    env.up.add_a("big.test", &many);

    // The testkit client advertises a 1232-byte EDNS buffer; 60 A
    // records (~1 KB of answers plus names) exceed 512 but not 1232, so
    // ask over a raw no-EDNS socket for the classic limit.
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = hickory_proto::op::Message::new(
        7,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    msg.add_query(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_ascii("big.test.").unwrap(),
        RecordType::A,
    ));
    msg.metadata.recursion_desired = true;
    sock.send_to(&msg.to_vec().unwrap(), env.server.udp_addrs[0])
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(n <= 512, "truncated response must fit 512 bytes, got {n}");
    let resp = hickory_proto::op::Message::from_vec(&buf[..n]).unwrap();
    assert!(resp.metadata.truncation, "TC bit must be set");

    let full = query_tcp(env.server.tcp_addrs[0], "big.test", RecordType::A).await;
    assert_eq!(full.addrs().len(), 60);
    env.server.shutdown().await;
}

// ---------------------------------------------------------------------------
// dual-stack binding
//
// Regression cover for a cutover-blocking bug: on Linux's default
// `net.ipv6.bindv6only=0`, a socket on `[::]:53` also claims every IPv4
// address, so binding `0.0.0.0:53` first and `[::]:53` second failed with
// EADDRINUSE against itself.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn binds_ipv4_and_ipv6_wildcards_on_the_same_port() {
    let port = free_port();
    let binds: Vec<SocketAddr> = vec![
        format!("0.0.0.0:{port}").parse().unwrap(),
        format!("[::]:{port}").parse().unwrap(),
    ];
    let env = start_on(&binds).await;
    assert_eq!(env.server.udp_addrs.len(), 2, "both families must bind");
    assert_eq!(env.server.tcp_addrs.len(), 2);

    // Both listeners must actually answer, not merely bind.
    for target in [format!("127.0.0.1:{port}"), format!("[::1]:{port}")] {
        let addr: SocketAddr = target.parse().unwrap();
        let resp = query_udp(addr, "blocked.test", RecordType::A).await;
        assert_eq!(resp.rcode, ResponseCode::NXDomain, "{target}");
    }
    env.server.shutdown().await;
}

#[tokio::test]
async fn a_genuinely_taken_port_still_fails_loudly_and_names_itself() {
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = squatter.local_addr().unwrap();
    let pki = Arc::new(Pki::new());
    let up = DnsUpstream::start(Arc::clone(&pki)).await;
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("e2e.sqlite")).unwrap();
    let p = pipeline(&up, &pki, &db, "").await;
    let Err(err) = serve(Arc::new(p), &[addr]).await else {
        panic!("binding an occupied port must fail")
    };
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    assert!(
        err.to_string().contains(&addr.to_string()),
        "the error must name the address: {err}"
    );
}
