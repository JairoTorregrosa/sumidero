//! End-to-end: a real UDP/TCP client against the assembled server on
//! 127.0.0.1:0 (no root, ufw-safe). Blocked domain → NXDOMAIN; allowed
//! domain → mock-upstream answer; both logged to `SQLite`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::IpNet;
use sumidero_core::cache::Cache;
use sumidero_core::db::Db;
use sumidero_core::safesearch::SafeSearch;
use sumidero_core::server::{Pipeline, Upstream, serve};
use sumidero_filter::{EngineBuilder, parse_list};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
struct MockUpstream {
    calls: Arc<AtomicUsize>,
}

impl Upstream for MockUpstream {
    fn resolve(
        &self,
        query: &Message,
    ) -> impl std::future::Future<Output = Result<Message, sumidero_core::upstream::Error>> + Send
    {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = ResponseCode::NoError;
        for q in &query.queries {
            resp.add_query(q.clone());
            resp.add_answer(Record::from_rdata(
                q.name.clone(),
                600,
                RData::A(A(Ipv4Addr::new(9, 9, 9, 9))),
            ));
        }
        std::future::ready(Ok(resp))
    }
}

fn build_query(name: &str) -> Vec<u8> {
    let mut msg = Message::new(7777, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    msg.metadata.recursion_desired = true;
    msg.to_vec().unwrap()
}

struct Env {
    server: sumidero_core::server::RunningServer,
    db: Db,
    _tmp: tempfile::TempDir,
}

/// Build a pipeline and serve it on `binds`.
async fn start_on(binds: &[std::net::SocketAddr]) -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("e2e.sqlite")).unwrap();
    let parsed = parse_list("||blocked.test^");
    assert!(parsed.issues.is_empty());
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    let pipeline = Pipeline::new(
        builder.build(),
        vec!["e2e".to_string()],
        Cache::new(64),
        SafeSearch::new(false, &[]).unwrap(),
        MockUpstream {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        db.writer(),
        vec![
            "127.0.0.0/8".parse::<IpNet>().unwrap(),
            "::1/128".parse::<IpNet>().unwrap(),
        ],
    );
    let server = serve(Arc::new(pipeline), binds).await.unwrap();
    Env {
        server,
        db,
        _tmp: tmp,
    }
}

async fn start() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("e2e.sqlite")).unwrap();
    let parsed = parse_list("||blocked.test^");
    assert!(parsed.issues.is_empty());
    let mut builder = EngineBuilder::new();
    builder.add_list(parsed.rules);
    let pipeline = Pipeline::new(
        builder.build(),
        vec!["e2e".to_string()],
        Cache::new(64),
        SafeSearch::new(false, &[]).unwrap(),
        MockUpstream {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        db.writer(),
        vec!["127.0.0.0/8".parse::<IpNet>().unwrap()],
    );
    let server = serve(Arc::new(pipeline), &["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    Env {
        server,
        db,
        _tmp: tmp,
    }
}

#[tokio::test]
async fn udp_end_to_end_blocked_and_allowed() {
    let env = start().await;
    let addr = env.server.udp_addrs[0];
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    sock.send_to(&build_query("blocked.test."), addr)
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(resp.metadata.id, 7777);
    assert_eq!(resp.authorities[0].data.record_type(), RecordType::SOA);

    sock.send_to(&build_query("allowed.test."), addr)
        .await
        .unwrap();
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    match &resp.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(9, 9, 9, 9)),
        other => panic!("expected A, got {other:?}"),
    }

    env.db.flush();
    let rows = env.db.recent_queries(10).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|r| r.qname == "blocked.test"
                && r.verdict == sumidero_core::db::VerdictKind::Blocked)
    );
    assert!(
        rows.iter()
            .any(|r| r.qname == "allowed.test"
                && r.verdict == sumidero_core::db::VerdictKind::Allowed)
    );

    env.server.shutdown().await;
}

#[tokio::test]
async fn tcp_end_to_end() {
    let env = start().await;
    let addr = env.server.tcp_addrs[0];
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let q = build_query("blocked.test.");
    let len = u16::try_from(q.len()).unwrap();
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&q).await.unwrap();
    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf).await.unwrap();
    let n = usize::from(u16::from_be_bytes(lenbuf));
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.unwrap();
    let resp = Message::from_vec(&buf).unwrap();
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    env.server.shutdown().await;
}

/// Upstream mock returning enough A records to overflow a 512-byte UDP
/// response, to pin the TC path.
#[derive(Clone)]
struct BigAnswerUpstream;

impl Upstream for BigAnswerUpstream {
    fn resolve(
        &self,
        query: &Message,
    ) -> impl std::future::Future<Output = Result<Message, sumidero_core::upstream::Error>> + Send
    {
        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = ResponseCode::NoError;
        for q in &query.queries {
            resp.add_query(q.clone());
            for i in 0..60u8 {
                resp.add_answer(Record::from_rdata(
                    q.name.clone(),
                    600,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, i))),
                ));
            }
        }
        std::future::ready(Ok(resp))
    }
}

#[tokio::test]
async fn udp_oversized_answer_gets_truncated() {
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("tc.sqlite")).unwrap();
    let mut builder = EngineBuilder::new();
    builder.add_list(parse_list("||blocked.test^").rules);
    let pipeline = Pipeline::new(
        builder.build(),
        vec!["e2e".into()],
        Cache::new(16),
        SafeSearch::new(false, &[]).unwrap(),
        BigAnswerUpstream,
        db.writer(),
        vec!["127.0.0.0/8".parse::<IpNet>().unwrap()],
    );
    let server = serve(Arc::new(pipeline), &["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // No EDNS in the query → 512-byte limit applies.
    sock.send_to(&build_query("big.test."), server.udp_addrs[0])
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(n <= 512, "truncated response must fit 512 bytes, got {n}");
    let resp = Message::from_vec(&buf[..n]).unwrap();
    assert!(resp.metadata.truncation, "TC bit must be set");
    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// dual-stack binding
//
// Regression cover for a cutover-blocking bug: on Linux's default
// `net.ipv6.bindv6only=0`, a socket on `[::]:53` also claims every IPv4
// address, so binding `0.0.0.0:53` first and `[::]:53` second failed with
// EADDRINUSE against itself. That is the configuration docs/CUTOVER.md
// tells the operator to use, and it would have failed at the point of no
// return with AdGuard already stopped.
// ---------------------------------------------------------------------------

/// Grab a port that is free right now, for tests that need the *same*
/// port on two addresses (`:0` would allocate two different ones).
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

#[tokio::test]
async fn binds_ipv4_and_ipv6_wildcards_on_the_same_port() {
    let port = free_port();
    let binds: Vec<std::net::SocketAddr> = vec![
        format!("0.0.0.0:{port}").parse().unwrap(),
        format!("[::]:{port}").parse().unwrap(),
    ];

    let env = start_on(&binds).await;
    assert_eq!(env.server.udp_addrs.len(), 2, "both families must bind");
    assert_eq!(env.server.tcp_addrs.len(), 2);

    // Both listeners must actually answer, not merely bind.
    for target in [format!("127.0.0.1:{port}"), format!("[::1]:{port}")] {
        let addr: std::net::SocketAddr = target.parse().unwrap();
        let local = if addr.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let sock = tokio::net::UdpSocket::bind(local).await.unwrap();
        sock.send_to(&build_query("blocked.test."), addr)
            .await
            .unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
                .await
                .expect("no answer from {target}")
                .unwrap();
        let resp = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NXDomain,
            "{target} did not answer correctly"
        );
    }

    env.server.shutdown().await;
}

#[tokio::test]
async fn a_genuinely_taken_port_still_fails_loudly_and_names_itself() {
    let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = squatter.local_addr().unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("e2e.sqlite")).unwrap();
    let pipeline = Pipeline::new(
        EngineBuilder::new().build(),
        vec![],
        Cache::new(8),
        SafeSearch::new(false, &[]).unwrap(),
        MockUpstream {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        db.writer(),
        vec!["127.0.0.0/8".parse::<IpNet>().unwrap()],
    );
    let Err(err) = serve(Arc::new(pipeline), &[addr]).await else {
        panic!("binding an occupied port must fail")
    };
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    assert!(
        err.to_string().contains(&addr.to_string()),
        "the error must name the address that failed: {err}"
    );
}
