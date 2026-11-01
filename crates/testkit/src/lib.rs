//! Real local servers for sumidero's tests.
//!
//! Every test that needs "the internet" talks to one of these over real
//! sockets and real protocols, never to an in-process stand-in:
//!
//! - [`DnsUpstream`]: a recursive-resolver look-alike serving DNS over
//!   HTTPS (HTTP/2 + TLS) and DNS over QUIC, built on `hickory-server`.
//!   Its [`Mode`] reproduces what real upstreams do on a bad day:
//!   answer SERVFAIL, hang, answer slowly, or vanish ([`DnsUpstream::stop`]
//!   drops the listeners *and* every open connection).
//! - [`ListHost`]: an HTTPS (HTTP/1.1 + TLS) blocklist host with `ETag`
//!   revalidation that can also fail, stall, or serve a captive-portal
//!   page.
//! - [`Pki`]: a throwaway CA. Its PEM goes into sumidero's
//!   `[tls] extra_roots`, the same knob an operator uses for a private
//!   resolver.

#![allow(
    clippy::missing_panics_doc,
    reason = "test support: a panic here is a failed test, reported where it happens"
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Metadata, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::Server;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── PKI ─────────────────────────────────────────────────────────────

/// A test CA plus one server certificate for `127.0.0.1`, `localhost`
/// and `lists.test`.
pub struct Pki {
    dir: tempfile::TempDir,
    ca_pem: PathBuf,
    cert: CertificateDer<'static>,
    key_der: Vec<u8>,
}

impl Pki {
    /// # Panics
    /// If key generation or signing fails (never on a working host).
    #[must_use]
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "sumidero test CA");
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca cert");

        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_params = rcgen::CertificateParams::new(vec![
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
            "lists.test".to_owned(),
        ])
        .expect("leaf params");
        let leaf = leaf_params.signed_by(&leaf_key, &ca).expect("leaf cert");

        let dir = tempfile::tempdir().expect("tempdir");
        let ca_pem = dir.path().join("test-ca.pem");
        std::fs::write(&ca_pem, ca.pem()).expect("write ca pem");
        Self {
            dir,
            ca_pem,
            cert: leaf.der().clone(),
            key_der: leaf_key.serialize_der(),
        }
    }

    /// PEM of the CA, for `[tls] extra_roots`.
    #[must_use]
    pub fn ca_pem_path(&self) -> &Path {
        &self.ca_pem
    }

    /// Scratch directory that lives as long as the PKI.
    #[must_use]
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    fn cert_resolver(&self) -> Arc<dyn rustls::server::ResolvesServerCert> {
        let provider = rustls::crypto::ring::default_provider();
        let ck =
            rustls::sign::CertifiedKey::from_der(vec![self.cert.clone()], self.key(), &provider)
                .expect("certified key");
        Arc::new(rustls::sign::SingleCertAndKey::from(ck))
    }

    fn http1_config(&self) -> Arc<rustls::ServerConfig> {
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key())
            .expect("server config");
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    }
}

impl Default for Pki {
    fn default() -> Self {
        Self::new()
    }
}

// ── DNS upstream (DoH + DoQ) ────────────────────────────────────────

/// How the upstream answers right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Answer from the zone; unknown names get a synthesized address
    /// (a recursive resolver answers for the whole internet).
    Answer,
    /// Every query gets SERVFAIL (broken authoritative, DNSSEC failure).
    ServFail,
    /// Accept the query and never answer (the 2026-08-20 hang).
    Hang,
    /// Answer correctly after this delay.
    Delay(Duration),
}

#[derive(Debug, Default)]
struct Zone {
    /// name (lowercase, no dot) → CNAME target.
    cnames: HashMap<String, String>,
    /// name → A records.
    a: HashMap<String, Vec<Ipv4Addr>>,
    /// Names answered NXDOMAIN.
    nx: Vec<String>,
}

struct UpstreamState {
    mode: Mutex<Mode>,
    /// Answer like a DNSSEC-signed zone to queries with the DO bit.
    signed: std::sync::atomic::AtomicBool,
    zone: Mutex<Zone>,
    ttl: AtomicU64,
    queries: AtomicU64,
    names: Mutex<Vec<String>>,
}

#[derive(Clone)]
struct Handler(Arc<UpstreamState>);

/// Deterministic documentation-range address for a name.
fn synth_v4(name: &str) -> Ipv4Addr {
    let h = name
        .bytes()
        .fold(7u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)));
    Ipv4Addr::new(198, 51, 100, u8::try_from(h % 250).unwrap_or(0) + 1)
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: hickory_net::runtime::Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let s = &self.0;
        s.queries.fetch_add(1, Ordering::SeqCst);
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        let Some(query) = request.queries.queries().first() else {
            metadata.response_code = ResponseCode::FormErr;
            return send(&mut response_handle, request, metadata, &[], &[]).await;
        };
        let qname = query
            .name()
            .to_string()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        s.names.lock().expect("names").push(qname.clone());
        let mode = *s.mode.lock().expect("mode");
        match mode {
            Mode::Hang => std::future::pending::<()>().await,
            Mode::Delay(d) => tokio::time::sleep(d).await,
            Mode::Answer | Mode::ServFail => {}
        }
        if mode == Mode::ServFail {
            metadata.response_code = ResponseCode::ServFail;
            return send(&mut response_handle, request, metadata, &[], &[]).await;
        }

        let ttl = u32::try_from(s.ttl.load(Ordering::SeqCst)).unwrap_or(300);
        let qtype = query.query_type();
        let (answers, authority, rcode) = {
            let zone = s.zone.lock().expect("zone");
            let mut answers = Vec::new();
            let mut authority = Vec::new();
            let mut rcode = ResponseCode::NoError;
            // Follow CNAMEs inside the zone, the way a recursive resolver
            // returns the whole chain.
            let mut name = qname.clone();
            for _ in 0..8 {
                let Some(target) = zone.cnames.get(&name) else {
                    break;
                };
                answers.push(Record::from_rdata(
                    fqdn(&name),
                    ttl,
                    RData::CNAME(CNAME(fqdn(target))),
                ));
                name.clone_from(target);
            }
            if zone.nx.contains(&name) {
                rcode = ResponseCode::NXDomain;
                authority.push(soa_record(ttl));
            } else {
                match qtype {
                    RecordType::A => {
                        let ips = zone
                            .a
                            .get(&name)
                            .cloned()
                            .unwrap_or_else(|| vec![synth_v4(&name)]);
                        for ip in ips {
                            answers.push(Record::from_rdata(fqdn(&name), ttl, RData::A(A(ip))));
                        }
                    }
                    RecordType::AAAA => {
                        let v4 = synth_v4(&name).octets();
                        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(v4[3]));
                        answers.push(Record::from_rdata(fqdn(&name), ttl, RData::AAAA(AAAA(ip))));
                    }
                    // NOERROR/NODATA with the SOA, as for a real zone.
                    _ => authority.push(soa_record(ttl)),
                }
            }
            (answers, authority, rcode)
        };
        metadata.response_code = rcode;
        let dnssec_ok = request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        let mut answers = answers;
        if s.signed.load(Ordering::SeqCst) && dnssec_ok && !answers.is_empty() {
            let covered = answers[0].record_type();
            answers.push(rrsig_for(&answers[0].name, covered, ttl));
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(true);
            return send_with_edns(
                &mut response_handle,
                request,
                metadata,
                &answers,
                &authority,
                &edns,
            )
            .await;
        }
        send(
            &mut response_handle,
            request,
            metadata,
            &answers,
            &authority,
        )
        .await
    }
}

fn fqdn(name: &str) -> Name {
    Name::from_ascii(format!("{name}.")).expect("valid test name")
}

fn soa_record(ttl: u32) -> Record {
    let origin = fqdn("test");
    Record::from_rdata(
        origin.clone(),
        ttl,
        RData::SOA(SOA::new(
            origin.clone(),
            fqdn("hostmaster.test"),
            1,
            3600,
            600,
            86400,
            ttl,
        )),
    )
}

/// A syntactically valid RRSIG (the signature bytes are filler: nothing
/// in sumidero validates DNSSEC, it only has to carry or strip them).
fn rrsig_for(name: &Name, covered: RecordType, ttl: u32) -> Record {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&u16::from(covered).to_be_bytes());
    rdata.push(13); // ECDSAP256SHA256
    rdata.push(name.num_labels());
    rdata.extend_from_slice(&ttl.to_be_bytes());
    rdata.extend_from_slice(&u32::MAX.to_be_bytes()); // expiration
    rdata.extend_from_slice(&0u32.to_be_bytes()); // inception
    rdata.extend_from_slice(&4242u16.to_be_bytes()); // key tag
    rdata.extend_from_slice(b"\x04test\x00"); // signer
    rdata.extend_from_slice(&[0xab; 64]);
    Record::from_rdata(
        name.clone(),
        ttl,
        RData::Unknown {
            code: RecordType::RRSIG,
            rdata: hickory_proto::rr::rdata::NULL::with(rdata),
        },
    )
}

async fn send_with_edns<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    metadata: Metadata,
    answers: &[Record],
    authority: &[Record],
    edns: &hickory_proto::op::Edns,
) -> ResponseInfo {
    let mut builder = MessageResponseBuilder::from_message_request(request);
    builder.edns(edns);
    let response = builder.build(
        metadata,
        answers.iter(),
        authority.iter(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => ResponseInfo::from(hickory_proto::op::Header {
            metadata: Metadata::response_from_request(&request.metadata),
            counts: hickory_proto::op::HeaderCounts::default(),
        }),
    }
}

async fn send<R: ResponseHandler>(
    handle: &mut R,
    request: &Request,
    metadata: Metadata,
    answers: &[Record],
    authority: &[Record],
) -> ResponseInfo {
    let response = MessageResponseBuilder::from_message_request(request).build(
        metadata,
        answers.iter(),
        authority.iter(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(_) => ResponseInfo::from(hickory_proto::op::Header {
            metadata: Metadata::response_from_request(&request.metadata),
            counts: hickory_proto::op::HeaderCounts::default(),
        }),
    }
}

/// A `DoH` + `DoQ` + plain-UDP upstream on 127.0.0.1.
pub struct DnsUpstream {
    state: Arc<UpstreamState>,
    pki: Arc<Pki>,
    doh: SocketAddr,
    doq: SocketAddr,
    udp: SocketAddr,
    server: Option<Server<Handler>>,
}

impl DnsUpstream {
    /// Start serving on fresh ports.
    ///
    /// # Panics
    /// If the loopback sockets cannot be bound.
    pub async fn start(pki: Arc<Pki>) -> Self {
        let state = Arc::new(UpstreamState {
            mode: Mutex::new(Mode::Answer),
            signed: std::sync::atomic::AtomicBool::new(false),
            zone: Mutex::new(Zone::default()),
            ttl: AtomicU64::new(300),
            queries: AtomicU64::new(0),
            names: Mutex::new(Vec::new()),
        });
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind doh");
        let quic = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind doq");
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp");
        let (doh, doq) = (
            tcp.local_addr().expect("addr"),
            quic.local_addr().expect("addr"),
        );
        let udp = plain.local_addr().expect("addr");
        let mut up = Self {
            state,
            pki,
            doh,
            doq,
            udp,
            server: None,
        };
        up.serve(tcp, quic, plain);
        up
    }

    fn serve(
        &mut self,
        tcp: tokio::net::TcpListener,
        udp: tokio::net::UdpSocket,
        plain: tokio::net::UdpSocket,
    ) {
        let mut server = Server::new(Handler(Arc::clone(&self.state)));
        server
            .register_https_listener(
                tcp,
                Duration::from_secs(5),
                self.pki.cert_resolver(),
                None,
                "/dns-query".to_owned(),
            )
            .expect("register doh");
        server
            .register_quic_listener(udp, Duration::from_secs(5), self.pki.cert_resolver())
            .expect("register doq");
        server.register_socket(plain);
        self.server = Some(server);
    }

    /// `https://127.0.0.1:<port>/dns-query`
    #[must_use]
    pub fn doh_url(&self) -> String {
        format!("https://{}/dns-query", self.doh)
    }

    /// `quic://127.0.0.1:<port>`
    #[must_use]
    pub fn doq_url(&self) -> String {
        format!("quic://{}", self.doq)
    }

    /// Plain DNS over UDP (a classic resolver, e.g. the shadow reference).
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.state.mode.lock().expect("mode") = mode;
    }

    /// Sign answers (RRSIG + DO in the OPT) for clients that set DO.
    pub fn set_signed(&self, signed: bool) {
        self.state.signed.store(signed, Ordering::SeqCst);
    }

    /// How many times `name` was asked, any type.
    #[must_use]
    pub fn asked(&self, name: &str) -> usize {
        self.state
            .names
            .lock()
            .expect("names")
            .iter()
            .filter(|n| *n == name)
            .count()
    }

    /// TTL of every record served from now on.
    pub fn set_ttl(&self, ttl: u32) {
        self.state.ttl.store(u64::from(ttl), Ordering::SeqCst);
    }

    /// `name` answers CNAME `target` (chains are followed).
    pub fn add_cname(&self, name: &str, target: &str) {
        self.state
            .zone
            .lock()
            .expect("zone")
            .cnames
            .insert(name.into(), target.into());
    }

    /// `name` answers these A records.
    pub fn add_a(&self, name: &str, ips: &[Ipv4Addr]) {
        self.state
            .zone
            .lock()
            .expect("zone")
            .a
            .insert(name.into(), ips.to_vec());
    }

    /// `name` answers NXDOMAIN.
    pub fn add_nxdomain(&self, name: &str) {
        self.state.zone.lock().expect("zone").nx.push(name.into());
    }

    /// Queries received so far (all transports).
    #[must_use]
    pub fn queries(&self) -> u64 {
        self.state.queries.load(Ordering::SeqCst)
    }

    /// Names queried so far, in arrival order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.state.names.lock().expect("names").clone()
    }

    /// Go dark: close the listeners and kill every open connection, as
    /// when the WAN drops or the provider restarts.
    pub async fn stop(&mut self) {
        if let Some(server) = self.server.take() {
            server.shutdown_token().cancel();
            drop(server);
        }
        // Give the runtime a beat to tear the connection tasks down.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// Come back on the same ports.
    ///
    /// # Panics
    /// If the ports were taken in the meantime.
    pub async fn restart(&mut self) {
        self.stop().await;
        let tcp = tokio::net::TcpListener::bind(self.doh)
            .await
            .expect("rebind doh");
        let quic = tokio::net::UdpSocket::bind(self.doq)
            .await
            .expect("rebind doq");
        let plain = tokio::net::UdpSocket::bind(self.udp)
            .await
            .expect("rebind udp");
        self.serve(tcp, quic, plain);
    }
}

// ── HTTPS list host ─────────────────────────────────────────────────

/// How the list host behaves right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListMode {
    /// Serve files with `ETag`, honour `If-None-Match` with 304.
    Serve,
    /// Answer every request with this HTTP status.
    Status(u16),
    /// Accept the connection and never answer.
    Stall,
    /// A captive portal: 200 with an HTML page.
    CaptivePortal,
}

struct ListState {
    files: Mutex<HashMap<String, String>>,
    mode: Mutex<ListMode>,
    requests: AtomicU64,
}

/// An HTTPS blocklist host on 127.0.0.1.
pub struct ListHost {
    addr: SocketAddr,
    state: Arc<ListState>,
    task: tokio::task::JoinHandle<()>,
}

impl ListHost {
    /// # Panics
    /// If the loopback socket cannot be bound.
    pub async fn start(pki: &Pki) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let state = Arc::new(ListState {
            files: Mutex::new(HashMap::new()),
            mode: Mutex::new(ListMode::Serve),
            requests: AtomicU64::new(0),
        });
        let acceptor = tokio_rustls::TlsAcceptor::from(pki.http1_config());
        let st = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let (acceptor, st) = (acceptor.clone(), Arc::clone(&st));
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        serve_http(tls, &st).await;
                    }
                });
            }
        });
        Self { addr, state, task }
    }

    /// Publish (or replace) `/name`.
    pub fn put(&self, name: &str, body: &str) {
        self.state
            .files
            .lock()
            .expect("files")
            .insert(name.into(), body.into());
    }

    /// `https://127.0.0.1:<port>/name`
    #[must_use]
    pub fn url(&self, name: &str) -> String {
        format!("https://{}/{name}", self.addr)
    }

    /// `https://lists.test:<port>/name`: needs DNS for `lists.test`.
    #[must_use]
    pub fn named_url(&self, name: &str) -> String {
        format!("https://lists.test:{}/{name}", self.addr.port())
    }

    pub fn set_mode(&self, mode: ListMode) {
        *self.state.mode.lock().expect("mode") = mode;
    }

    #[must_use]
    pub fn requests(&self) -> u64 {
        self.state.requests.load(Ordering::SeqCst)
    }
}

impl Drop for ListHost {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn etag_of(body: &str) -> String {
    let h = body.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("\"{h:016x}\"")
}

async fn serve_http<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    st: &ListState,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    st.requests.fetch_add(1, Ordering::SeqCst);
    let head = String::from_utf8_lossy(&buf).to_string();
    let path = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .trim_start_matches('/')
        .to_owned();
    let if_none_match = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("if-none-match")
            .then(|| v.trim().to_owned())
    });
    let mode = *st.mode.lock().expect("mode");
    let response = match mode {
        ListMode::Stall => {
            std::future::pending::<()>().await;
            return;
        }
        ListMode::Status(code) => {
            format!("HTTP/1.1 {code} Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        }
        ListMode::CaptivePortal => {
            let body = "<html><body>Please log in to the hotel Wi-Fi</body></html>";
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
        }
        ListMode::Serve => {
            let file = st.files.lock().expect("files").get(&path).cloned();
            match file {
                None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    .to_owned(),
                Some(body) => {
                    let etag = etag_of(&body);
                    if if_none_match.as_deref() == Some(etag.as_str()) {
                        format!(
                            "HTTP/1.1 304 Not Modified\r\netag: {etag}\r\nconnection: close\r\n\r\n"
                        )
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\netag: {etag}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    }
                }
            }
        }
    };
    let _ = s.write_all(response.as_bytes()).await;
    let _ = s.shutdown().await;
}

// ── DNS client ──────────────────────────────────────────────────────

/// What a household device sees for one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rcode: ResponseCode,
    /// `(name, type, rdata)` of the answer section, lowercase, no dots.
    pub records: Vec<(String, RecordType, String)>,
    /// TTL of the first answer record, if any.
    pub ttl: Option<u32>,
    pub truncated: bool,
}

impl Answer {
    /// The A/AAAA addresses in the answer.
    #[must_use]
    pub fn addrs(&self) -> Vec<IpAddr> {
        self.records
            .iter()
            .filter_map(|(_, _, data)| data.parse().ok())
            .collect()
    }
}

/// Ask `server` over UDP, the way a phone does.
///
/// # Panics
/// If no answer arrives within 10 s (the test has failed).
pub async fn query_udp(server: SocketAddr, name: &str, qtype: RecordType) -> Answer {
    let sock = tokio::net::UdpSocket::bind(if server.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .await
    .expect("bind client");
    let id = u16::try_from(rand_id(name)).unwrap_or(1);
    let wire = query_wire(id, name, qtype);
    sock.send_to(&wire, server).await.expect("send");
    let mut buf = vec![0u8; 65_535];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
        .await
        .expect("no DNS answer within 10 s")
        .expect("recv");
    parse_answer(&buf[..n], id)
}

/// Ask `server` over TCP.
///
/// # Panics
/// If no answer arrives within 10 s.
pub async fn query_tcp(server: SocketAddr, name: &str, qtype: RecordType) -> Answer {
    let mut s = tokio::net::TcpStream::connect(server)
        .await
        .expect("connect");
    let id = 4242;
    let wire = query_wire(id, name, qtype);
    let len = u16::try_from(wire.len()).expect("small query");
    s.write_all(&len.to_be_bytes()).await.expect("write len");
    s.write_all(&wire).await.expect("write");
    let mut lenbuf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut lenbuf))
        .await
        .expect("no TCP answer within 10 s")
        .expect("read len");
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lenbuf))];
    s.read_exact(&mut buf).await.expect("read body");
    parse_answer(&buf, id)
}

fn rand_id(name: &str) -> u32 {
    name.bytes()
        .fold(17u32, |h, b| h.wrapping_mul(33) ^ u32::from(b))
        & 0xffff
}

fn query_wire(id: u16, name: &str, qtype: RecordType) -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(fqdn(name), qtype));
    msg.metadata.recursion_desired = true;
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    msg.set_edns(edns);
    msg.to_vec().expect("encode query")
}

fn parse_answer(bytes: &[u8], id: u16) -> Answer {
    let msg = hickory_proto::op::Message::from_vec(bytes).expect("parse answer");
    assert_eq!(msg.metadata.id, id, "answer id must echo the query id");
    Answer {
        rcode: msg.metadata.response_code,
        records: msg
            .answers
            .iter()
            .map(|r| {
                (
                    r.name.to_string().trim_end_matches('.').to_owned(),
                    r.record_type(),
                    r.data.to_string().trim_end_matches('.').to_owned(),
                )
            })
            .collect(),
        ttl: msg.answers.first().map(|r| r.ttl),
        truncated: msg.metadata.truncation,
    }
}

/// A port on 127.0.0.1 that was free a moment ago (UDP and TCP).
///
/// # Panics
/// If no port can be bound.
#[must_use]
pub fn free_port() -> u16 {
    loop {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let port = udp.local_addr().expect("addr").port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}
