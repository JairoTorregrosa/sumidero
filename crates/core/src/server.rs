//! DNS server: request pipeline, sockets, SIGHUP reload.
//!
//! Pipeline per request (settled design):
//! 1. Client allowlist — non-allowed source IP gets REFUSED.
//! 2. `ANY` queries get REFUSED (settled).
//! 3. Filter verdict — blocked names get NXDOMAIN + synthetic SOA.
//! 4. Safe-search rewrite — answered as CNAME to the enforced endpoint
//!    plus the endpoint's records resolved through cache/upstream.
//! 5. Cache — fresh hit answers immediately; stale hit answers and
//!    triggers a background refresh.
//! 6. Upstream pool; answers are cached and logged. Total upstream
//!    failure = SERVFAIL (never a silently dropped query).
//!
//! Every request logs a [`crate::db::QueryRecord`] via [`crate::db::DbWriter`].
//! Reload swaps the compiled engine atomically ([`arc_swap`]); a failed
//! reload keeps the old engine and logs loudly — it never half-applies.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::IpNet;
use sumidero_filter::{Engine, Verdict};

use crate::CoreError;
use crate::cache::{Cache, CacheKey, Lookup};
use crate::config::Config;
use crate::db::{DbWriter, LogEvent, QueryRecord, ResponseSource, VerdictKind};
use crate::safesearch::SafeSearch;

/// Hard cap on queries being handled at once; excess load is shed with
/// an immediate SERVFAIL (never a silently dropped query). Sized far
/// above any legitimate household burst — a device retry storm at this
/// level is the daemon's cue to shed, not absorb: each admitted miss
/// fans out to every upstream, and unbounded admission under a hung
/// upstream means unbounded memory under `MemoryMax`.
pub const MAX_IN_FLIGHT_QUERIES: usize = 512;

/// Synthetic SOA fields for blocked answers.
pub const BLOCK_SOA_MNAME: &str = "sumidero.invalid.";
pub const BLOCK_SOA_TTL: u32 = 300;
/// TTL for synthesized safe-search CNAME records.
const SAFESEARCH_CNAME_TTL: u32 = 300;

/// Anything that can answer a DNS query — the real
/// [`crate::upstream::UpstreamPool`], or a test mock.
pub trait Upstream: Send + Sync + 'static {
    fn resolve(
        &self,
        query: &Message,
    ) -> impl std::future::Future<Output = Result<Message, crate::upstream::Error>> + Send;
}

impl Upstream for crate::upstream::UpstreamPool {
    async fn resolve(&self, query: &Message) -> Result<Message, crate::upstream::Error> {
        Self::resolve(self, query).await
    }
}

/// Is this client allowed to query?
#[must_use]
pub fn client_allowed(allow: &[IpNet], client: IpAddr) -> bool {
    allow.iter().any(|net| net.contains(&client))
}

/// Start a response from a request: same id, question copied, RD echoed,
/// RA set (we are a recursive resolver).
fn response_skeleton(request: &Message) -> Message {
    let mut resp = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    for q in &request.queries {
        resp.add_query(q.clone());
    }
    resp.metadata.recursion_desired = request.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    apply_edns(&mut resp, request);
    resp
}

/// Whether the client asked for DNSSEC records (EDNS DO bit).
///
/// We always set DO on our own upstream queries, so upstream answers —
/// and everything the cache holds — can carry RRSIG/NSEC records that
/// this particular client never asked for.
fn client_wants_dnssec(request: &Message) -> bool {
    request
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok)
}

/// EDNS-aware clients expect an OPT in the response; advertise our own
/// receive size (RFC 6891; 1232 is the flag-day recommendation).
///
/// A client that sent no OPT record gets no OPT back (RFC 6891 §6.1.1),
/// and the DO bit we echo is the client's, never the one we used
/// upstream.
fn apply_edns(resp: &mut Message, request: &Message) {
    if request.edns.is_none() {
        // Never hand an OPT record to a client that speaks plain DNS,
        // even when the upstream answer we adopted carried one.
        resp.edns = None;
        return;
    }
    let mut edns = resp.edns.clone().unwrap_or_else(|| {
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        edns
    });
    edns.set_dnssec_ok(client_wants_dnssec(request));
    resp.set_edns(edns);
}

/// NXDOMAIN + synthetic SOA in authority, copying the request id/question.
///
/// # Panics
/// Never in practice: the SOA names are static and valid.
#[must_use]
pub fn synth_block_response(request: &Message) -> Message {
    let mut resp = response_skeleton(request);
    resp.metadata.response_code = ResponseCode::NXDomain;
    let mname = Name::from_ascii(BLOCK_SOA_MNAME).expect("static name is valid");
    let rname = Name::from_ascii("nobody.sumidero.invalid.").expect("static name is valid");
    let soa = SOA::new(mname.clone(), rname, 1, 3600, 900, 604_800, BLOCK_SOA_TTL);
    resp.add_authority(Record::from_rdata(mname, BLOCK_SOA_TTL, RData::SOA(soa)));
    resp
}

/// REFUSED, copying the request id/question.
#[must_use]
pub fn synth_refused(request: &Message) -> Message {
    let mut resp = response_skeleton(request);
    resp.metadata.response_code = ResponseCode::Refused;
    resp
}

/// SERVFAIL, copying the request id/question.
#[must_use]
pub fn synth_servfail(request: &Message) -> Message {
    let mut resp = response_skeleton(request);
    resp.metadata.response_code = ResponseCode::ServFail;
    resp
}

/// Removes a key from the single-flight lookup map when dropped, so the
/// entry cannot outlive its leader task no matter how that task ends.
struct RemoveOnDrop {
    lookups: Arc<
        std::sync::Mutex<
            std::collections::HashMap<CacheKey, tokio::sync::broadcast::Sender<Option<Message>>>,
        >,
    >,
    key: CacheKey,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Ok(mut lookups) = self.lookups.lock() {
            lookups.remove(&self.key);
        }
    }
}

/// Removes a key from the serve-stale refresh set when dropped.
struct RemoveFromSetOnDrop {
    refreshing: Arc<std::sync::Mutex<std::collections::HashSet<CacheKey>>>,
    key: CacheKey,
}

impl Drop for RemoveFromSetOnDrop {
    fn drop(&mut self) {
        if let Ok(mut refreshing) = self.refreshing.lock() {
            refreshing.remove(&self.key);
        }
    }
}

/// The engine plus the list names it was built from, swapped atomically.
struct EngineState {
    engine: Engine,
    #[expect(dead_code, reason = "used by explain/logging in phase 3")]
    list_names: Vec<String>,
}

/// The assembled request pipeline, generic over the upstream so tests can
/// inject a mock.
pub struct Pipeline<U: Upstream> {
    state: ArcSwap<EngineState>,
    cache: Arc<Cache>,
    safesearch: ArcSwap<SafeSearch>,
    upstream: Arc<U>,
    writer: DbWriter,
    allow: ArcSwap<Vec<IpNet>>,
    /// Queries currently inside `handle_at` (graceful shutdown drains it).
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    /// Cache keys with a serve-stale refresh already running (dedup).
    refreshing: Arc<std::sync::Mutex<std::collections::HashSet<CacheKey>>>,
    /// Cache keys with an upstream lookup already in flight: concurrent
    /// misses for one name subscribe to the leader's result instead of
    /// each doing full upstream work.
    lookups: Arc<
        std::sync::Mutex<
            std::collections::HashMap<CacheKey, tokio::sync::broadcast::Sender<Option<Message>>>,
        >,
    >,
    /// Shadow-mode reference resolver, when enabled.
    shadow: Option<crate::shadow::Shadow>,
}

impl<U: Upstream> Pipeline<U> {
    #[must_use]
    pub fn new(
        engine: Engine,
        list_names: Vec<String>,
        cache: Cache,
        safesearch: SafeSearch,
        upstream: U,
        writer: DbWriter,
        allow: Vec<IpNet>,
    ) -> Self {
        Self {
            state: ArcSwap::from_pointee(EngineState { engine, list_names }),
            cache: Arc::new(cache),
            safesearch: ArcSwap::from_pointee(safesearch),
            upstream: Arc::new(upstream),
            writer,
            allow: ArcSwap::from_pointee(allow),
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            refreshing: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            lookups: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            shadow: None,
        }
    }

    /// Query-log events dropped because the writer queue was full.
    ///
    /// Non-zero means the log under-reports; `status` surfaces it.
    #[must_use]
    pub fn log_events_dropped(&self) -> u64 {
        self.writer.dropped()
    }

    /// The upstream, so the daemon can publish its health.
    #[must_use]
    pub fn upstream(&self) -> &U {
        &self.upstream
    }

    /// Enable shadow mode against a reference resolver (call before serving).
    pub fn set_shadow(&mut self, addr: std::net::SocketAddr) {
        self.shadow = Some(crate::shadow::Shadow::new(addr));
    }

    /// Swap the client allowlist and safe-search table (SIGHUP reload).
    pub fn swap_policy(&self, safesearch: SafeSearch, allow: Vec<IpNet>) {
        self.safesearch.store(Arc::new(safesearch));
        self.allow.store(Arc::new(allow));
    }

    /// Number of queries currently being handled.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Swap in a new engine (SIGHUP reload / periodic list refresh).
    pub fn swap_engine(&self, engine: Engine, list_names: Vec<String>) {
        self.state
            .store(Arc::new(EngineState { engine, list_names }));
    }

    /// Answer one request at the current wall-clock instant.
    pub async fn handle(&self, request: &Message, client: IpAddr) -> Message {
        self.handle_at(request, client, Instant::now()).await
    }

    /// Answer one request. Infallible by contract: every failure mode maps
    /// to a DNS response (REFUSED/SERVFAIL/NXDOMAIN), never a dropped
    /// query. `now` is injected so tests control cache time.
    pub async fn handle_at(&self, request: &Message, client: IpAddr, now: Instant) -> Message {
        struct InFlight<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for InFlight<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        let previously_in_flight = self
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let _guard = InFlight(&self.in_flight);

        let started = Instant::now();
        let ts = unix_now();

        // Admission control: past the cap, shed load with an immediate
        // SERVFAIL instead of queueing unbounded work. The client sees a
        // clean, retryable failure and the log records the shed.
        if previously_in_flight >= MAX_IN_FLIGHT_QUERIES {
            return self.shed_overload(request, client, ts, started);
        }

        let Some(query) = request.queries.first() else {
            let mut resp = response_skeleton(request);
            resp.metadata.response_code = ResponseCode::FormErr;
            let mut log = QueryRecord {
                ts,
                client,
                qname: String::new(),
                qtype: 0,
                verdict: VerdictKind::Allowed,
                rule: None,
                list: None,
                source: ResponseSource::Synth,
                rcode: 0,
                duration_us: 0,
            };
            self.finish(&mut log, &resp, started);
            return resp;
        };
        let qname = normalize_qname(&query.name.to_ascii());
        let qtype = query.query_type;

        let mut log = QueryRecord {
            ts,
            client,
            qname: qname.clone(),
            qtype: qtype.into(),
            verdict: VerdictKind::Allowed,
            rule: None,
            list: None,
            source: ResponseSource::Synth,
            rcode: 0,
            duration_us: 0,
        };

        if !client_allowed(&self.allow.load(), client) {
            let resp = synth_refused(request);
            self.finish(&mut log, &resp, started);
            return resp;
        }
        if qtype == RecordType::ANY {
            let resp = synth_refused(request);
            self.finish(&mut log, &resp, started);
            return resp;
        }

        // Filter verdict.
        let state = self.state.load();
        match state.engine.verdict(&qname) {
            Verdict::Block { list, rule } => {
                log.verdict = VerdictKind::Blocked;
                log.rule = Some(rule.text.to_string());
                log.list = Some(list);
                let resp = synth_block_response(request);
                self.finish(&mut log, &resp, started);
                self.shadow_tap(request, &resp, true, &qname, qtype);
                return resp;
            }
            Verdict::Except { list, rule } => {
                log.verdict = VerdictKind::Excepted;
                log.rule = Some(rule.text.to_string());
                log.list = Some(list);
            }
            Verdict::NoMatch => {}
        }
        drop(state);

        // Safe-search rewrite.
        let safesearch = self.safesearch.load();
        if let Some(target) = safesearch.rewrite(&qname) {
            let resp = self
                .answer_safesearch(request, &qname, qtype, target, now)
                .await;
            self.finish(&mut log, &resp, started);
            return resp;
        }

        // Cache → upstream.
        let (resp, source) = self.resolve_cached(request, &qname, qtype, now).await;
        log.source = source;
        self.finish(&mut log, &resp, started);
        self.shadow_tap(request, &resp, false, &qname, qtype);
        resp
    }

    /// SERVFAIL a query rejected by admission control, logging the shed.
    fn shed_overload(
        &self,
        request: &Message,
        client: IpAddr,
        ts: i64,
        started: Instant,
    ) -> Message {
        let resp = synth_servfail(request);
        let mut log = QueryRecord {
            ts,
            client,
            qname: request
                .queries
                .first()
                .map(|q| normalize_qname(&q.name.to_ascii()))
                .unwrap_or_default(),
            qtype: request.queries.first().map_or(0, |q| q.query_type.into()),
            verdict: VerdictKind::Allowed,
            rule: None,
            list: None,
            source: ResponseSource::Failed,
            rcode: 0,
            duration_us: 0,
        };
        self.finish(&mut log, &resp, started);
        resp
    }

    /// Mirror an answered query to the shadow reference, if enabled.
    fn shadow_tap(
        &self,
        request: &Message,
        resp: &Message,
        blocked: bool,
        qname: &str,
        qtype: RecordType,
    ) {
        if let Some(shadow) = &self.shadow {
            shadow.spawn_compare(
                request.clone(),
                resp.clone(),
                blocked,
                qname.to_string(),
                qtype.into(),
                self.writer.clone(),
            );
        }
    }

    /// Cache lookup with upstream fallback; returns the response for the
    /// client plus its provenance for the log.
    async fn resolve_cached(
        &self,
        request: &Message,
        qname: &str,
        qtype: RecordType,
        now: Instant,
    ) -> (Message, ResponseSource) {
        let Ok(name) = Name::from_ascii(qname) else {
            let mut resp = response_skeleton(request);
            resp.metadata.response_code = ResponseCode::FormErr;
            return (resp, ResponseSource::Synth);
        };
        let key = CacheKey::new(
            name,
            qtype,
            request
                .queries
                .first()
                .map_or(hickory_proto::rr::DNSClass::IN, |q| q.query_class),
        );

        match self.cache.get(&key, now) {
            Lookup::Fresh(cached) => (restamp(cached, request), ResponseSource::Cache),
            Lookup::Stale(cached) => {
                self.spawn_refresh(request.clone(), key);
                (restamp(cached, request), ResponseSource::Stale)
            }
            Lookup::Miss => self.resolve_shared(request, qname, key, now).await,
        }
    }

    /// One upstream lookup per key, shared by every concurrent miss.
    ///
    /// The first miss for a key becomes the leader and spawns the
    /// upstream lookup as a detached task (a cancelled client must not
    /// strand the followers); every miss for the same key while it runs
    /// subscribes to that task's result instead of fanning out its own
    /// upstream queries. Without this, a burst of identical misses — a
    /// popular name expiring, or one device retrying hard — multiplies
    /// into upstream work per client instead of per name.
    async fn resolve_shared(
        &self,
        request: &Message,
        qname: &str,
        key: CacheKey,
        now: Instant,
    ) -> (Message, ResponseSource) {
        let (mut rx, leader) = {
            let mut lookups = self.lookups.lock().expect("lookup map poisoned");
            if let Some(tx) = lookups.get(&key) {
                (tx.subscribe(), None)
            } else {
                let (tx, rx) = tokio::sync::broadcast::channel(1);
                lookups.insert(key.clone(), tx.clone());
                (rx, Some(tx))
            }
        };

        if let Some(tx) = leader {
            let upstream = Arc::clone(&self.upstream);
            let cache = Arc::clone(&self.cache);
            let req = request.clone();
            let qname = qname.to_owned();
            // The map entry MUST be removed however the task ends — a
            // panicking leader that left its key behind would strand
            // every future miss for that name forever (each one would
            // subscribe to a channel nobody will ever publish on), and
            // each stranded query pins an in_flight slot until the cap
            // turns the whole daemon into a SERVFAIL loop.
            let cleanup = RemoveOnDrop {
                lookups: Arc::clone(&self.lookups),
                key: key.clone(),
            };
            tokio::spawn(async move {
                let answer = match upstream.resolve(&req).await {
                    Ok(answer) => {
                        cache.insert(key.clone(), &answer, now);
                        Some(answer)
                    }
                    Err(err) => {
                        tracing::warn!(qname, %err, "all upstreams failed");
                        None
                    }
                };
                // Remove the key before publishing: a miss that arrives
                // after the send starts a fresh lookup rather than
                // subscribing to a concluded one.
                drop(cleanup);
                let _ = tx.send(answer);
            });
        }

        match rx.recv().await {
            Ok(Some(answer)) => (restamp(answer, request), ResponseSource::Upstream),
            // None: every upstream failed. Err: the leader task died
            // without publishing; either way the client gets SERVFAIL.
            Ok(None) | Err(_) => (synth_servfail(request), ResponseSource::Failed),
        }
    }

    /// Serve-stale refresh: re-resolve in the background and re-cache.
    /// At most one refresh runs per key at a time (a popular expired name
    /// must not trigger an upstream query per client hit).
    fn spawn_refresh(&self, request: Message, key: CacheKey) {
        {
            let mut refreshing = self.refreshing.lock().expect("refresh set poisoned");
            if !refreshing.insert(key.clone()) {
                return; // already being refreshed
            }
        }
        let upstream = Arc::clone(&self.upstream);
        let cache = Arc::clone(&self.cache);
        // Removed on drop, so a panicking refresh cannot leave the key
        // marked as being-refreshed forever (which would block every
        // future refresh of that name).
        let cleanup = RemoveFromSetOnDrop {
            refreshing: Arc::clone(&self.refreshing),
            key: key.clone(),
        };
        tokio::spawn(async move {
            let _cleanup = cleanup;
            match upstream.resolve(&request).await {
                // Fresh Instant: the entry's clock starts when the answer
                // arrived, not when the stale hit happened.
                Ok(answer) => cache.insert(key, &answer, Instant::now()),
                Err(err) => {
                    tracing::warn!(%err, "stale refresh failed");
                }
            }
        });
    }

    /// CNAME to the safe-search endpoint plus the endpoint's own records.
    async fn answer_safesearch(
        &self,
        request: &Message,
        qname: &str,
        qtype: RecordType,
        target: &str,
        now: Instant,
    ) -> Message {
        let mut resp = response_skeleton(request);
        resp.metadata.response_code = ResponseCode::NoError;
        let (Ok(qname_name), Ok(target_name)) = (
            Name::from_ascii(format!("{qname}.")),
            Name::from_ascii(format!("{target}.")),
        ) else {
            resp.metadata.response_code = ResponseCode::ServFail;
            return resp;
        };
        resp.add_answer(Record::from_rdata(
            qname_name,
            SAFESEARCH_CNAME_TTL,
            RData::CNAME(CNAME(target_name.clone())),
        ));
        // Resolve the target through the normal cache/upstream path and
        // append its records; a failure still returns the CNAME alone.
        let mut target_query = Message::new(request.metadata.id, MessageType::Query, OpCode::Query);
        target_query.add_query(hickory_proto::op::Query::query(target_name, qtype));
        target_query.metadata.recursion_desired = true;
        let (target_resp, _) = self.resolve_cached(&target_query, target, qtype, now).await;
        if target_resp.metadata.response_code == ResponseCode::NoError {
            for record in &target_resp.answers {
                resp.add_answer(record.clone());
            }
        } else {
            // Do not launder an upstream failure into a clean NOERROR:
            // surface the target's rcode (the CNAME stays, which is legal).
            resp.metadata.response_code = target_resp.metadata.response_code;
        }
        resp
    }

    /// Stamp rcode/duration into the log record and enqueue it.
    fn finish(&self, log: &mut QueryRecord, resp: &Message, started: Instant) {
        log.rcode = u16::from(resp.metadata.response_code);
        log.duration_us = u32::try_from(started.elapsed().as_micros()).unwrap_or(u32::MAX);
        if !self.writer.log(LogEvent::Query(log.clone())) {
            tracing::warn!("query log queue full; dropped a record");
        }
    }
}

/// Lowercase, strip one trailing dot.
fn normalize_qname(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.strip_suffix('.').unwrap_or(&lower).to_string()
}

/// Adopt a cached/upstream message as the answer to `request`: fix the id
/// and echo the question/RD flags.
fn restamp(mut msg: Message, request: &Message) -> Message {
    msg.metadata.id = request.metadata.id;
    msg.metadata.message_type = MessageType::Response;
    msg.metadata.recursion_desired = request.metadata.recursion_desired;
    msg.metadata.recursion_available = true;
    if msg.queries.is_empty() {
        for q in &request.queries {
            msg.add_query(q.clone());
        }
    }
    // RFC 6840 §5.9: a resolver must not return DNSSEC records to a
    // client with a clear DO bit. Stripping happens here, per request,
    // rather than before caching: one cache entry then serves both
    // DNSSEC-aware and plain clients.
    let mut msg = msg.maybe_strip_dnssec_records(client_wants_dnssec(request));
    apply_edns(&mut msg, request);
    msg
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

// ---------------------------------------------------------------------------
// sockets
// ---------------------------------------------------------------------------

/// Handle to a serving daemon: bound addresses + shutdown.
pub struct RunningServer {
    /// Actual bound UDP addresses (useful with port 0 in tests).
    pub udp_addrs: Vec<std::net::SocketAddr>,
    /// Actual bound TCP addresses (same ports as UDP).
    pub tcp_addrs: Vec<std::net::SocketAddr>,
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RunningServer {
    /// Stop accepting and terminate the socket tasks.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

/// Attach the address to a bind failure.
///
/// The bare OS error is "Address already in use" with no hint which of
/// several configured addresses failed — the difference between a
/// one-minute fix and a confused rollback during a cutover.
fn bind_error(addr: std::net::SocketAddr, proto: &str, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(err.kind(), format!("cannot bind {proto} {addr}: {err}"))
}

/// Configure a listening socket for one configured address.
///
/// IPv6 sockets are set `IPV6_V6ONLY`, so every entry in `bind` means
/// exactly the family it names. Without it, Linux's default
/// (`net.ipv6.bindv6only=0`) makes `[::]:53` also claim every IPv4
/// address, and the natural dual-stack configuration
/// `["0.0.0.0:53", "[::]:53"]` fails with EADDRINUSE against itself.
fn new_socket(
    addr: std::net::SocketAddr,
    ty: socket2::Type,
    proto: socket2::Protocol,
    protoname: &str,
) -> std::io::Result<socket2::Socket> {
    let domain = socket2::Domain::for_address(addr);
    let sock = socket2::Socket::new(domain, ty, Some(proto))
        .map_err(|e| bind_error(addr, protoname, &e))?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)
            .map_err(|e| bind_error(addr, protoname, &e))?;
    }
    Ok(sock)
}

fn bind_tcp(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let sock = new_socket(addr, socket2::Type::STREAM, socket2::Protocol::TCP, "tcp")?;
    // Standard for a listener: allows restart while old connections sit
    // in TIME_WAIT. It does not mask a port that is actively listening,
    // so a real conflict still fails loudly.
    sock.set_reuse_address(true)
        .map_err(|e| bind_error(addr, "tcp", &e))?;
    sock.bind(&addr.into())
        .map_err(|e| bind_error(addr, "tcp", &e))?;
    sock.listen(1024).map_err(|e| bind_error(addr, "tcp", &e))?;
    sock.set_nonblocking(true)
        .map_err(|e| bind_error(addr, "tcp", &e))?;
    tokio::net::TcpListener::from_std(std::net::TcpListener::from(sock))
        .map_err(|e| bind_error(addr, "tcp", &e))
}

fn bind_udp(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    // No SO_REUSEADDR here: for unicast UDP it would only blur "this
    // port is taken", which must stay a loud failure.
    let sock = new_socket(addr, socket2::Type::DGRAM, socket2::Protocol::UDP, "udp")?;
    sock.bind(&addr.into())
        .map_err(|e| bind_error(addr, "udp", &e))?;
    sock.set_nonblocking(true)
        .map_err(|e| bind_error(addr, "udp", &e))?;
    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))
        .map_err(|e| bind_error(addr, "udp", &e))
}

/// Bind UDP+TCP on every address (TCP first, then UDP on the same
/// resolved port, so `:0` ends up on one port for both) and serve
/// requests through the pipeline until shutdown.
#[expect(
    clippy::unused_async,
    reason = "binding is synchronous now, but this spawns the socket tasks \
              and so must run inside a runtime; the async signature enforces that"
)]
pub async fn serve<U: Upstream>(
    pipeline: std::sync::Arc<Pipeline<U>>,
    binds: &[std::net::SocketAddr],
) -> std::io::Result<RunningServer> {
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::new();
    let mut udp_addrs = Vec::new();
    let mut tcp_addrs = Vec::new();

    for &bind in binds {
        let tcp = bind_tcp(bind)?;
        let mut tcp_addr = tcp.local_addr()?;
        let udp_bind = std::net::SocketAddr::new(bind.ip(), tcp_addr.port());
        let udp = bind_udp(udp_bind)?;
        let udp_addr = udp.local_addr()?;
        tcp_addr = tcp.local_addr()?;
        udp_addrs.push(udp_addr);
        tcp_addrs.push(tcp_addr);

        let udp = std::sync::Arc::new(udp);
        let p = std::sync::Arc::clone(&pipeline);
        let mut rx = shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    recv = udp.recv_from(&mut buf) => {
                        let Ok((n, peer)) = recv else { continue };
                        let Ok(request) = Message::from_vec(&buf[..n]) else {
                            continue; // unparseable datagram: nothing sane to answer
                        };
                        let p = std::sync::Arc::clone(&p);
                        let udp = std::sync::Arc::clone(&udp);
                        tokio::spawn(async move {
                            let response = p.handle(&request, peer.ip()).await;
                            let max = usize::from(request.max_payload());
                            match response.to_vec() {
                                Ok(bytes) if bytes.len() <= max => {
                                    let _ = udp.send_to(&bytes, peer).await;
                                }
                                Ok(_) => {
                                    // Too big for this client: truncate.
                                    let tc = response.truncate();
                                    if let Ok(bytes) = tc.to_vec() {
                                        let _ = udp.send_to(&bytes, peer).await;
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(%err, "failed to serialize response");
                                }
                            }
                        });
                    }
                }
            }
        }));

        let p = std::sync::Arc::clone(&pipeline);
        let mut rx = shutdown.subscribe();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rx.changed() => break,
                    accepted = tcp.accept() => {
                        let Ok((stream, peer)) = accepted else { continue };
                        let p = std::sync::Arc::clone(&p);
                        tokio::spawn(async move {
                            let _ = serve_tcp_conn(stream, peer.ip(), p).await;
                        });
                    }
                }
            }
        }));
    }

    Ok(RunningServer {
        udp_addrs,
        tcp_addrs,
        shutdown,
        tasks,
    })
}

/// One TCP connection: length-prefixed messages, 10s idle timeout.
async fn serve_tcp_conn<U: Upstream>(
    mut stream: tokio::net::TcpStream,
    peer: IpAddr,
    pipeline: std::sync::Arc<Pipeline<U>>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let idle = std::time::Duration::from_secs(10);
    loop {
        let mut lenbuf = [0u8; 2];
        match tokio::time::timeout(idle, stream.read_exact(&mut lenbuf)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()), // idle timeout or peer closed
        }
        let len = usize::from(u16::from_be_bytes(lenbuf));
        let mut buf = vec![0u8; len];
        match tokio::time::timeout(idle, stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }
        let Ok(request) = Message::from_vec(&buf) else {
            return Ok(()); // garbage: drop the connection
        };
        let response = pipeline.handle(&request, peer).await;
        let Ok(bytes) = response.to_vec() else {
            return Ok(());
        };
        let Ok(len) = u16::try_from(bytes.len()) else {
            return Ok(());
        };
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
    }
}

// ---------------------------------------------------------------------------
// daemon entry
// ---------------------------------------------------------------------------

/// Reload lists and swap the engine; on any failure the old engine stays.
async fn reload_lists<U: Upstream>(
    config: &Config,
    pipeline: &Pipeline<U>,
    db: &crate::db::Db,
    started_ts: i64,
    offline: bool,
) -> Result<String, CoreError> {
    let loaded = crate::lists::load(
        &config.effective_lists(),
        &config.filtering.list_dir,
        offline,
    )
    .await?;
    for (list, issue) in &loaded.issues {
        tracing::warn!(list, %issue, "blocklist line rejected");
    }
    let hash = loaded.hash.clone();
    tracing::info!(
        rules = loaded.rule_counts.iter().sum::<usize>(),
        lists = loaded.names.len(),
        hash,
        "filter engine ready"
    );
    pipeline.swap_engine(loaded.engine, loaded.names);
    let hb = crate::db::Heartbeat {
        pid: std::process::id(),
        started_ts,
        updated_ts: unix_now(),
        config_hash: config.hash(),
        lists_hash: hash.clone(),
    };
    db.write_heartbeat(&hb)?;
    Ok(hash)
}

/// Run the daemon from a config file: fail loud on any startup problem,
/// serve until SIGTERM/SIGINT, reload config+lists on SIGHUP, refresh
/// lists daily, heartbeat every minute, retention sweep hourly.
#[expect(
    clippy::too_many_lines,
    reason = "linear startup + event loop, no branching logic"
)]
pub async fn run(
    config_path: &std::path::Path,
    shadow: Option<std::net::SocketAddr>,
) -> Result<(), CoreError> {
    let config = Config::load(config_path)?;
    let db = crate::db::Db::open(&config.database.path)?;
    let started_ts = unix_now();

    let providers: Vec<&str> = config
        .safe_search
        .providers
        .iter()
        .map(String::as_str)
        .collect();
    let safesearch = SafeSearch::new(config.safe_search.enabled, &providers)?;

    let pool = crate::upstream::UpstreamPool::new(&crate::upstream::UpstreamConfig {
        urls: config.upstreams.servers.clone(),
        bootstrap_ips: config.upstreams.bootstrap.clone(),
        timeout_ms: config.upstreams.timeout_ms,
    })
    .await?;

    // Start with an empty engine, then load lists (online, fail loud)
    // BEFORE binding any socket: never serve unfiltered.
    let mut pipeline = Pipeline::new(
        sumidero_filter::EngineBuilder::new().build(),
        Vec::new(),
        Cache::new(16_384),
        safesearch,
        pool,
        db.writer(),
        config.server.allow.clone(),
    );
    if let Some(addr) = shadow {
        tracing::info!(%addr, "shadow mode: mirroring queries to reference resolver");
        pipeline.set_shadow(addr);
    }
    let pipeline = std::sync::Arc::new(pipeline);
    let mut lists_hash = reload_lists(&config, &pipeline, &db, started_ts, false).await?;

    let server = serve(std::sync::Arc::clone(&pipeline), &config.server.bind).await?;
    tracing::info!(udp = ?server.udp_addrs, tcp = ?server.tcp_addrs, "serving");

    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_mins(1));
    let mut retention = tokio::time::interval(std::time::Duration::from_hours(1));
    let mut refresh = tokio::time::interval(std::time::Duration::from_secs(
        crate::consts::LIST_UPDATE_SECS,
    ));
    // The first tick of an interval fires immediately; consume them.
    heartbeat.tick().await;
    retention.tick().await;
    refresh.tick().await;

    let mut current_config = config;
    // Drop count at the previous heartbeat, so each sample can report
    // what was lost *since then* rather than since process start.
    let mut dropped_at_last_sample: u64 = 0;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => {
                // nginx pattern: re-read config; a bad config or unloadable
                // lists keep the old state and log loudly.
                match Config::load(config_path) {
                    Ok(new_config) => {
                        match reload_lists(&new_config, &pipeline, &db, started_ts, false).await {
                            Ok(hash) => {
                                let providers: Vec<&str> = new_config
                                    .safe_search
                                    .providers
                                    .iter()
                                    .map(String::as_str)
                                    .collect();
                                match SafeSearch::new(new_config.safe_search.enabled, &providers) {
                                    Ok(ss) => pipeline
                                        .swap_policy(ss, new_config.server.allow.clone()),
                                    Err(err) => tracing::error!(
                                        %err,
                                        "safe-search reload failed; keeping old table"
                                    ),
                                }
                                if new_config.server.bind != current_config.server.bind
                                    || new_config.upstreams != current_config.upstreams
                                    || new_config.database != current_config.database
                                {
                                    tracing::warn!(
                                        "bind/upstream/database changes need a restart; \
                                         filtering, allowlist, and safe-search were reloaded"
                                    );
                                }
                                current_config = new_config;
                                lists_hash = hash;
                                tracing::info!("reload complete");
                            }
                            Err(err) => {
                                tracing::error!(%err, "reload failed; keeping old lists");
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(%err, "reload failed: bad config; keeping old state");
                    }
                }
            }
            _ = heartbeat.tick() => {
                let hb = crate::db::Heartbeat {
                    pid: std::process::id(),
                    started_ts,
                    updated_ts: unix_now(),
                    config_hash: current_config.hash(),
                    lists_hash: lists_hash.clone(),
                };
                // rusqlite is blocking; keep it off the async workers.
                let result = tokio::task::block_in_place(|| db.write_heartbeat(&hb));
                if let Err(err) = result {
                    tracing::error!(%err, "heartbeat write failed");
                }

                // Publish runtime counters next to the heartbeat so a
                // degraded daemon is visible from `status` alone.
                let health = pipeline.upstream().health();
                // Only "no upstream could answer" is worth a warning: a
                // single dropped connection is rebuilt on the next query
                // and the race hides it from clients entirely.
                if health.consecutive_all_failed > 0 {
                    tracing::error!(
                        consecutive = health.consecutive_all_failed,
                        total = health.all_failed_total,
                        "every upstream is failing; the daemon cannot resolve"
                    );
                }
                match serde_json::to_string(&health) {
                    Ok(upstreams_json) => {
                        let dropped_total = pipeline.log_events_dropped();
                        let dropped_recent =
                            dropped_total.saturating_sub(dropped_at_last_sample);
                        dropped_at_last_sample = dropped_total;
                        if dropped_recent > 0 {
                            tracing::warn!(
                                dropped_recent,
                                dropped_total,
                                "query-log events dropped: the writer queue is full"
                            );
                        }
                        let stats = crate::db::DaemonStats {
                            updated_ts: unix_now(),
                            log_events_dropped: dropped_total,
                            log_events_dropped_recent: dropped_recent,
                            upstreams_json,
                        };
                        let result =
                            tokio::task::block_in_place(|| db.write_daemon_stats(&stats));
                        if let Err(err) = result {
                            tracing::error!(%err, "daemon stats write failed");
                        }
                    }
                    Err(err) => tracing::error!(%err, "upstream health serialization failed"),
                }
            }
            _ = retention.tick() => {
                match tokio::task::block_in_place(|| db.retention_sweep(unix_now())) {
                    Ok(deleted) if deleted > 0 => tracing::info!(deleted, "retention sweep"),
                    Ok(_) => {}
                    Err(err) => tracing::error!(%err, "retention sweep failed"),
                }
            }
            _ = refresh.tick() => {
                match reload_lists(&current_config, &pipeline, &db, started_ts, false).await {
                    Ok(hash) => lists_hash = hash,
                    Err(err) => {
                        tracing::error!(%err, "daily list refresh failed; keeping old lists");
                    }
                }
            }
        }
    }

    tracing::info!("shutting down");
    server.shutdown().await;
    // Drain in-flight queries (bounded) so their log records reach the
    // writer before the final flush.
    let drain_deadline = Instant::now() + std::time::Duration::from_secs(2);
    while pipeline.in_flight() > 0 && Instant::now() < drain_deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::task::block_in_place(|| db.flush());
    Ok(())
}
