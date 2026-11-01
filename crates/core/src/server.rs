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

use crate::cache::{Cache, CacheKey, Lookup};
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

/// The daemon shares one pool between the pipeline and the list
/// fetcher's resolver.
impl<T: Upstream> Upstream for std::sync::Arc<T> {
    fn resolve(
        &self,
        query: &Message,
    ) -> impl std::future::Future<Output = Result<Message, crate::upstream::Error>> + Send {
        T::resolve(self, query)
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

/// Everything that decides an answer, swapped as one value: a query sees
/// one consistent policy from its first check to its CNAME check, and a
/// reload can never pair new lists with an old allowlist.
#[derive(Clone)]
pub struct Policy {
    pub engine: Arc<Engine>,
    pub safesearch: Arc<SafeSearch>,
    pub allow: Arc<[IpNet]>,
}

/// The assembled request pipeline, generic over the upstream (the pool
/// in production; a test can pass any `Upstream`).
pub struct Pipeline<U: Upstream> {
    policy: ArcSwap<Policy>,
    cache: Arc<Cache>,
    upstream: Arc<U>,
    writer: DbWriter,
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
    /// Recent resolution failures (RFC 9520 hold-downs).
    failures: Arc<crate::failcache::FailureCache>,
}

impl<U: Upstream> Pipeline<U> {
    #[must_use]
    pub fn new(
        engine: Engine,
        cache: Cache,
        safesearch: SafeSearch,
        upstream: U,
        writer: DbWriter,
        allow: Vec<IpNet>,
    ) -> Self {
        Self::from_policy(
            Policy {
                engine: Arc::new(engine),
                safesearch: Arc::new(safesearch),
                allow: allow.into(),
            },
            cache,
            upstream,
            writer,
        )
    }

    #[must_use]
    pub fn from_policy(policy: Policy, cache: Cache, upstream: U, writer: DbWriter) -> Self {
        Self {
            policy: ArcSwap::from_pointee(policy),
            cache: Arc::new(cache),
            upstream: Arc::new(upstream),
            writer,
            in_flight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            refreshing: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            lookups: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            shadow: None,
            failures: Arc::new(crate::failcache::FailureCache::new()),
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

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> Arc<Policy> {
        self.policy.load_full()
    }

    /// Install a whole new policy in one atomic step (reload).
    pub fn install(&self, policy: Policy) {
        self.policy.store(Arc::new(policy));
    }

    /// Keep the engine, replace the allowlist and safe-search table.
    pub fn swap_policy(&self, safesearch: SafeSearch, allow: Vec<IpNet>) {
        let engine = Arc::clone(&self.policy.load().engine);
        self.install(Policy {
            engine,
            safesearch: Arc::new(safesearch),
            allow: allow.into(),
        });
    }

    /// Number of queries currently being handled.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Keep the allowlist and safe search, replace the engine.
    pub fn swap_engine(&self, engine: Engine) {
        let current = self.policy.load_full();
        self.install(Policy {
            engine: Arc::new(engine),
            safesearch: Arc::clone(&current.safesearch),
            allow: Arc::clone(&current.allow),
        });
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
            let mut log = new_log(ts, client, String::new(), 0, ResponseSource::Synth);
            self.finish(&mut log, &resp, started);
            return resp;
        };
        let qname = normalize_qname(&query.name.to_ascii());
        let qtype = query.query_type;

        let mut log = new_log(
            ts,
            client,
            qname.clone(),
            qtype.into(),
            ResponseSource::Synth,
        );

        // One policy snapshot for the whole query: the CNAME check after
        // the upstream answer judges with the same engine as the name
        // itself, even if a reload lands in between.
        let policy = self.policy.load_full();
        if !client_allowed(&policy.allow, client) {
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
        match policy.engine.verdict(&qname) {
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

        // Safe-search rewrite.
        if let Some(target) = policy.safesearch.rewrite(&qname) {
            log.verdict = VerdictKind::Rewritten;
            log.rule = Some(format!("safe-search -> {target}"));
            let resp = self
                .answer_safesearch(request, &qname, qtype, target, now)
                .await;
            self.finish(&mut log, &resp, started);
            return resp;
        }

        // Cache → upstream.
        let (resp, source) = self.resolve_cached(request, &qname, qtype, now).await;
        log.source = source;

        // CNAME cloaking: a tracker served under a first-party alias
        // (`metrics.shop.example CNAME shop.tracker.example`) is blocked
        // when any name in the chain is. An exception on the queried name
        // covers its whole chain, the way the operator wrote it.
        if log.verdict != VerdictKind::Excepted
            && let Some((target, list, rule)) = blocked_cname_target(&policy.engine, &resp)
        {
            log.verdict = VerdictKind::Blocked;
            log.rule = Some(format!("{rule} (CNAME target {target})"));
            log.list = Some(list);
            let resp = synth_block_response(request);
            self.finish(&mut log, &resp, started);
            self.shadow_tap(request, &resp, true, &qname, qtype);
            return resp;
        }
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
        let mut log = new_log(
            ts,
            client,
            request
                .queries
                .first()
                .map(|q| normalize_qname(&q.name.to_ascii()))
                .unwrap_or_default(),
            request.queries.first().map_or(0, |q| q.query_type.into()),
            ResponseSource::Failed,
        );
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
            Lookup::Miss => {
                if self.failures.held(&key, now).is_some() {
                    return (synth_servfail(request), ResponseSource::FailureCached);
                }
                self.resolve_shared(request, qname, key, now).await
            }
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
            let failures = Arc::clone(&self.failures);
            tokio::spawn(async move {
                let answer = match upstream.resolve(&req).await {
                    Ok(answer) => {
                        settle(&cache, &failures, key.clone(), &answer, now, &qname);
                        Some(answer)
                    }
                    Err(err) => {
                        let hold = failures.record(key.clone(), now);
                        tracing::warn!(
                            qname,
                            %err,
                            hold_s = hold.as_secs(),
                            "no upstream could resolve; repeats get SERVFAIL until the hold ends"
                        );
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
        let failures = Arc::clone(&self.failures);
        tokio::spawn(async move {
            let _cleanup = cleanup;
            // Fresh Instant: the entry's clock starts when the answer
            // arrived, not when the stale hit happened.
            let now = Instant::now();
            if failures.held(&key, now).is_some() {
                return; // failed moments ago; keep serving stale
            }
            let qname = key_name(&key);
            match upstream.resolve(&request).await {
                Ok(answer) => settle(&cache, &failures, key, &answer, now, &qname),
                Err(err) => {
                    let hold = failures.record(key, now);
                    tracing::warn!(qname, %err, hold_s = hold.as_secs(), "stale refresh failed; still serving stale");
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

/// A log record before the verdict: allowed until proven otherwise;
/// rcode and duration are stamped by `finish`.
fn new_log(
    ts: i64,
    client: IpAddr,
    qname: String,
    qtype: u16,
    source: ResponseSource,
) -> QueryRecord {
    QueryRecord {
        ts,
        client,
        qname,
        qtype,
        verdict: VerdictKind::Allowed,
        rule: None,
        list: None,
        source,
        rcode: 0,
        duration_us: 0,
    }
}

/// The first CNAME target in `resp` that the engine blocks, with the
/// list index and rule text. Targets the engine excepts do not block.
fn blocked_cname_target(engine: &Engine, resp: &Message) -> Option<(String, usize, String)> {
    resp.answers.iter().find_map(|record| {
        let RData::CNAME(target) = &record.data else {
            return None;
        };
        let target = normalize_qname(&target.0.to_ascii());
        match engine.verdict(&target) {
            Verdict::Block { list, rule } => {
                let rule = rule.text.into_owned();
                Some((target, list, rule))
            }
            Verdict::Except { .. } | Verdict::NoMatch => None,
        }
    })
}

/// File an upstream answer: cacheable answers go to the cache and clear
/// the key's failure streak; an upstream SERVFAIL is a resolution
/// failure (RFC 9520) and starts or extends a hold-down.
fn settle(
    cache: &Cache,
    failures: &crate::failcache::FailureCache,
    key: CacheKey,
    answer: &Message,
    now: Instant,
    qname: &str,
) {
    if answer.metadata.response_code == ResponseCode::ServFail {
        let hold = failures.record(key, now);
        tracing::warn!(
            qname,
            hold_s = hold.as_secs(),
            "upstream answered SERVFAIL; holding the name down"
        );
    } else {
        failures.clear(&key);
        cache.insert(key, answer, now);
    }
}

fn key_name(key: &CacheKey) -> String {
    normalize_qname(&key.name().to_ascii())
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

pub(crate) fn unix_now() -> i64 {
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
// Async although binding is synchronous: it spawns the socket tasks and
// so must run inside a runtime; the signature enforces that.
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
