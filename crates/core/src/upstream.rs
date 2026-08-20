//! Encrypted DNS upstream pool (`DoH` / `DoQ`).
//!
//! [`UpstreamPool`] fans out every query to **all** configured upstreams
//! concurrently and returns the first successful response, stamping the
//! original query id onto the response before returning it.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::h2::HttpsClientStream;
use hickory_resolver::net::quic::QuicClientStream;
use hickory_resolver::net::runtime::{RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
#[cfg(test)]
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, Message};
use hickory_resolver::{Resolver, TokioResolver};
use tokio::sync::RwLock;
use tokio::time::Instant;
use url::Url;

// ── Error types ─────────────────────────────────────────────────────

/// Errors produced by [`UpstreamPool`].
#[derive(Debug)]
pub enum Error {
    /// A configured upstream URL is not a supported scheme or is malformed.
    UnsupportedUrl(String),
    /// Pool initialisation failed (bootstrap resolution, transport build, etc.).
    Init(String),
    /// Every upstream failed for a given query.
    AllFailed(Vec<String>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedUrl(u) => write!(f, "unsupported upstream URL: {u}"),
            Self::Init(msg) => write!(f, "upstream pool init failed: {msg}"),
            Self::AllFailed(errs) => {
                write!(f, "all upstreams failed:")?;
                for e in errs {
                    write!(f, "\n  - {e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {}

// ── Config ──────────────────────────────────────────────────────────

/// Configuration for [`UpstreamPool`].
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Upstream URLs (`https://…` or `quic://…`).
    pub urls: Vec<String>,
    /// Bootstrap DNS server IPs used to resolve upstream hostnames.
    pub bootstrap_ips: Vec<IpAddr>,
    /// Per-upstream query timeout in milliseconds.
    pub timeout_ms: u64,
}

// ── Internal transport trait ────────────────────────────────────────

type BoxSendFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How one send failed, as classified by the transport.
///
/// The distinction drives connection lifecycle: a `Fatal` error means
/// the multiplexed connection is dead or poisoned and every later send
/// on it will fail, so it must be torn down and rebuilt. A `Query`
/// error condemns only the one query that hit it — tearing down a
/// healthy connection over it would punish every other query.
#[derive(Debug)]
enum SendError {
    /// The connection is unusable for every query; rebuild it.
    Fatal(String),
    /// Only this query failed; the connection remains usable.
    Query(String),
}

/// Abstraction over a single upstream transport so tests can inject fakes.
trait Transport: Send + Sync + 'static {
    /// Send a DNS message and return the response.
    fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>>;
}

// ── Real transports (DoH / DoQ via hickory DnsExchange) ─────────────

/// Classify a hickory transport error: is the connection dead, or did
/// only this query fail?
///
/// `Busy` is the signature of a dead `DnsExchange` (its background task
/// exited; the 2026-08-20 outage mode). `Dns`/`Proto` errors are about
/// one response's content — a server that garbles or refuses one answer
/// has not hung up on the connection carrying it. `NetError` is
/// non-exhaustive, so anything unrecognized is treated as fatal: a
/// spurious rebuild costs one handshake, a spurious reuse of a dead
/// connection costs every query until the process restarts.
fn classify_net_error(err: &hickory_resolver::net::NetError) -> SendError {
    use hickory_resolver::net::NetError;
    match err {
        NetError::Dns(_) | NetError::Proto(_) | NetError::QueryCaseMismatch => {
            SendError::Query(err.to_string())
        }
        _ => SendError::Fatal(err.to_string()),
    }
}

/// Wraps a cloneable `DnsExchange` for `DoH` or `DoQ`.
///
/// Holds the runtime provider alive so its `JoinSet` (which owns the
/// exchange background task) is not dropped prematurely.
struct ExchangeTransport<P: hickory_resolver::net::runtime::RuntimeProvider> {
    exchange: hickory_resolver::net::xfer::DnsExchange<P>,
    _provider: P,
}

impl<P> Transport for ExchangeTransport<P>
where
    P: hickory_resolver::net::runtime::RuntimeProvider + 'static,
{
    fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
        let exchange = self.exchange.clone();
        Box::pin(async move {
            let request = DnsRequest::new(msg, DnsRequestOptions::default());
            let response = exchange
                .send(request)
                .first_answer()
                .await
                .map_err(|e| classify_net_error(&e))?;
            Ok(response.into_message())
        })
    }
}

// ── Parsed upstream descriptor ──────────────────────────────────────

#[derive(Debug, Clone)]
enum UpstreamKind {
    Https {
        host: String,
        port: u16,
        path: String,
    },
    Quic {
        host: String,
        port: u16,
    },
}

fn parse_upstream_url(raw: &str) -> Result<UpstreamKind, Error> {
    let url = Url::parse(raw).map_err(|e| Error::UnsupportedUrl(format!("{raw}: {e}")))?;
    match url.scheme() {
        "https" => {
            let host = url
                .host_str()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| Error::UnsupportedUrl(format!("{raw}: missing host")))?
                .to_owned();
            let port = url.port().unwrap_or(443);
            let path = url.path().to_owned();
            if path.is_empty() || path == "/" {
                return Err(Error::UnsupportedUrl(format!(
                    "{raw}: https URL must include a path (e.g. /dns-query)"
                )));
            }
            Ok(UpstreamKind::Https { host, port, path })
        }
        "quic" => {
            let host = url
                .host_str()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| Error::UnsupportedUrl(format!("{raw}: missing host")))?
                .to_owned();
            let port = url.port().unwrap_or(853);
            // quic URLs must not have a meaningful path
            Ok(UpstreamKind::Quic { host, port })
        }
        other => Err(Error::UnsupportedUrl(format!(
            "{raw}: unsupported scheme '{other}' (expected https or quic)"
        ))),
    }
}

// ── Bootstrap resolution ────────────────────────────────────────────

async fn bootstrap_resolve(host: &str, bootstrap_ips: &[IpAddr]) -> Result<IpAddr, Error> {
    // If the host is already an IP literal, return it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    if bootstrap_ips.is_empty() {
        return Err(Error::Init(
            "bootstrap_ips is empty and upstream hostname requires resolution".into(),
        ));
    }

    let name_servers: Vec<NameServerConfig> = bootstrap_ips
        .iter()
        .map(|ip| NameServerConfig::udp_and_tcp(*ip))
        .collect();

    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    let resolver: TokioResolver =
        Resolver::builder_with_config(config, TokioRuntimeProvider::new())
            .with_options({
                let mut opts = ResolverOpts::default();
                opts.cache_size = 0;
                opts.timeout = Duration::from_secs(5);
                opts
            })
            .build()
            .map_err(|e| Error::Init(format!("bootstrap resolver build failed: {e}")))?;

    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| Error::Init(format!("bootstrap resolution of '{host}' failed: {e}")))?;

    // Prefer IPv4 to avoid issues on hosts without IPv6 connectivity.
    let mut v4 = None;
    let mut first = None;
    for ip in lookup.iter() {
        if first.is_none() {
            first = Some(ip);
        }
        if ip.is_ipv4() {
            v4 = Some(ip);
            break;
        }
    }
    v4.or(first).ok_or_else(|| {
        Error::Init(format!(
            "bootstrap resolution of '{host}' returned no addresses"
        ))
    })
}

// ── Transport construction ──────────────────────────────────────────

async fn build_transport(
    kind: &UpstreamKind,
    resolved_ip: IpAddr,
) -> Result<Arc<dyn Transport>, Error> {
    let provider = TokioRuntimeProvider::new();
    match kind {
        UpstreamKind::Https { host, port, path } => {
            let addr = SocketAddr::new(resolved_ip, *port);
            let client_config = build_rustls_client_config();
            let exchange = HttpsClientStream::builder(Arc::new(client_config), provider.clone())
                .exchange(addr, Arc::from(host.as_str()), Arc::from(path.as_str()))
                .await
                .map_err(|e| Error::Init(format!("DoH exchange to {host}:{port} failed: {e}")))?;
            Ok(Arc::new(ExchangeTransport {
                exchange,
                _provider: provider,
            }))
        }
        UpstreamKind::Quic { host, port } => {
            let addr = SocketAddr::new(resolved_ip, *port);
            let client_config = build_rustls_client_config();
            let stream = QuicClientStream::builder()
                .crypto_config(client_config)
                .build(addr, Arc::from(host.as_str()))
                .await
                .map_err(|e| Error::Init(format!("DoQ stream to {host}:{port} failed: {e}")))?;
            let (exchange, bg) =
                hickory_resolver::net::xfer::DnsExchange::<TokioRuntimeProvider>::from_stream(
                    stream,
                );
            provider.create_handle().spawn_bg(bg);
            Ok(Arc::new(ExchangeTransport {
                exchange,
                _provider: provider,
            }))
        }
    }
}

// ── Transport factories ─────────────────────────────────────────────

/// Builds a fresh transport for one upstream, on demand.
///
/// A [`ReconnectingUpstream`] calls this every time it needs a new
/// connection, so each rebuild also re-resolves the upstream hostname
/// through the bootstrap servers: a daemon that runs for months must
/// follow upstream IP changes.
trait TransportFactory: Send + Sync + 'static {
    /// Establish a new connection to this upstream.
    fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>>;
    /// The configured URL, used in logs and health output.
    fn label(&self) -> &str;
}

/// Factory for a real network upstream.
struct NetworkFactory {
    kind: UpstreamKind,
    bootstrap_ips: Vec<IpAddr>,
    url: String,
}

impl TransportFactory for NetworkFactory {
    fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
        Box::pin(async move {
            let host = match &self.kind {
                UpstreamKind::Https { host, .. } | UpstreamKind::Quic { host, .. } => host,
            };
            let ip = bootstrap_resolve(host, &self.bootstrap_ips).await?;
            build_transport(&self.kind, ip).await
        })
    }

    fn label(&self) -> &str {
        &self.url
    }
}

/// Millis as u64, saturating (backoffs are seconds, never near overflow).
fn duration_to_millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Unix seconds, saturating at 0 before the epoch.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

// ── Reconnecting upstream ───────────────────────────────────────────

/// Shortest wait between two connection attempts to a failing upstream.
const MIN_RECONNECT_BACKOFF: Duration = Duration::from_millis(500);
/// Longest wait between two connection attempts when the *build* fails
/// (connection refused, handshake error): the upstream is hard-down.
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
/// Longest wait between rebuilds when builds *succeed* but the fresh
/// connections keep failing their sends (the upstream accepts
/// connections it cannot serve). Kept short: this also bounds how long
/// a recovered upstream waits before it is retried, and the race means
/// other upstreams cover the gap.
const MAX_REBUILD_HOLDDOWN: Duration = Duration::from_secs(5);

/// The mutable connection state of one upstream.
struct Slot {
    /// Bumped on every successful build; lets a task tell "the transport
    /// I just used" from "a replacement someone else already installed".
    generation: u64,
    /// `None` means disconnected — a detached repair task rebuilds.
    transport: Option<Arc<dyn Transport>>,
    /// Earliest instant at which another build attempt may run.
    next_attempt: Option<Instant>,
}

/// Health snapshot for the whole pool.
///
/// `consecutive_all_failed` is the signal that matters for alerting: it
/// counts queries since the last one any upstream answered. Individual
/// upstreams drop and rebuild connections all the time — Quad9 does it
/// every minute — and the race hides that from clients entirely, so
/// per-upstream state must not drive an alert. Only "no upstream could
/// answer" means the daemon is not doing its job.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolHealth {
    /// Per-upstream detail.
    pub upstreams: Vec<UpstreamHealth>,
    /// Queries answered by at least one upstream.
    pub resolved: u64,
    /// Queries where every upstream failed (the client got SERVFAIL).
    pub all_failed_total: u64,
    /// Consecutive all-upstreams-failed queries; non-zero means the
    /// daemon cannot currently resolve anything.
    pub consecutive_all_failed: u64,
}

/// Health snapshot for a single upstream.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UpstreamHealth {
    /// The configured upstream URL.
    pub url: String,
    /// Whether a live connection is currently held.
    ///
    /// Informational only, and **not** a health signal: connections are
    /// rebuilt lazily on the next query, so a perfectly healthy upstream
    /// reads `false` between a connection dropping and the next query
    /// that needs it. Use `last_success_secs_ago` to judge health.
    pub connected: bool,
    /// Seconds since this upstream last answered, or `None` if it never
    /// has.
    pub last_success_secs_ago: Option<u64>,
    /// Queries dispatched to this upstream.
    pub queries: u64,
    /// Queries this upstream failed to answer (after any reconnect).
    pub failures: u64,
    /// Successful connection builds after the initial one.
    pub reconnects: u64,
    /// Failures since the last success; non-zero means degraded.
    pub consecutive_failures: u64,
}

/// One upstream plus the state that lets it survive a dead connection.
///
/// hickory's `DnsExchange` is a handle onto a background task. When that
/// task exits — the server sends GOAWAY, drops an idle HTTP/2 connection,
/// or the QUIC connection times out — every later send fails instantly
/// with `resource too busy`, permanently. Holding one exchange for the
/// process lifetime therefore turns a transient network event into a
/// dead resolver, so the exchange is dropped and rebuilt on failure.
///
/// The rebuild runs in a **detached task**, never inside the query that
/// noticed the death: queries race across upstreams and the losers are
/// cancelled, so a repair owned by a query would be abandoned whenever
/// a faster upstream answered first — and a consistently slower
/// upstream would never recover. Queries that find the slot empty wait
/// (bounded by their deadline) for the repair's outcome instead.
struct ReconnectingUpstream {
    factory: Box<dyn TransportFactory>,
    slot: RwLock<Slot>,
    /// Wait before the next build attempt, doubled on each rebuild that
    /// is not followed by a successful send; reset on success. Millis,
    /// atomic so the success path never takes the slot write lock.
    backoff_ms: AtomicU64,
    /// A detached repair task is currently running (dedup: at most one).
    repairing: AtomicBool,
    /// Bumped every time a repair attempt concludes (either way), so
    /// queries waiting for a transport can re-check the slot.
    repair_done: tokio::sync::watch::Sender<u64>,
    /// Bound on one connection build (bootstrap DNS + TCP/QUIC + TLS).
    build_timeout: Duration,
    queries: AtomicU64,
    failures: AtomicU64,
    reconnects: AtomicU64,
    consecutive_failures: AtomicU64,
    connected: AtomicBool,
    /// Unix seconds of the last successful answer; 0 means never.
    last_success_ts: AtomicI64,
}

impl ReconnectingUpstream {
    /// Build the initial connection; failure here is fatal at startup.
    async fn connect(
        factory: Box<dyn TransportFactory>,
        build_timeout: Duration,
    ) -> Result<Self, Error> {
        let transport = tokio::time::timeout(build_timeout, factory.build())
            .await
            .map_err(|_| {
                Error::Init(format!("{}: initial connection timed out", factory.label()))
            })??;
        Ok(Self::with_transport(factory, transport, build_timeout))
    }

    /// Wrap an already-established connection.
    fn with_transport(
        factory: Box<dyn TransportFactory>,
        transport: Arc<dyn Transport>,
        build_timeout: Duration,
    ) -> Self {
        Self {
            factory,
            slot: RwLock::new(Slot {
                generation: 0,
                transport: Some(transport),
                next_attempt: None,
            }),
            backoff_ms: AtomicU64::new(duration_to_millis(MIN_RECONNECT_BACKOFF)),
            repairing: AtomicBool::new(false),
            repair_done: tokio::sync::watch::Sender::new(0),
            build_timeout,
            queries: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            connected: AtomicBool::new(true),
            last_success_ts: AtomicI64::new(0),
        }
    }

    /// Spawn the detached repair task, unless one is already running.
    fn trigger_repair(self: &Arc<Self>) {
        if self.repairing.swap(true, Ordering::AcqRel) {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move { this.repair().await });
    }

    /// One repair attempt: build a fresh connection and install it.
    ///
    /// Runs detached from any query, so a cancelled query can never
    /// abandon it half-done. The build itself happens *outside* the
    /// slot lock; `repairing` already guarantees a single builder, so
    /// queries only ever wait on the lock for O(1) critical sections.
    async fn repair(self: Arc<Self>) {
        // Clear `repairing` and wake waiters however this task ends —
        // including a panic or the task being dropped at an await point
        // during shutdown. A stuck flag would block every future repair,
        // leaving the upstream dead until process restart.
        struct Concluded<'a>(&'a ReconnectingUpstream);
        impl Drop for Concluded<'_> {
            fn drop(&mut self) {
                self.0.repairing.store(false, Ordering::Release);
                self.0.repair_done.send_modify(|n| *n += 1);
            }
        }
        let _concluded = Concluded(&self);

        let should_build = {
            let slot = self.slot.read().await;
            // Nothing to do if a transport is already installed, and
            // don't build while a backoff window is still open.
            slot.transport.is_none() && slot.next_attempt.is_none_or(|next| Instant::now() >= next)
        };
        if should_build {
            let built = match tokio::time::timeout(self.build_timeout, self.factory.build()).await {
                Ok(Ok(transport)) => Ok(transport),
                Ok(Err(err)) => Err(err.to_string()),
                Err(_) => Err("connection build timed out".to_owned()),
            };
            let backoff = Duration::from_millis(self.backoff_ms.load(Ordering::Relaxed));
            let mut slot = self.slot.write().await;
            match built {
                Ok(transport) => {
                    slot.generation += 1;
                    slot.transport = Some(transport);
                    // Rate-limit the next rebuild: if this connection also
                    // fails without a single successful send, the upstream
                    // is accepting connections it cannot serve, and each
                    // rebuild costs a full handshake. Cap the *applied*
                    // holddown too: the ladder may have climbed to the 30s
                    // build-failure cap during an outage, and a working
                    // connection must never inherit a 30s retry gap.
                    slot.next_attempt = Some(Instant::now() + backoff.min(MAX_REBUILD_HOLDDOWN));
                    self.backoff_ms.store(
                        duration_to_millis((backoff * 2).min(MAX_REBUILD_HOLDDOWN)),
                        Ordering::Relaxed,
                    );
                    self.reconnects.fetch_add(1, Ordering::Relaxed);
                    self.connected.store(true, Ordering::Relaxed);
                    tracing::info!(upstream = self.factory.label(), "upstream reconnected");
                }
                Err(err) => {
                    slot.next_attempt = Some(Instant::now() + backoff);
                    self.backoff_ms.store(
                        duration_to_millis((backoff * 2).min(MAX_RECONNECT_BACKOFF)),
                        Ordering::Relaxed,
                    );
                    tracing::warn!(
                        upstream = self.factory.label(),
                        %err,
                        "upstream reconnect failed"
                    );
                }
            }
        }
    }

    /// Return a usable transport, waiting (up to `deadline`) for the
    /// detached repair if the slot is empty.
    async fn acquire(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<(u64, Arc<dyn Transport>), String> {
        loop {
            // Subscribe before reading the slot: a repair concluding
            // between the read and the wait then wakes us immediately.
            let mut done = self.repair_done.subscribe();
            {
                let slot = self.slot.read().await;
                if let Some(transport) = slot.transport.clone() {
                    return Ok((slot.generation, transport));
                }
                if let Some(next) = slot.next_attempt
                    && Instant::now() < next
                {
                    return Err(format!(
                        "{}: disconnected, reconnect backing off",
                        self.factory.label()
                    ));
                }
            }
            self.trigger_repair();
            match tokio::time::timeout_at(deadline, done.changed()).await {
                Ok(_) => {} // repair concluded (or sender replaced): re-check
                Err(_) => {
                    return Err(format!(
                        "{}: timed out waiting for reconnect",
                        self.factory.label()
                    ));
                }
            }
        }
    }

    /// Drop the transport of `generation`, unless it was already
    /// replaced, and kick off a detached repair.
    async fn invalidate(self: &Arc<Self>, generation: u64) {
        let empty = {
            let mut slot = self.slot.write().await;
            if slot.generation == generation {
                slot.transport = None;
                self.connected.store(false, Ordering::Relaxed);
            }
            slot.transport.is_none()
        };
        if empty {
            // The spawn happens before this function returns, so even if
            // the calling query is cancelled right after, the repair runs.
            self.trigger_repair();
        }
    }

    /// Send one query within `deadline`, reconnecting once if the
    /// current connection fails fatally.
    async fn send(self: &Arc<Self>, msg: Message, deadline: Instant) -> Result<Message, String> {
        self.queries.fetch_add(1, Ordering::Relaxed);

        let (generation, transport) = match self.acquire(deadline).await {
            Ok(pair) => pair,
            Err(err) => return Err(self.record_failure(err)),
        };

        let first_err =
            match tokio::time::timeout_at(deadline, transport.send_query(msg.clone())).await {
                Ok(Ok(response)) => return self.judge(response).await,
                Ok(Err(SendError::Query(err))) => {
                    // One bad answer does not condemn the connection.
                    return Err(self.record_failure(err));
                }
                Ok(Err(SendError::Fatal(err))) => err,
                Err(_) => {
                    // A silent hang poisons every query multiplexed onto
                    // this connection: tear it down like any fatal error.
                    self.invalidate(generation).await;
                    return Err(self.record_failure(format!("{}: timed out", self.factory.label())));
                }
            };

        // A dead exchange fails every subsequent send the same way, so
        // retrying on the same transport is pointless: replace it.
        tracing::warn!(
            upstream = self.factory.label(),
            err = %first_err,
            "upstream send failed; reconnecting"
        );
        self.invalidate(generation).await;

        let (generation, fresh) = match self.acquire(deadline).await {
            Ok(pair) => pair,
            Err(err) => return Err(self.record_failure(format!("{first_err}; {err}"))),
        };
        match tokio::time::timeout_at(deadline, fresh.send_query(msg)).await {
            Ok(Ok(response)) => self
                .judge(response)
                .await
                .map_err(|err| format!("{first_err}; after reconnect: {err}")),
            Ok(Err(SendError::Query(err))) => {
                Err(self.record_failure(format!("{first_err}; after reconnect: {err}")))
            }
            Ok(Err(SendError::Fatal(err))) => {
                self.invalidate(generation).await;
                Err(self.record_failure(format!("{first_err}; after reconnect: {err}")))
            }
            Err(_) => {
                self.invalidate(generation).await;
                Err(self.record_failure(format!(
                    "{first_err}; after reconnect: {}: timed out",
                    self.factory.label()
                )))
            }
        }
    }

    /// Accept or reject a transport-level success by its rcode.
    ///
    /// SERVFAIL/REFUSED/NOTIMP are unusable answers: they must count as
    /// this upstream failing — the health counters drive an operator
    /// alert, and an upstream that "answers" only SERVFAIL is exactly
    /// the failure the alert exists for. The connection stays: rcode is
    /// the server's verdict on the query, not on the transport.
    async fn judge(&self, response: Message) -> Result<Message, String> {
        use hickory_resolver::proto::op::ResponseCode;
        let rcode = response.metadata.response_code;
        if matches!(
            rcode,
            ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::NotImp
        ) {
            return Err(self.record_failure(format!(
                "{}: upstream answered {rcode}",
                self.factory.label()
            )));
        }
        self.record_success().await;
        Ok(response)
    }

    /// Note an answered query.
    async fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success_ts.store(unix_now(), Ordering::Relaxed);
        self.backoff_ms
            .store(duration_to_millis(MIN_RECONNECT_BACKOFF), Ordering::Relaxed);
        // Clear any pending holddown: this connection just proved
        // usable, so its eventual replacement must not be delayed by a
        // backoff earned during a previous outage.
        let pending = { self.slot.read().await.next_attempt.is_some() };
        if pending {
            self.slot.write().await.next_attempt = None;
        }
    }

    /// Count a failed query and return the error unchanged.
    fn record_failure(&self, err: String) -> String {
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        err
    }

    fn health(&self) -> UpstreamHealth {
        let last = self.last_success_ts.load(Ordering::Relaxed);
        UpstreamHealth {
            url: self.factory.label().to_owned(),
            connected: self.connected.load(Ordering::Relaxed),
            last_success_secs_ago: (last > 0)
                .then(|| unix_now().saturating_sub(last).max(0).cast_unsigned()),
            queries: self.queries.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
        }
    }
}

fn build_rustls_client_config() -> rustls::ClientConfig {
    // Ensure the ring CryptoProvider is installed process-wide (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let root_store: rustls::RootCertStore =
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

// ── UpstreamPool ────────────────────────────────────────────────────

/// A pool of encrypted DNS upstreams.
///
/// Queries are sent to **all** upstreams concurrently; the first
/// successful response wins. Per-upstream timeout is enforced.
pub struct UpstreamPool {
    upstreams: Vec<Arc<ReconnectingUpstream>>,
    timeout: Duration,
    resolved: AtomicU64,
    all_failed_total: AtomicU64,
    consecutive_all_failed: AtomicU64,
}

impl fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("upstream_count", &self.upstreams.len())
            .field("timeout", &self.timeout)
            .field("resolved", &self.resolved)
            .field("all_failed_total", &self.all_failed_total)
            .field("consecutive_all_failed", &self.consecutive_all_failed)
            .finish()
    }
}

impl UpstreamPool {
    /// Build a new pool from configuration.
    ///
    /// Every URL is validated, hostnames are resolved via the bootstrap
    /// servers, and one transport is built per upstream. **Any** failure
    /// is fatal — the pool refuses to partially initialise.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedUrl`] if a URL is malformed or uses an
    ///   unsupported scheme.
    /// - [`Error::Init`] if bootstrap resolution or transport creation
    ///   fails for any upstream.
    pub async fn new(cfg: &UpstreamConfig) -> Result<Self, Error> {
        if cfg.urls.is_empty() {
            return Err(Error::Init("no upstream URLs configured".into()));
        }
        if cfg.timeout_ms == 0 {
            return Err(Error::Init("timeout_ms must be > 0".into()));
        }

        let timeout = Duration::from_millis(cfg.timeout_ms);
        let mut upstreams: Vec<Arc<ReconnectingUpstream>> = Vec::with_capacity(cfg.urls.len());

        for raw_url in &cfg.urls {
            let kind = parse_upstream_url(raw_url)?;
            let factory = NetworkFactory {
                kind,
                bootstrap_ips: cfg.bootstrap_ips.clone(),
                url: raw_url.clone(),
            };
            upstreams.push(Arc::new(
                ReconnectingUpstream::connect(Box::new(factory), timeout).await?,
            ));
        }

        Ok(Self::assemble(upstreams, timeout))
    }

    fn assemble(upstreams: Vec<Arc<ReconnectingUpstream>>, timeout: Duration) -> Self {
        Self {
            upstreams,
            timeout,
            resolved: AtomicU64::new(0),
            all_failed_total: AtomicU64::new(0),
            consecutive_all_failed: AtomicU64::new(0),
        }
    }

    /// Health counters for `status` and the soak alerting.
    #[must_use]
    pub fn health(&self) -> PoolHealth {
        PoolHealth {
            upstreams: self.upstreams.iter().map(|u| u.health()).collect(),
            resolved: self.resolved.load(Ordering::Relaxed),
            all_failed_total: self.all_failed_total.load(Ordering::Relaxed),
            consecutive_all_failed: self.consecutive_all_failed.load(Ordering::Relaxed),
        }
    }

    /// Resolve a DNS query through the upstream pool.
    ///
    /// The DO (DNSSEC OK) bit is set on the outgoing query. All
    /// upstreams are queried concurrently with the configured timeout.
    /// The first successful response wins; its id is overwritten with
    /// the original query id before returning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AllFailed`] if every upstream either times out
    /// or returns an error.
    pub async fn resolve(&self, query: &Message) -> Result<Message, Error> {
        let mut outgoing = query.clone();

        // Ensure RD is set — we forward to recursive upstreams.
        outgoing.metadata.recursion_desired = true;

        // Set the DO bit via EDNS.
        let mut edns = outgoing.edns.clone().unwrap_or_default();
        edns.set_dnssec_ok(true);
        outgoing.set_edns(edns);

        let original_id = query.metadata.id;
        // Each send bounds every await inside it by this deadline, so no
        // outer timeout is needed — and unlike an outer timeout, a hang
        // inside a send is seen by the upstream's own failure handling
        // (tear-down, reconnect, health counters), not just by the pool.
        let deadline = Instant::now() + self.timeout;

        // Each upstream leg runs as its own task, NOT as a racing future
        // dropped when a sibling wins: a cancelled leg would abandon its
        // failure handling mid-flight, so a slower upstream whose
        // connection died would never notice (no failure counted, no
        // tear-down, no repair) as long as a faster one kept answering.
        // A detached leg always runs to its own conclusion; the race
        // only decides whose answer the client gets.
        let (tx, mut rx) = tokio::sync::mpsc::channel(self.upstreams.len());
        for upstream in &self.upstreams {
            let msg = outgoing.clone();
            let tx = tx.clone();
            let upstream = Arc::clone(upstream);
            tokio::spawn(async move {
                let _ = tx.send(upstream.send(msg, deadline).await).await;
            });
        }
        drop(tx);

        let mut errors = Vec::new();

        while let Some(result) = rx.recv().await {
            match result {
                Ok(mut response) => {
                    // send() already rejected unusable rcodes, so any
                    // success here may win the race.
                    // Stamp the original query id (DoQ may force id=0).
                    response.metadata.id = original_id;
                    self.resolved.fetch_add(1, Ordering::Relaxed);
                    self.consecutive_all_failed.store(0, Ordering::Relaxed);
                    return Ok(response);
                }
                Err(e) => errors.push(e),
            }
        }

        self.all_failed_total.fetch_add(1, Ordering::Relaxed);
        self.consecutive_all_failed.fetch_add(1, Ordering::Relaxed);
        Err(Error::AllFailed(errors))
    }

    // ── Test-only constructor ───────────────────────────────────────

    /// Build a pool from already-connected transports that never change.
    #[cfg(test)]
    fn from_transports(transports: Vec<Box<dyn Transport>>, timeout: Duration) -> Self {
        let upstreams = transports
            .into_iter()
            .enumerate()
            .map(|(i, transport)| {
                let transport: Arc<dyn Transport> = Arc::from(transport);
                let factory = tests::StaticFactory {
                    transport: Arc::clone(&transport),
                    label: format!("static-{i}"),
                };
                Arc::new(ReconnectingUpstream::with_transport(
                    Box::new(factory),
                    transport,
                    timeout,
                ))
            })
            .collect();
        Self::assemble(upstreams, timeout)
    }

    /// Build a pool from transport factories, so a test can script
    /// connection death and observe the rebuild.
    #[cfg(test)]
    async fn from_factories(factories: Vec<Box<dyn TransportFactory>>, timeout: Duration) -> Self {
        let mut upstreams = Vec::with_capacity(factories.len());
        for factory in factories {
            upstreams.push(Arc::new(
                ReconnectingUpstream::connect(factory, timeout)
                    .await
                    .expect("initial connect"),
            ));
        }
        Self::assemble(upstreams, timeout)
    }
}

// Required for the RuntimeProvider Handle::Spawn bound.
use hickory_resolver::net::runtime::Spawn;

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── Fake transports ─────────────────────────────────────────────

    /// A fake transport that returns a fixed response after a delay.
    struct FakeTransport {
        delay: Duration,
        /// If `Some`, return this error instead of a response.
        error: Option<String>,
        /// Response id to return (simulates `DoQ` id=0 behaviour).
        response_id: u16,
    }

    impl FakeTransport {
        fn ok(delay: Duration) -> Self {
            Self {
                delay,
                error: None,
                response_id: 0,
            }
        }

        fn ok_with_id(delay: Duration, response_id: u16) -> Self {
            Self {
                delay,
                error: None,
                response_id,
            }
        }

        fn failing(msg: &str) -> Self {
            Self {
                delay: Duration::ZERO,
                error: Some(msg.to_owned()),
                response_id: 0,
            }
        }
    }

    impl Transport for FakeTransport {
        fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
            Box::pin(async move {
                if self.delay > Duration::ZERO {
                    tokio::time::sleep(self.delay).await;
                }
                if let Some(ref err) = self.error {
                    return Err(SendError::Fatal(err.clone()));
                }
                let mut resp = Message::new(self.response_id, MessageType::Response, OpCode::Query);
                // Echo back the query questions so the caller can verify.
                for q in &msg.queries {
                    resp.add_query(q.clone());
                }
                Ok(resp)
            })
        }
    }

    /// A factory that hands out the same transport forever.
    pub(super) struct StaticFactory {
        pub(super) transport: Arc<dyn Transport>,
        pub(super) label: String,
    }

    impl TransportFactory for StaticFactory {
        fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
            let transport = Arc::clone(&self.transport);
            Box::pin(async move { Ok(transport) })
        }

        fn label(&self) -> &str {
            &self.label
        }
    }

    /// A transport that answers `healthy_sends` queries and then fails
    /// every later one — hickory's dead-`DnsExchange` behaviour.
    struct DiesAfter {
        healthy_sends: usize,
        sends: AtomicU64,
    }

    impl DiesAfter {
        fn new(healthy_sends: usize) -> Self {
            Self {
                healthy_sends,
                sends: AtomicU64::new(0),
            }
        }
    }

    impl Transport for DiesAfter {
        fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
            let n = self.sends.fetch_add(1, Ordering::Relaxed);
            let dead = n >= self.healthy_sends as u64;
            Box::pin(async move {
                if dead {
                    return Err(SendError::Fatal("resource too busy".to_owned()));
                }
                let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
                for q in &msg.queries {
                    resp.add_query(q.clone());
                }
                Ok(resp)
            })
        }
    }

    /// A factory whose every build produces a fresh [`DiesAfter`], and
    /// which counts how many connections were built.
    struct DyingFactory {
        healthy_sends: usize,
        builds: Arc<AtomicU64>,
        label: &'static str,
    }

    impl TransportFactory for DyingFactory {
        fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
            self.builds.fetch_add(1, Ordering::Relaxed);
            let healthy_sends = self.healthy_sends;
            Box::pin(
                async move { Ok(Arc::new(DiesAfter::new(healthy_sends)) as Arc<dyn Transport>) },
            )
        }

        fn label(&self) -> &str {
            self.label
        }
    }

    /// Echo the query back as a bare response.
    fn echo_response(msg: &Message) -> Message {
        let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
        for q in &msg.queries {
            resp.add_query(q.clone());
        }
        resp
    }

    /// A transport whose liveness the test flips at will — the network
    /// going away and coming back under a running daemon.
    struct Flaky {
        up: Arc<AtomicBool>,
    }

    impl Transport for Flaky {
        fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
            let up = self.up.load(Ordering::Relaxed);
            Box::pin(async move {
                if up {
                    Ok(echo_response(&msg))
                } else {
                    Err(SendError::Fatal("resource too busy".to_owned()))
                }
            })
        }
    }

    struct FlakyFactory {
        up: Arc<AtomicBool>,
        label: &'static str,
    }

    impl TransportFactory for FlakyFactory {
        fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
            let up = Arc::clone(&self.up);
            Box::pin(async move { Ok(Arc::new(Flaky { up }) as Arc<dyn Transport>) })
        }

        fn label(&self) -> &str {
            self.label
        }
    }

    /// A factory that connects once and then refuses to build again.
    struct BreaksAfterFirstBuild {
        builds: Arc<AtomicU64>,
        label: &'static str,
    }

    impl TransportFactory for BreaksAfterFirstBuild {
        fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
            let n = self.builds.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                if n == 0 {
                    Ok(Arc::new(DiesAfter::new(0)) as Arc<dyn Transport>)
                } else {
                    Err(Error::Init("connection refused".into()))
                }
            })
        }

        fn label(&self) -> &str {
            self.label
        }
    }

    use hickory_resolver::proto::op::{MessageType, OpCode};
    use hickory_resolver::proto::rr::{Name, RecordType};

    /// Build a test query Message with the given id.
    fn test_query(id: u16) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        msg
    }

    // ── URL validation tests ────────────────────────────────────────

    #[test]
    fn valid_https_url() {
        let kind = parse_upstream_url("https://dns.cloudflare.com/dns-query").unwrap();
        match kind {
            UpstreamKind::Https { host, port, path } => {
                assert_eq!(host, "dns.cloudflare.com");
                assert_eq!(port, 443);
                assert_eq!(path, "/dns-query");
            }
            UpstreamKind::Quic { .. } => panic!("expected Https"),
        }
    }

    #[test]
    fn valid_https_url_custom_port() {
        let kind = parse_upstream_url("https://dns.example.com:8443/resolve").unwrap();
        match kind {
            UpstreamKind::Https { host, port, path } => {
                assert_eq!(host, "dns.example.com");
                assert_eq!(port, 8443);
                assert_eq!(path, "/resolve");
            }
            UpstreamKind::Quic { .. } => panic!("expected Https"),
        }
    }

    #[test]
    fn valid_quic_url() {
        let kind = parse_upstream_url("quic://dns.adguard.com").unwrap();
        match kind {
            UpstreamKind::Quic { host, port } => {
                assert_eq!(host, "dns.adguard.com");
                assert_eq!(port, 853);
            }
            UpstreamKind::Https { .. } => panic!("expected Quic"),
        }
    }

    #[test]
    fn valid_quic_url_custom_port() {
        let kind = parse_upstream_url("quic://dns.example.com:8853").unwrap();
        match kind {
            UpstreamKind::Quic { host, port } => {
                assert_eq!(host, "dns.example.com");
                assert_eq!(port, 8853);
            }
            UpstreamKind::Https { .. } => panic!("expected Quic"),
        }
    }

    #[test]
    fn unsupported_scheme_http() {
        let err = parse_upstream_url("http://dns.example.com/dns-query").unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    #[test]
    fn unsupported_scheme_tls() {
        let err = parse_upstream_url("tls://dns.example.com").unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    #[test]
    fn unsupported_scheme_udp() {
        let err = parse_upstream_url("udp://8.8.8.8").unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    #[test]
    fn https_url_missing_path() {
        let err = parse_upstream_url("https://dns.example.com").unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    #[test]
    fn https_url_root_path_only() {
        let err = parse_upstream_url("https://dns.example.com/").unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    #[test]
    fn malformed_url() {
        let err = parse_upstream_url("not a url at all").unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    #[test]
    fn empty_url() {
        let err = parse_upstream_url("").unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    // ── Pool::new validation tests ──────────────────────────────────

    #[tokio::test]
    async fn new_rejects_empty_urls() {
        let cfg = UpstreamConfig {
            urls: vec![],
            bootstrap_ips: vec!["1.1.1.1".parse().unwrap()],
            timeout_ms: 5000,
        };
        let err = UpstreamPool::new(&cfg).await.unwrap_err();
        assert!(matches!(err, Error::Init(_)));
    }

    #[tokio::test]
    async fn new_rejects_zero_timeout() {
        let cfg = UpstreamConfig {
            urls: vec!["https://dns.example.com/dns-query".into()],
            bootstrap_ips: vec!["1.1.1.1".parse().unwrap()],
            timeout_ms: 0,
        };
        let err = UpstreamPool::new(&cfg).await.unwrap_err();
        assert!(matches!(err, Error::Init(_)));
    }

    #[tokio::test]
    async fn new_rejects_bad_url() {
        let cfg = UpstreamConfig {
            urls: vec!["http://bad-scheme.example.com/dns-query".into()],
            bootstrap_ips: vec!["1.1.1.1".parse().unwrap()],
            timeout_ms: 5000,
        };
        let err = UpstreamPool::new(&cfg).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedUrl(_)));
    }

    #[tokio::test]
    async fn new_rejects_empty_bootstrap_for_hostname() {
        let cfg = UpstreamConfig {
            urls: vec!["https://dns.example.com/dns-query".into()],
            bootstrap_ips: vec![],
            timeout_ms: 5000,
        };
        let err = UpstreamPool::new(&cfg).await.unwrap_err();
        assert!(matches!(err, Error::Init(_)));
    }

    // ── Racing / timeout / AllFailed tests ──────────────────────────

    #[tokio::test]
    async fn first_ok_wins_fast_over_slow() {
        let pool = UpstreamPool::from_transports(
            vec![
                Box::new(FakeTransport::ok(Duration::from_millis(200))),
                Box::new(FakeTransport::ok(Duration::from_millis(10))),
            ],
            Duration::from_secs(5),
        );

        let query = test_query(42);

        let start = tokio::time::Instant::now();
        let resp = pool.resolve(&query).await.unwrap();
        let elapsed = start.elapsed();

        // The fast transport (10ms) should win well before the slow one (200ms).
        assert!(elapsed < Duration::from_millis(150));
        // Id should be stamped to the original query id.
        assert_eq!(resp.metadata.id, 42);
    }

    #[tokio::test]
    async fn response_id_stamped_from_query() {
        // Simulate DoQ returning id=0.
        let pool = UpstreamPool::from_transports(
            vec![Box::new(FakeTransport::ok_with_id(
                Duration::from_millis(1),
                0,
            ))],
            Duration::from_secs(5),
        );

        let query = test_query(12345);

        let resp = pool.resolve(&query).await.unwrap();
        assert_eq!(resp.metadata.id, 12345);
    }

    #[tokio::test]
    async fn do_bit_set_on_outgoing() {
        /// A transport that captures whether the DO bit was set.
        struct CaptureDo;

        impl Transport for CaptureDo {
            fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
                Box::pin(async move {
                    let edns = msg
                        .edns
                        .as_ref()
                        .expect("EDNS should be present on outgoing query");
                    assert!(edns.flags().dnssec_ok, "DO bit should be set");
                    Ok(Message::response(0, OpCode::Query))
                })
            }
        }

        let pool = UpstreamPool::from_transports(vec![Box::new(CaptureDo)], Duration::from_secs(5));

        let query = test_query(1);
        pool.resolve(&query).await.unwrap();
    }

    #[tokio::test]
    async fn all_fail_returns_all_failed() {
        let pool = UpstreamPool::from_transports(
            vec![
                Box::new(FakeTransport::failing("upstream-1 down")),
                Box::new(FakeTransport::failing("upstream-2 down")),
            ],
            Duration::from_secs(5),
        );

        let query = test_query(1);

        let err = pool.resolve(&query).await.unwrap_err();
        match err {
            Error::AllFailed(errs) => {
                assert_eq!(errs.len(), 2);
                assert!(errs.iter().any(|e| e.contains("upstream-1")));
                assert!(errs.iter().any(|e| e.contains("upstream-2")));
            }
            other => panic!("expected AllFailed, got {other}"),
        }
    }

    #[tokio::test]
    async fn timeout_triggers_when_transport_too_slow() {
        let pool = UpstreamPool::from_transports(
            vec![Box::new(FakeTransport::ok(Duration::from_secs(10)))],
            Duration::from_millis(50), // 50ms timeout
        );

        let query = test_query(1);

        let err = pool.resolve(&query).await.unwrap_err();
        assert!(matches!(err, Error::AllFailed(_)));
    }

    #[tokio::test]
    async fn one_fails_one_succeeds() {
        let pool = UpstreamPool::from_transports(
            vec![
                Box::new(FakeTransport::failing("nope")),
                Box::new(FakeTransport::ok(Duration::from_millis(1))),
            ],
            Duration::from_secs(5),
        );

        let query = test_query(99);

        let resp = pool.resolve(&query).await.unwrap();
        assert_eq!(resp.metadata.id, 99);
    }

    #[tokio::test]
    async fn one_timeout_one_succeeds() {
        let pool = UpstreamPool::from_transports(
            vec![
                Box::new(FakeTransport::ok(Duration::from_secs(10))), // will timeout
                Box::new(FakeTransport::ok(Duration::from_millis(5))), // fast
            ],
            Duration::from_millis(50),
        );

        let query = test_query(77);

        let resp = pool.resolve(&query).await.unwrap();
        assert_eq!(resp.metadata.id, 77);
    }

    // ── Reconnection tests ──────────────────────────────────────────
    //
    // Regression cover for the 2026-08-20 shadow outage: a single
    // long-lived `DnsExchange` died about an hour into the run and every
    // later query returned `resource too busy`, so the daemon SERVFAILed
    // for seven hours straight with no recovery path.

    #[tokio::test]
    async fn dead_connection_is_replaced_within_the_same_query() {
        let builds = Arc::new(AtomicU64::new(0));
        // Healthy for exactly one send, then dead like a closed exchange.
        let pool = UpstreamPool::from_factories(
            vec![Box::new(DyingFactory {
                healthy_sends: 1,
                builds: Arc::clone(&builds),
                label: "dying",
            })],
            Duration::from_secs(5),
        )
        .await;

        // First query rides the connection built at startup.
        assert_eq!(pool.resolve(&test_query(1)).await.unwrap().metadata.id, 1);
        assert_eq!(builds.load(Ordering::Relaxed), 1);

        // The second query hits the now-dead connection. Before the fix
        // this returned AllFailed forever; now it must reconnect and
        // answer without the caller ever seeing a failure.
        assert_eq!(pool.resolve(&test_query(2)).await.unwrap().metadata.id, 2);
        assert_eq!(builds.load(Ordering::Relaxed), 2, "expected one rebuild");
    }

    #[tokio::test]
    async fn recovery_is_sustained_over_many_queries() {
        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(DyingFactory {
                healthy_sends: 1,
                builds: Arc::clone(&builds),
                label: "dying",
            })],
            Duration::from_secs(5),
        )
        .await;

        // Every connection dies after one send, so every query but the
        // first must reconnect. None of them may fail.
        for id in 1..=20u16 {
            let resp = pool
                .resolve(&test_query(id))
                .await
                .unwrap_or_else(|e| panic!("query {id} failed: {e}"));
            assert_eq!(resp.metadata.id, id);
        }
        assert_eq!(builds.load(Ordering::Relaxed), 20);
    }

    #[tokio::test]
    async fn healthy_connection_is_reused_not_rebuilt() {
        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(DyingFactory {
                healthy_sends: usize::MAX,
                builds: Arc::clone(&builds),
                label: "dying",
            })],
            Duration::from_secs(5),
        )
        .await;

        for id in 1..=50u16 {
            pool.resolve(&test_query(id)).await.unwrap();
        }
        // Connection reuse is the whole point of DoH/DoQ: one handshake.
        assert_eq!(builds.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_backoff_stops_hammering_a_down_upstream() {
        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(BreaksAfterFirstBuild {
                builds: Arc::clone(&builds),
                label: "broken",
            })],
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(builds.load(Ordering::Relaxed), 1);

        // The startup connection is dead on arrival and rebuilds fail, so
        // every query errors — but without a build attempt per query.
        for id in 1..=10u16 {
            assert!(pool.resolve(&test_query(id)).await.is_err());
        }
        let attempts = builds.load(Ordering::Relaxed);
        assert!(
            attempts < 10,
            "backoff should suppress a build per query, saw {attempts}"
        );

        // Past the backoff window a fresh attempt is allowed again.
        tokio::time::advance(MAX_RECONNECT_BACKOFF * 2).await;
        assert!(pool.resolve(&test_query(99)).await.is_err());
        assert!(builds.load(Ordering::Relaxed) > attempts);
    }

    #[tokio::test]
    async fn health_surfaces_upstream_failures() {
        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(BreaksAfterFirstBuild {
                builds: Arc::clone(&builds),
                label: "broken",
            })],
            Duration::from_secs(5),
        )
        .await;

        assert!(pool.resolve(&test_query(1)).await.is_err());

        let health = pool.health();
        assert_eq!(health.upstreams.len(), 1);
        assert_eq!(health.upstreams[0].url, "broken");
        assert!(
            !health.upstreams[0].connected,
            "a dead upstream must report down"
        );
        assert_eq!(health.upstreams[0].queries, 1);
        assert_eq!(health.upstreams[0].failures, 1);
        assert!(health.upstreams[0].consecutive_failures >= 1);
        assert_eq!(
            health.upstreams[0].last_success_secs_ago, None,
            "an upstream that never answered must not look recent"
        );
        // Pool level: the client got nothing, and that is the signal
        // alerting keys off.
        assert_eq!(health.resolved, 0);
        assert_eq!(health.all_failed_total, 1);
        assert_eq!(health.consecutive_all_failed, 1);
    }

    #[tokio::test]
    async fn one_dead_upstream_does_not_stop_the_race() {
        let pool = UpstreamPool::from_factories(
            vec![
                Box::new(BreaksAfterFirstBuild {
                    builds: Arc::new(AtomicU64::new(0)),
                    label: "broken",
                }),
                Box::new(DyingFactory {
                    healthy_sends: usize::MAX,
                    builds: Arc::new(AtomicU64::new(0)),
                    label: "healthy",
                }),
            ],
            Duration::from_secs(5),
        )
        .await;

        let resp = pool.resolve(&test_query(7)).await.unwrap();
        assert_eq!(resp.metadata.id, 7);

        // One upstream is hard-down, yet the pool answered: this is the
        // shape that must NOT read as degraded, or the soak alert cries
        // wolf every time Quad9 drops a connection.
        let health = pool.health();
        assert_eq!(health.resolved, 1);
        assert_eq!(health.all_failed_total, 0);
        assert_eq!(health.consecutive_all_failed, 0);
    }

    #[tokio::test]
    async fn pool_failure_streak_clears_once_an_upstream_answers_again() {
        let up = Arc::new(AtomicBool::new(true));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(FlakyFactory {
                up: Arc::clone(&up),
                label: "flaky",
            })],
            Duration::from_secs(5),
        )
        .await;

        pool.resolve(&test_query(1)).await.unwrap();
        assert_eq!(pool.health().consecutive_all_failed, 0);

        // The network goes away: the send fails, the rebuild succeeds but
        // the replacement cannot send either, so the client gets nothing.
        up.store(false, Ordering::Relaxed);
        assert!(pool.resolve(&test_query(2)).await.is_err());
        assert!(pool.resolve(&test_query(3)).await.is_err());
        let health = pool.health();
        assert_eq!(health.consecutive_all_failed, 2);
        assert_eq!(health.all_failed_total, 2);

        // ...and comes back. Sit out the rebuild holddown earned during
        // the outage: recovery is only visible on the next rebuild.
        up.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        pool.resolve(&test_query(4)).await.unwrap();
        let health = pool.health();
        assert_eq!(
            health.consecutive_all_failed, 0,
            "the streak must clear on recovery, or status stays degraded forever"
        );
        assert_eq!(health.all_failed_total, 2, "the total stays cumulative");
        assert_eq!(health.resolved, 2);
        assert!(
            health.upstreams[0].last_success_secs_ago.is_some(),
            "an upstream that just answered must report a last success"
        );
    }

    // ── Hypothesis evidence tests (2026-08-20 review) ───────────────

    /// A transport that never answers: the peer accepted the connection
    /// and then went silent (black-holed route, dead middlebox).
    struct Hangs;

    impl Transport for Hangs {
        fn send_query(&self, _msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
            Box::pin(async move {
                std::future::pending::<()>().await;
                unreachable!()
            })
        }
    }

    /// Build #0 hangs on every send; later builds are healthy.
    struct HangsThenHealthy {
        builds: Arc<AtomicU64>,
        label: &'static str,
    }

    impl TransportFactory for HangsThenHealthy {
        fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
            let n = self.builds.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                if n == 0 {
                    Ok(Arc::new(Hangs) as Arc<dyn Transport>)
                } else {
                    Ok(Arc::new(DiesAfter::new(usize::MAX)) as Arc<dyn Transport>)
                }
            })
        }

        fn label(&self) -> &str {
            self.label
        }
    }

    /// H1: an upstream whose connection hangs silently until the query
    /// deadline must be torn down and replaced, not reused forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hung_connection_is_torn_down_and_replaced() {
        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(HangsThenHealthy {
                builds: Arc::clone(&builds),
                label: "hung",
            })],
            Duration::from_millis(100),
        )
        .await;

        // First query rides the hung connection into the deadline.
        assert!(pool.resolve(&test_query(1)).await.is_err());

        // The hang must count as a failure on this upstream (H5).
        let health = pool.health();
        assert!(
            health.upstreams[0].failures >= 1,
            "a timed-out query must count as an upstream failure, saw {}",
            health.upstreams[0].failures
        );

        // Give the detached repair a moment, then the upstream must
        // answer again — before the fix the hung transport was reused
        // for every later query, failing all of them.
        tokio::time::sleep(Duration::from_millis(700)).await;
        let resp = pool
            .resolve(&test_query(2))
            .await
            .expect("upstream must recover after the hung connection is replaced");
        assert_eq!(resp.metadata.id, 2);
        assert!(
            builds.load(Ordering::Relaxed) >= 2,
            "the hung transport was never replaced"
        );
    }

    /// A factory whose rebuilds take a while, like a real TLS handshake.
    struct SlowRebuild {
        builds_started: Arc<AtomicU64>,
        builds_completed: Arc<AtomicU64>,
        label: &'static str,
    }

    impl TransportFactory for SlowRebuild {
        fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
            let n = self.builds_started.fetch_add(1, Ordering::Relaxed);
            let completed = Arc::clone(&self.builds_completed);
            Box::pin(async move {
                if n == 0 {
                    // Startup connection: dead on arrival.
                    completed.fetch_add(1, Ordering::Relaxed);
                    Ok(Arc::new(DiesAfter::new(0)) as Arc<dyn Transport>)
                } else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    completed.fetch_add(1, Ordering::Relaxed);
                    Ok(Arc::new(DiesAfter::new(usize::MAX)) as Arc<dyn Transport>)
                }
            })
        }

        fn label(&self) -> &str {
            self.label
        }
    }

    /// H2: the repair of a broken upstream must survive the query that
    /// triggered it being cancelled because a faster upstream won.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repair_survives_cancellation_by_a_faster_upstream() {
        let builds_started = Arc::new(AtomicU64::new(0));
        let builds_completed = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![
                Box::new(DyingFactory {
                    healthy_sends: usize::MAX,
                    builds: Arc::new(AtomicU64::new(0)),
                    label: "fast-healthy",
                }),
                Box::new(SlowRebuild {
                    builds_started: Arc::clone(&builds_started),
                    builds_completed: Arc::clone(&builds_completed),
                    label: "slow-rebuilder",
                }),
            ],
            Duration::from_secs(5),
        )
        .await;

        // Each query is answered by the healthy upstream almost
        // instantly, cancelling the loser mid-rebuild every time.
        for id in 1..=10u16 {
            pool.resolve(&test_query(id)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Give any in-flight rebuild time to finish.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            builds_completed.load(Ordering::Relaxed) >= 2,
            "the slower upstream's repair never completed: {} started, {} completed",
            builds_started.load(Ordering::Relaxed),
            builds_completed.load(Ordering::Relaxed),
        );
        let health = pool.health();
        assert!(
            health.upstreams[1].connected,
            "the slower upstream must end up repaired"
        );
    }

    /// H3: an upstream that accepts connections but fails every send
    /// must not cost a fresh handshake per query.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failing_sends_do_not_cause_a_handshake_per_query() {
        struct CountingFlakyFactory {
            up: Arc<AtomicBool>,
            builds: Arc<AtomicU64>,
            label: &'static str,
        }

        impl TransportFactory for CountingFlakyFactory {
            fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
                self.builds.fetch_add(1, Ordering::Relaxed);
                let up = Arc::clone(&self.up);
                Box::pin(async move { Ok(Arc::new(Flaky { up }) as Arc<dyn Transport>) })
            }

            fn label(&self) -> &str {
                self.label
            }
        }

        let up = Arc::new(AtomicBool::new(false));
        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(CountingFlakyFactory {
                up: Arc::clone(&up),
                builds: Arc::clone(&builds),
                label: "accepts-but-cannot-answer",
            })],
            Duration::from_secs(5),
        )
        .await;

        for id in 1..=20u16 {
            assert!(pool.resolve(&test_query(id)).await.is_err());
        }
        // 20 failed queries in well under the minimum backoff window
        // must not have paid anywhere near 20 handshakes.
        let n = builds.load(Ordering::Relaxed);
        assert!(n <= 4, "handshake per query: {n} builds for 20 queries");
    }

    /// A recovered upstream must not inherit the 30s build-failure
    /// backoff as its post-install holddown: once a build succeeds, the
    /// applied holddown is capped at [`MAX_REBUILD_HOLDDOWN`].
    #[tokio::test(start_paused = true)]
    async fn recovered_upstream_is_not_held_down_by_outage_backoff() {
        struct Script {
            builds: Arc<AtomicU64>,
            label: &'static str,
        }

        impl TransportFactory for Script {
            fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
                let n = self.builds.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move {
                    match n {
                        // Startup connection: answers once, then dies.
                        0 => Ok(Arc::new(DiesAfter::new(1)) as Arc<dyn Transport>),
                        // Outage: six failed builds climb the ladder to 30s.
                        1..=6 => Err(Error::Init("connection refused".into())),
                        // Recovery, but this connection is dead on arrival:
                        // no send succeeds before the next rebuild.
                        7 => Ok(Arc::new(DiesAfter::new(0)) as Arc<dyn Transport>),
                        _ => Ok(Arc::new(DiesAfter::new(usize::MAX)) as Arc<dyn Transport>),
                    }
                })
            }

            fn label(&self) -> &str {
                self.label
            }
        }

        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(Script {
                builds: Arc::clone(&builds),
                label: "outage-then-recovery",
            })],
            Duration::from_secs(5),
        )
        .await;

        pool.resolve(&test_query(1)).await.unwrap();

        // Outage: six failed builds climb the ladder to the 30s cap.
        for id in 2..=7u16 {
            assert!(pool.resolve(&test_query(id)).await.is_err());
            tokio::time::advance(Duration::from_secs(31)).await;
        }
        // Recovery build: succeeds but dead on arrival, so the applied
        // holddown (not any later reset) is what gates the next rebuild.
        assert!(pool.resolve(&test_query(8)).await.is_err());
        assert!(
            builds.load(Ordering::Relaxed) >= 8,
            "expected the scripted builds to be consumed, saw {}",
            builds.load(Ordering::Relaxed)
        );

        // Rewind-free check: within one holddown cap of the last
        // failure, the upstream must answer again — an outage-earned 30s
        // backoff must not gate a now-working upstream.
        tokio::time::advance(MAX_REBUILD_HOLDDOWN + Duration::from_millis(500)).await;
        pool.resolve(&test_query(21))
            .await
            .expect("recovered upstream must answer within the holddown cap");
    }

    /// H4: a query-specific error (bad response for one query) must not
    /// tear down an otherwise healthy multiplexed connection.
    #[tokio::test]
    async fn query_error_does_not_kill_the_connection() {
        /// Errors the first send as query-specific, then answers.
        struct BadAnswerOnce {
            fired: AtomicBool,
        }

        impl Transport for BadAnswerOnce {
            fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
                let first = !self.fired.swap(true, Ordering::Relaxed);
                Box::pin(async move {
                    if first {
                        Err(SendError::Query("malformed response for this query".into()))
                    } else {
                        Ok(echo_response(&msg))
                    }
                })
            }
        }

        struct CountingOnceFactory {
            builds: Arc<AtomicU64>,
            label: &'static str,
        }

        impl TransportFactory for CountingOnceFactory {
            fn build(&self) -> BoxSendFuture<'_, Result<Arc<dyn Transport>, Error>> {
                self.builds.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move {
                    Ok(Arc::new(BadAnswerOnce {
                        fired: AtomicBool::new(false),
                    }) as Arc<dyn Transport>)
                })
            }

            fn label(&self) -> &str {
                self.label
            }
        }

        let builds = Arc::new(AtomicU64::new(0));
        let pool = UpstreamPool::from_factories(
            vec![Box::new(CountingOnceFactory {
                builds: Arc::clone(&builds),
                label: "bad-answer-once",
            })],
            Duration::from_secs(5),
        )
        .await;

        // The query that hit the bad answer fails...
        assert!(pool.resolve(&test_query(1)).await.is_err());
        // ...but the connection survives: the next query succeeds on it.
        pool.resolve(&test_query(2)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            builds.load(Ordering::Relaxed),
            1,
            "a query-specific error must not cause a rebuild"
        );
        let health = pool.health();
        assert_eq!(health.upstreams[0].failures, 1);
        assert_eq!(health.upstreams[0].consecutive_failures, 0);
    }

    /// H5: an upstream whose answers are unusable (SERVFAIL) must not
    /// read as healthy in the per-upstream counters.
    #[tokio::test]
    async fn unusable_answers_count_as_upstream_failures() {
        /// Transport-level success carrying SERVFAIL every time.
        struct AlwaysServfail;

        impl Transport for AlwaysServfail {
            fn send_query(&self, msg: Message) -> BoxSendFuture<'_, Result<Message, SendError>> {
                Box::pin(async move {
                    let mut resp = echo_response(&msg);
                    resp.metadata.response_code =
                        hickory_resolver::proto::op::ResponseCode::ServFail;
                    Ok(resp)
                })
            }
        }

        let pool =
            UpstreamPool::from_transports(vec![Box::new(AlwaysServfail)], Duration::from_secs(5));

        for id in 1..=3u16 {
            assert!(pool.resolve(&test_query(id)).await.is_err());
        }

        let health = pool.health();
        assert_eq!(
            health.upstreams[0].failures, 3,
            "SERVFAIL answers must count as failures"
        );
        assert_eq!(health.upstreams[0].consecutive_failures, 3);
        assert_eq!(
            health.upstreams[0].last_success_secs_ago, None,
            "an upstream that never gave a usable answer must not read healthy"
        );
    }

    // ── Live network test (requires network, kept #[ignore]) ────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires network access to Cloudflare DoH"]
    async fn live_doh_cloudflare() {
        let cfg = UpstreamConfig {
            urls: vec!["https://dns.cloudflare.com/dns-query".into()],
            bootstrap_ips: vec!["1.1.1.1".parse().unwrap(), "1.0.0.1".parse().unwrap()],
            timeout_ms: 10_000,
        };

        let pool = UpstreamPool::new(&cfg).await.expect("pool init");

        let query = test_query(1234);

        let resp = pool.resolve(&query).await.expect("resolve");
        assert_eq!(resp.metadata.id, 1234);
        assert!(!resp.answers.is_empty(), "expected at least one A record");
    }
}
