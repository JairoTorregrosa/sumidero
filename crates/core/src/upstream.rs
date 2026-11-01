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
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::h2::HttpsClientStream;
use hickory_resolver::net::quic::QuicClientStream;
use hickory_resolver::net::runtime::{RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, Message};
use hickory_resolver::{Resolver, TokioResolver};
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
    /// Trust anchors added to the public web PKI (`[tls] extra_roots`).
    pub extra_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// How long start-up keeps trying before it gives up
    /// ([`DEFAULT_CONNECT_BUDGET`] in the daemon).
    pub connect_budget: Duration,
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

/// One established connection (`DoH` or `DoQ`), type-erased.
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
///
/// A 4xx HTTP status is a complete response on a working stream: the
/// server refused this one request (Quad9 answers `403 DoH dropped
/// query` when it sheds load). Tearing the connection down for it, as
/// for a dead one, turns every shed query into a TLS handshake. A 5xx
/// stays fatal: a proxy pinned to a broken backend keeps failing on the
/// same connection, and a new one may reach a healthy backend.
/// hickory reports the status only as a message (its own TODO is an
/// explicit error type), so the message is matched.
fn classify_net_error(err: &hickory_resolver::net::NetError) -> SendError {
    use hickory_resolver::net::NetError;
    match err {
        NetError::Dns(_) | NetError::Proto(_) | NetError::QueryCaseMismatch => {
            SendError::Query(err.to_string())
        }
        NetError::Msg(msg)
            if msg
                .strip_prefix(HTTP_STATUS_ERROR_PREFIX)
                .is_some_and(|status| status.starts_with('4')) =>
        {
            SendError::Query(err.to_string())
        }
        _ => SendError::Fatal(err.to_string()),
    }
}

/// How hickory's `DoH` (h2) and `DoH3` clients word a non-2xx status.
const HTTP_STATUS_ERROR_PREFIX: &str = "http unsuccessful code: ";

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
    tls: &Arc<rustls::ClientConfig>,
) -> Result<Arc<dyn Transport>, Error> {
    let provider = TokioRuntimeProvider::new();
    match kind {
        UpstreamKind::Https { host, port, path } => {
            let addr = SocketAddr::new(resolved_ip, *port);
            let exchange = HttpsClientStream::builder(Arc::clone(tls), provider.clone())
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
            let stream = QuicClientStream::builder()
                .crypto_config((**tls).clone())
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

// ── Connection factory ──────────────────────────────────────────────

/// Builds a fresh connection to one upstream, on demand.
///
/// Every rebuild re-resolves the upstream hostname through the bootstrap
/// servers: a daemon that runs for months must follow upstream IP
/// changes.
struct NetworkFactory {
    kind: UpstreamKind,
    bootstrap_ips: Vec<IpAddr>,
    url: String,
    tls: Arc<rustls::ClientConfig>,
}

impl NetworkFactory {
    async fn build(&self) -> Result<Arc<dyn Transport>, Error> {
        let host = match &self.kind {
            UpstreamKind::Https { host, .. } | UpstreamKind::Quic { host, .. } => host,
        };
        let ip = bootstrap_resolve(host, &self.bootstrap_ips).await?;
        build_transport(&self.kind, ip, &self.tls).await
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
/// Longest probation after a successful build: if the fresh connection
/// fails before answering once, the next rebuild waits this long at
/// most (the upstream accepts connections it cannot serve). Short,
/// because it also bounds how long a recovered upstream waits, and the
/// race lets the other upstreams cover the gap.
const MAX_PROBATION: Duration = Duration::from_secs(5);
/// Start-up: how long `UpstreamPool::new` keeps trying before it gives
/// up and the process exits for systemd to restart it.
pub const DEFAULT_CONNECT_BUDGET: Duration = Duration::from_secs(30);
/// First wait between start-up connection rounds.
const INIT_RETRY_BACKOFF_START: Duration = Duration::from_millis(500);
/// Longest wait between start-up connection rounds.
const INIT_RETRY_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// The connection state of one upstream. Every transition happens under
/// one short `std::sync::Mutex` section; no lock is held across an
/// `.await`.
///
/// ```text
///            build ok                     first answer
///  Down ───────────────▶ Connected{probation} ──────▶ Connected{proven}
///   ▲  ▲   (Connecting)        │                            │
///   │  └─ build fails ◀────────┘ fails before answering     │ send fails
///   │     retry_at = now+backoff   retry_at = probation end │ (idle drop,
///   └───────────────────────────────────────────────────────┘  GOAWAY, hang)
///                         retry_at = now
/// ```
enum ConnState {
    /// No connection. A build may start once `retry_at` has passed.
    Down {
        retry_at: Instant,
        last_error: String,
    },
    /// A detached task is building a connection.
    Connecting,
    /// A connection is installed. `probation_until` is `Some` until it
    /// answers once: a failure before then waits out the probation
    /// before the next build.
    Connected {
        generation: u64,
        transport: Arc<dyn Transport>,
        probation_until: Option<Instant>,
    },
}

impl ConnState {
    fn name(&self) -> &'static str {
        match self {
            Self::Down { .. } => "down",
            Self::Connecting => "connecting",
            Self::Connected { .. } => "connected",
        }
    }
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
    /// `connected`, `connecting` or `down`. Informational: connections
    /// are rebuilt on demand, so a healthy upstream can read `down`
    /// between an idle drop and the next query. Judge health by
    /// `last_success_secs_ago`.
    pub state: &'static str,
    /// Whether a connection is installed (`state == "connected"`).
    pub connected: bool,
    /// Why the last connection attempt failed, while `down`.
    pub last_error: Option<String>,
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
/// upstream would never recover. Queries that find no connection wait
/// (bounded by their deadline) for the repair's outcome instead.
struct ReconnectingUpstream {
    factory: NetworkFactory,
    state: std::sync::Mutex<ConnState>,
    /// Builds so far; tags each connection so a failure on an old one
    /// cannot tear down its replacement.
    builds: AtomicU64,
    /// Wait before the next build after a failure; doubled per failure,
    /// reset by an answer.
    backoff_ms: AtomicU64,
    /// Bumped whenever a build concludes, so waiting queries re-check.
    repair_done: tokio::sync::watch::Sender<u64>,
    /// Bound on one connection build (bootstrap DNS + TCP/QUIC + TLS).
    build_timeout: Duration,
    queries: AtomicU64,
    failures: AtomicU64,
    reconnects: AtomicU64,
    consecutive_failures: AtomicU64,
    /// Unix seconds of the last successful answer; 0 means never.
    last_success_ts: AtomicI64,
}

impl ReconnectingUpstream {
    fn new(factory: NetworkFactory, initial: ConnState, build_timeout: Duration) -> Self {
        let builds = u64::from(matches!(initial, ConnState::Connected { .. }));
        Self {
            factory,
            state: std::sync::Mutex::new(initial),
            builds: AtomicU64::new(builds),
            backoff_ms: AtomicU64::new(duration_to_millis(MIN_RECONNECT_BACKOFF)),
            repair_done: tokio::sync::watch::Sender::new(0),
            build_timeout,
            queries: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            consecutive_failures: AtomicU64::new(0),
            last_success_ts: AtomicI64::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConnState> {
        self.state.lock().expect("upstream state poisoned")
    }

    /// `Down` and due → `Connecting`, and spawn the build. Anything
    /// else is left alone (a build is running, or the connection is up,
    /// or the retry time has not come).
    fn trigger_repair(self: &Arc<Self>) {
        {
            let mut state = self.lock();
            match &*state {
                ConnState::Down { retry_at, .. } if Instant::now() >= *retry_at => {
                    *state = ConnState::Connecting;
                }
                _ => return,
            }
        }
        let this = Arc::clone(self);
        tokio::spawn(async move { this.repair().await });
    }

    /// Build a connection and install it (`Connecting` → `Connected` or
    /// `Down`). Detached from every query.
    async fn repair(self: Arc<Self>) {
        // However this task ends — including being dropped at an await
        // during shutdown — it must not leave the upstream `Connecting`
        // forever, and waiters must wake.
        struct Concluded<'a>(&'a ReconnectingUpstream);
        impl Drop for Concluded<'_> {
            fn drop(&mut self) {
                if let Ok(mut state) = self.0.state.lock()
                    && matches!(*state, ConnState::Connecting)
                {
                    *state = ConnState::Down {
                        retry_at: Instant::now(),
                        last_error: "connection build abandoned".to_owned(),
                    };
                }
                self.0.repair_done.send_modify(|n| *n += 1);
            }
        }
        let _concluded = Concluded(&self);

        let built = match tokio::time::timeout(self.build_timeout, self.factory.build()).await {
            Ok(Ok(transport)) => Ok(transport),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err("connection build timed out".to_owned()),
        };
        let backoff = Duration::from_millis(self.backoff_ms.load(Ordering::Relaxed));
        match built {
            Ok(transport) => {
                let generation = self.builds.fetch_add(1, Ordering::Relaxed) + 1;
                *self.lock() = ConnState::Connected {
                    generation,
                    transport,
                    // A connection that never answers must not be
                    // rebuilt in a tight loop; a 30 s ladder from an
                    // outage must not delay a working one either.
                    probation_until: Some(Instant::now() + backoff.min(MAX_PROBATION)),
                };
                self.backoff_ms.store(
                    duration_to_millis((backoff * 2).min(MAX_PROBATION)),
                    Ordering::Relaxed,
                );
                self.reconnects.fetch_add(1, Ordering::Relaxed);
                tracing::info!(upstream = self.factory.label(), "upstream connected");
            }
            Err(err) => {
                tracing::warn!(
                    upstream = self.factory.label(),
                    %err,
                    retry_in_ms = duration_to_millis(backoff),
                    "upstream connection failed"
                );
                *self.lock() = ConnState::Down {
                    retry_at: Instant::now() + backoff,
                    last_error: err,
                };
                self.backoff_ms.store(
                    duration_to_millis((backoff * 2).min(MAX_RECONNECT_BACKOFF)),
                    Ordering::Relaxed,
                );
            }
        }
    }

    /// A usable connection, waiting (up to `deadline`) for a build.
    async fn acquire(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<(u64, Arc<dyn Transport>), String> {
        loop {
            // Subscribe before reading: a build that concludes between
            // the read and the wait then wakes us at once.
            let mut done = self.repair_done.subscribe();
            {
                let state = self.lock();
                match &*state {
                    ConnState::Connected {
                        generation,
                        transport,
                        ..
                    } => return Ok((*generation, Arc::clone(transport))),
                    ConnState::Down {
                        retry_at,
                        last_error,
                    } if Instant::now() < *retry_at => {
                        return Err(format!(
                            "{}: down, next connection attempt in {} ms (last error: {last_error})",
                            self.factory.label(),
                            duration_to_millis(retry_at.saturating_duration_since(Instant::now()))
                        ));
                    }
                    ConnState::Down { .. } | ConnState::Connecting => {}
                }
            }
            self.trigger_repair();
            if tokio::time::timeout_at(deadline, done.changed())
                .await
                .is_err()
            {
                return Err(format!(
                    "{}: timed out waiting for a connection",
                    self.factory.label()
                ));
            }
        }
    }

    /// The connection of `generation` failed: drop it (unless already
    /// replaced) and start a rebuild when one is due.
    fn invalidate(self: &Arc<Self>, generation: u64, why: &str) {
        {
            let mut state = self.lock();
            let ConnState::Connected {
                generation: current,
                probation_until,
                ..
            } = &*state
            else {
                return;
            };
            if *current != generation {
                return;
            }
            let retry_at = probation_until.unwrap_or_else(Instant::now);
            *state = ConnState::Down {
                retry_at,
                last_error: why.to_owned(),
            };
        }
        // The spawn happens before this returns, so even if the calling
        // query is cancelled right after, the repair runs.
        self.trigger_repair();
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
                Ok(Ok(response)) => return self.judge(response),
                // One bad answer does not condemn the connection.
                Ok(Err(SendError::Query(err))) => return Err(self.record_failure(err)),
                Ok(Err(SendError::Fatal(err))) => err,
                Err(_) => {
                    // A silent hang poisons every query multiplexed onto
                    // this connection: tear it down like a fatal error.
                    self.invalidate(generation, "query timed out on this connection");
                    return Err(self.record_failure(format!("{}: timed out", self.factory.label())));
                }
            };

        // A dead exchange fails every later send the same way: replace
        // it. Servers close idle connections routinely (Quad9 every
        // minute), so this is an event, not a warning, unless the
        // replacement fails too.
        tracing::info!(
            upstream = self.factory.label(),
            err = %first_err,
            "connection closed by the upstream; reconnecting"
        );
        self.invalidate(generation, &first_err);
        let (generation, fresh) = match self.acquire(deadline).await {
            Ok(pair) => pair,
            Err(err) => return Err(self.record_failure(format!("{first_err}; {err}"))),
        };
        match tokio::time::timeout_at(deadline, fresh.send_query(msg)).await {
            Ok(Ok(response)) => self
                .judge(response)
                .map_err(|err| format!("{first_err}; after reconnect: {err}")),
            Ok(Err(SendError::Query(err))) => {
                Err(self.record_failure(format!("{first_err}; after reconnect: {err}")))
            }
            Ok(Err(SendError::Fatal(err))) => {
                self.invalidate(generation, &err);
                Err(self.record_failure(format!("{first_err}; after reconnect: {err}")))
            }
            Err(_) => {
                self.invalidate(generation, "query timed out on this connection");
                Err(self.record_failure(format!(
                    "{first_err}; after reconnect: {}: timed out",
                    self.factory.label()
                )))
            }
        }
    }

    /// Accept or reject a transport-level success by its rcode.
    ///
    /// SERVFAIL/REFUSED/NOTIMP are unusable answers: they count as this
    /// upstream failing (the health counters drive an operator alert,
    /// and an upstream that "answers" only SERVFAIL is exactly what the
    /// alert is for). The connection stays: rcode is the server's
    /// verdict on the query, not on the transport.
    fn judge(&self, response: Message) -> Result<Message, String> {
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
        self.record_success();
        Ok(response)
    }

    /// An answer: the connection is proven, the backoff resets.
    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success_ts.store(unix_now(), Ordering::Relaxed);
        self.backoff_ms
            .store(duration_to_millis(MIN_RECONNECT_BACKOFF), Ordering::Relaxed);
        if let ConnState::Connected {
            probation_until, ..
        } = &mut *self.lock()
        {
            *probation_until = None;
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
        let (state, last_error) = {
            let state = self.lock();
            let err = match &*state {
                ConnState::Down { last_error, .. } => Some(last_error.clone()),
                _ => None,
            };
            (state.name(), err)
        };
        UpstreamHealth {
            url: self.factory.label().to_owned(),
            state,
            connected: state == "connected",
            last_error,
            last_success_secs_ago: (last > 0)
                .then(|| unix_now().saturating_sub(last).max(0).cast_unsigned()),
            queries: self.queries.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
        }
    }
}

/// One TLS client configuration for every upstream connection: the
/// public web PKI plus the operator's `[tls] extra_roots`.
fn build_rustls_client_config(
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<rustls::ClientConfig, Error> {
    // Ensure the ring CryptoProvider is installed process-wide (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut root_store: rustls::RootCertStore =
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    for cert in extra_roots {
        root_store
            .add(cert.clone())
            .map_err(|e| Error::Init(format!("tls.extra_roots: unusable certificate: {e}")))?;
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
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

/// Validate every URL and build its connection factory. Configuration
/// errors are fatal here: they are not transient.
fn factories(
    cfg: &UpstreamConfig,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<Vec<NetworkFactory>, Error> {
    let mut factories = Vec::with_capacity(cfg.urls.len());
    for raw_url in &cfg.urls {
        let kind = parse_upstream_url(raw_url)?;
        if cfg.bootstrap_ips.is_empty() {
            let host = match &kind {
                UpstreamKind::Https { host, .. } | UpstreamKind::Quic { host, .. } => host,
            };
            if host.parse::<IpAddr>().is_err() {
                return Err(Error::Init(format!(
                    "bootstrap_ips is empty and upstream '{raw_url}' requires resolution"
                )));
            }
        }
        factories.push(NetworkFactory {
            kind,
            bootstrap_ips: cfg.bootstrap_ips.clone(),
            url: raw_url.clone(),
            tls: Arc::clone(tls),
        });
    }
    Ok(factories)
}

impl UpstreamPool {
    /// Build a new pool from configuration.
    ///
    /// URLs are validated up front — a malformed/unsupported URL, or a
    /// hostname upstream with no bootstrap servers, is a *configuration*
    /// error and fails fast. Then every upstream connects **in
    /// parallel**, in rounds, until at least one is live or
    /// `connect_budget` is spent. Upstreams still down when the pool
    /// comes up join as `Down` and connect on demand — a single dead
    /// upstream can no longer keep the whole LAN's DNS server from
    /// starting, nor delay it by its timeout.
    ///
    /// If **no** upstream connects within the budget, `new` returns
    /// [`Error::Init`] and the process exits for systemd to restart it:
    /// a DNS server that "came up" with zero working upstreams would
    /// look healthy while resolving nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedUrl`] if a URL is malformed or uses an
    ///   unsupported scheme.
    /// - [`Error::Init`] on empty/invalid config, or if no upstream could
    ///   be connected within the budget.
    pub async fn new(cfg: &UpstreamConfig) -> Result<Self, Error> {
        if cfg.urls.is_empty() {
            return Err(Error::Init("no upstream URLs configured".into()));
        }
        if cfg.timeout_ms == 0 {
            return Err(Error::Init("timeout_ms must be > 0".into()));
        }

        let timeout = Duration::from_millis(cfg.timeout_ms);
        let tls = Arc::new(build_rustls_client_config(&cfg.extra_roots)?);

        let factories = factories(cfg, &tls)?;

        let deadline = Instant::now() + cfg.connect_budget;
        let mut built: Vec<Option<Arc<dyn Transport>>> = vec![None; factories.len()];
        let mut errors: Vec<String> = vec![String::new(); factories.len()];
        let mut backoff = INIT_RETRY_BACKOFF_START;
        loop {
            // One round: every still-down upstream at once, each bounded
            // by the per-attempt timeout and by the overall deadline.
            let round_deadline = (Instant::now() + timeout).min(deadline);
            let attempts = factories
                .iter()
                .enumerate()
                .filter(|(i, _)| built[*i].is_none())
                .map(|(i, factory)| async move {
                    let result =
                        match tokio::time::timeout_at(round_deadline, factory.build()).await {
                            Ok(Ok(transport)) => Ok(transport),
                            Ok(Err(err)) => Err(err.to_string()),
                            Err(_) => Err("connection timed out".to_owned()),
                        };
                    (i, result)
                });
            for (i, result) in futures::future::join_all(attempts).await {
                match result {
                    Ok(transport) => {
                        tracing::info!(
                            upstream = factories[i].label(),
                            "upstream connected at startup"
                        );
                        built[i] = Some(transport);
                    }
                    Err(err) => {
                        tracing::warn!(upstream = factories[i].label(), %err, "upstream not ready at startup");
                        errors[i] = format!("{}: {err}", factories[i].label());
                    }
                }
            }
            let live = built.iter().filter(|b| b.is_some()).count();
            if live > 0 {
                if live < factories.len() {
                    tracing::warn!(
                        live,
                        total = factories.len(),
                        "starting with some upstreams down; they connect on demand"
                    );
                }
                break;
            }
            if Instant::now() + backoff >= deadline {
                return Err(Error::Init(format!(
                    "no upstream could be connected within {:?}; giving up (the process \
                     will exit and systemd will restart it): {}",
                    cfg.connect_budget,
                    errors.join("; ")
                )));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(INIT_RETRY_BACKOFF_MAX);
        }

        let upstreams = factories
            .into_iter()
            .zip(built)
            .zip(errors)
            .map(|((factory, transport), error)| {
                let initial = match transport {
                    Some(transport) => ConnState::Connected {
                        generation: 1,
                        transport,
                        probation_until: None,
                    },
                    None => ConnState::Down {
                        retry_at: Instant::now(),
                        last_error: error,
                    },
                };
                Arc::new(ReconnectingUpstream::new(factory, initial, timeout))
            })
            .collect();
        Ok(Self {
            upstreams,
            timeout,
            resolved: AtomicU64::new(0),
            all_failed_total: AtomicU64::new(0),
            consecutive_all_failed: AtomicU64::new(0),
        })
    }

    /// Health counters for `status` and alerting.
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
        // We forward to recursive upstreams.
        outgoing.metadata.recursion_desired = true;
        let mut edns = outgoing.edns.clone().unwrap_or_default();
        edns.set_dnssec_ok(true);
        outgoing.set_edns(edns);

        let original_id = query.metadata.id;
        // Each send bounds every await inside it by this deadline, so a
        // hang is seen by the upstream's own failure handling (tear-down,
        // reconnect, health counters), not just by the pool.
        let deadline = Instant::now() + self.timeout;

        // Each leg runs as its own task, NOT as a racing future dropped
        // when a sibling wins: a cancelled leg would abandon its failure
        // handling, so a slower upstream whose connection died would
        // never notice as long as a faster one kept answering.
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
                    // Stamp the original query id (DoQ forces id 0).
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
}

// Required for the RuntimeProvider Handle::Spawn bound.
use hickory_resolver::net::runtime::Spawn;

// ── Tests ───────────────────────────────────────────────────────────
//
// Pool behaviour (races, reconnects, outages, health) is tested against
// real DoH/DoQ servers in `tests/upstream.rs`. Here: URL parsing and
// configuration rejection, which need no network.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_http_status_refusal_fails_the_query_not_the_connection() {
        use hickory_resolver::net::NetError;
        // The exact error hickory-net builds for Quad9's load shedding.
        let shed = NetError::from(format!(
            "http unsuccessful code: {}, message: {}",
            "403 Forbidden", "DoH dropped query"
        ));
        assert!(matches!(classify_net_error(&shed), SendError::Query(_)));
        // A server error may be this connection's backend: rebuild.
        let broken = NetError::from(format!(
            "http unsuccessful code: {}, message: {}",
            "502 Bad Gateway", ""
        ));
        assert!(matches!(classify_net_error(&broken), SendError::Fatal(_)));
        // A dead exchange still condemns the connection.
        assert!(matches!(
            classify_net_error(&NetError::Busy),
            SendError::Fatal(_)
        ));
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
            extra_roots: Vec::new(),
            connect_budget: DEFAULT_CONNECT_BUDGET,
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
            extra_roots: Vec::new(),
            connect_budget: DEFAULT_CONNECT_BUDGET,
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
            extra_roots: Vec::new(),
            connect_budget: DEFAULT_CONNECT_BUDGET,
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
            extra_roots: Vec::new(),
            connect_budget: DEFAULT_CONNECT_BUDGET,
        };
        let err = UpstreamPool::new(&cfg).await.unwrap_err();
        assert!(matches!(err, Error::Init(_)));
    }
}
