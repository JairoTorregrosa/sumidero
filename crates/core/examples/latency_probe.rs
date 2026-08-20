//! DNS latency probe: compare sumidero against its upstreams, queried
//! the same way sumidero queries them.
//!
//! Browsers resolve in bursts — A + AAAA + HTTPS(65) per name, a dozen
//! names per page — so this probe sends browsing-shaped bursts and
//! reports the answer-latency distribution per target. Targets:
//!
//! - `pool:URL[,URL...]` — a [`sumidero_core::upstream::UpstreamPool`]
//!   over the given DoH/DoQ URLs (one URL measures a single upstream
//!   directly; several race them exactly as the daemon does).
//! - `udp:ADDR` — plain-DNS queries to a resolver socket (a throwaway
//!   sumidero instance, or any other resolver).
//!
//! Names are read from a file (one per line, `#` comments allowed),
//! deterministically shuffled, and partitioned round-robin across
//! targets so no target's queries warm a provider edge cache for
//! another target's identical name. Keep private household names out of
//! committed name files; pass them by path from outside the repo.
//!
//! ```sh
//! cargo run --release -p sumidero-core --example latency_probe -- \
//!   --names names.txt --seed 1 \
//!   'pool:https://dns.google/dns-query' \
//!   'pool:https://dns.google/dns-query,https://dns.quad9.net/dns-query' \
//!   udp:127.0.0.1:15353
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use sumidero_core::upstream::{UpstreamConfig, UpstreamPool};

/// Per-upstream timeout, matching the production config.
const TIMEOUT_MS: u64 = 5000;
/// Default concurrent name-bursts per target: a page load resolves
/// several names at once, but a household does not sustain hundreds in
/// flight. Raise with `--concurrency` for overload shapes (a same-name
/// stampede is a names file repeating one name, at high concurrency).
const CONCURRENT_BURSTS: usize = 4;
/// The record types a browser asks for per name.
const QTYPES: [RecordType; 3] = [RecordType::A, RecordType::AAAA, RecordType::HTTPS];

/// One measured query.
struct Sample {
    qtype: RecordType,
    elapsed: Duration,
    /// `None` = transport failure or timeout; `Some(rcode)` otherwise.
    rcode: Option<u16>,
}

/// Anything the probe can send a query to.
enum Target {
    Pool(Arc<UpstreamPool>),
    Udp(SocketAddr),
}

impl Target {
    async fn query(&self, name: &Name, qtype: RecordType) -> Sample {
        let mut msg = Message::new(fastrand_id(name, qtype), MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(name.clone(), qtype));
        msg.metadata.recursion_desired = true;

        let started = Instant::now();
        let rcode = match self {
            Self::Pool(pool) => pool
                .resolve(&msg)
                .await
                .ok()
                .map(|resp| u16::from(resp.metadata.response_code)),
            Self::Udp(addr) => udp_query(*addr, &msg).await,
        };
        Sample {
            qtype,
            elapsed: started.elapsed(),
            rcode,
        }
    }
}

/// Stable DNS message id per (name, qtype) — collisions are harmless
/// because every UDP query gets its own connected socket.
fn fastrand_id(name: &Name, qtype: RecordType) -> u16 {
    let mut h: u32 = u32::from(u16::from(qtype));
    for b in name.to_ascii().bytes() {
        h = h.wrapping_mul(31).wrapping_add(u32::from(b));
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "deliberate truncation to the 16-bit id space"
    )]
    let id = h as u16;
    id
}

/// One plain-DNS query over a fresh UDP socket (how a LAN client asks).
async fn udp_query(addr: SocketAddr, msg: &Message) -> Option<u16> {
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("static addr")
    } else {
        "0.0.0.0:0".parse().expect("static addr")
    };
    let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
    // Connected socket: rejects datagrams from other sources and turns
    // ICMP port-unreachable into a fast error instead of a 5s timeout.
    sock.connect(addr).await.ok()?;
    sock.send(&msg.to_vec().ok()?).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let recv = tokio::time::timeout(Duration::from_millis(TIMEOUT_MS), sock.recv(&mut buf));
    let n = recv.await.ok()?.ok()?;
    let resp = Message::from_vec(&buf[..n]).ok()?;
    (resp.metadata.id == msg.metadata.id).then(|| u16::from(resp.metadata.response_code))
}

/// Deterministic xorshift shuffle — reproducible runs without a rand dep.
fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15; // nonzero for any seed
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        // allow, not expect: CI runs a newer clippy whose cast lints may
        // stop firing here, and -D warnings would then fail the expect.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "modulo bounds the value to a valid index"
        )]
        let j = (state % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    // allow, not expect: CI runs a newer clippy whose cast lints may
    // stop firing here, and -D warnings would then fail the expect.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        reason = "index arithmetic on small in-memory sample counts"
    )]
    // Nearest-rank: ceil(len * p) - 1.
    let idx = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

fn print_stats(label: &str, samples: &[Sample]) {
    let mut ok: Vec<Duration> = samples
        .iter()
        .filter(|s| s.rcode.is_some())
        .map(|s| s.elapsed)
        .collect();
    ok.sort_unstable();
    let failed = samples.len() - ok.len();
    println!("\n== {label}: {} queries, {failed} failed", samples.len());
    println!(
        "   answered  p50={:>8.1?} p90={:>8.1?} p95={:>8.1?} p99={:>8.1?} p999={:>8.1?} max={:>8.1?}",
        percentile(&ok, 0.50),
        percentile(&ok, 0.90),
        percentile(&ok, 0.95),
        percentile(&ok, 0.99),
        percentile(&ok, 0.999),
        ok.last().copied().unwrap_or_default(),
    );
    for qtype in QTYPES {
        let mut v: Vec<Duration> = samples
            .iter()
            .filter(|s| s.qtype == qtype && s.rcode.is_some())
            .map(|s| s.elapsed)
            .collect();
        v.sort_unstable();
        println!(
            "   {qtype:<5} n={:>5} p50={:>8.1?} p90={:>8.1?} p99={:>8.1?}",
            v.len(),
            percentile(&v, 0.50),
            percentile(&v, 0.90),
            percentile(&v, 0.99),
        );
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: latency_probe --names FILE [--seed N] [--limit N] [--concurrency N] TARGET...\n\
         TARGET: pool:URL[,URL...] | udp:HOST:PORT"
    );
    std::process::exit(2);
}

/// Build a target from its CLI spec.
async fn build_target(spec: &str) -> Target {
    if let Some(urls) = spec.strip_prefix("pool:") {
        let cfg = UpstreamConfig {
            urls: urls.split(',').map(str::to_owned).collect(),
            bootstrap_ips: vec![
                "8.8.8.8".parse().expect("static IP"),
                "9.9.9.9".parse().expect("static IP"),
            ],
            timeout_ms: TIMEOUT_MS,
        };
        let pool = UpstreamPool::new(&cfg)
            .await
            .unwrap_or_else(|e| panic!("{spec}: {e}"));
        Target::Pool(Arc::new(pool))
    } else if let Some(addr) = spec.strip_prefix("udp:") {
        Target::Udp(addr.parse().unwrap_or_else(|e| panic!("{spec}: {e}")))
    } else {
        usage()
    }
}

#[tokio::main]
async fn main() {
    let mut names_path: Option<String> = None;
    let mut seed: u64 = 1;
    let mut limit: usize = usize::MAX;
    let mut concurrency: usize = CONCURRENT_BURSTS;
    let mut target_specs: Vec<String> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--names" => names_path = args.next(),
            "--seed" => {
                seed = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--limit" => {
                limit = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--concurrency" => {
                concurrency = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            _ if arg.starts_with("pool:") || arg.starts_with("udp:") => target_specs.push(arg),
            _ => usage(),
        }
    }
    let Some(names_path) = names_path else {
        usage()
    };
    if target_specs.is_empty() {
        usage();
    }

    let raw = std::fs::read_to_string(&names_path)
        .unwrap_or_else(|e| panic!("cannot read {names_path}: {e}"));
    let candidates: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let mut names: Vec<Name> = candidates
        .iter()
        .filter_map(|l| Name::from_ascii(format!("{l}.")).ok())
        .collect();
    let dropped = candidates.len() - names.len();
    if dropped > 0 {
        eprintln!(
            "warning: {dropped} lines in {names_path} are not valid ASCII DNS names (raw-Unicode IDN? use punycode) and were skipped"
        );
    }
    shuffle(&mut names, seed);
    names.truncate(limit);

    let mut targets: Vec<(String, Target)> = Vec::new();
    for spec in &target_specs {
        targets.push((spec.clone(), build_target(spec).await));
    }

    // Disjoint name sets per target: round-robin over the shuffled list,
    // so the populations are statistically alike but no name repeats
    // across targets (a repeat would warm a provider's edge cache and
    // flatter whoever queries it second).
    let per_target: Vec<Vec<Name>> = (0..targets.len())
        .map(|t| {
            names
                .iter()
                .skip(t)
                .step_by(targets.len())
                .cloned()
                .collect()
        })
        .collect();

    println!(
        "{} names from {names_path}, seed {seed}: {} per target",
        names.len(),
        per_target.first().map_or(0, Vec::len),
    );

    for ((label, target), target_names) in targets.into_iter().zip(per_target) {
        let target = Arc::new(target);
        let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut tasks = Vec::new();
        let run_started = Instant::now();
        for name in target_names {
            let target = Arc::clone(&target);
            let permit = Arc::clone(&sem).acquire_owned().await.expect("semaphore");
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                // A browser burst: all three qtypes in flight at once.
                let (a, aaaa, https) = tokio::join!(
                    target.query(&name, QTYPES[0]),
                    target.query(&name, QTYPES[1]),
                    target.query(&name, QTYPES[2]),
                );
                [a, aaaa, https]
            }));
        }
        let mut samples = Vec::new();
        for task in tasks {
            samples.extend(task.await.expect("probe task panicked"));
        }
        print_stats(&label, &samples);
        println!("   wall time {:.1?}", run_started.elapsed());
    }
}
