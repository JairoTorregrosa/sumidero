//! Open-loop UDP load generator for a DNS server.
//!
//! Sends at a fixed rate whatever the server does (so a slow server
//! shows up as latency and loss, not as a politely slower client), from
//! many sockets, and prints one JSON line an agent can compare.
//!
//! ```text
//! cargo run --release -p sumidero-core --example loadgen -- \
//!     --server 127.0.0.1:53 --qps 2000 --secs 20 --mode hit
//! ```
//!
//! Modes:
//! - `hit`: 500 popular names, asked over and over (cache hits);
//! - `blocked`: names from `--names FILE` (one per line), expected NXDOMAIN;
//! - `miss`: a fresh random name under `--zone` every query (upstream work);
//! - `mix`: 80% hit, 10% blocked, 10% miss.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "display-only statistics"
)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const SOCKETS: usize = 32;
const LOSS_AFTER: Duration = Duration::from_secs(2);

const POPULAR: &[&str] = &[
    "google.com",
    "www.google.com",
    "youtube.com",
    "i.ytimg.com",
    "facebook.com",
    "graph.facebook.com",
    "instagram.com",
    "whatsapp.net",
    "apple.com",
    "icloud.com",
    "microsoft.com",
    "login.microsoftonline.com",
    "amazon.com",
    "netflix.com",
    "spotify.com",
    "github.com",
    "api.github.com",
    "cloudflare.com",
    "wikipedia.org",
    "tiktok.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "mercadolibre.com.co",
];

struct Args {
    server: SocketAddr,
    qps: u64,
    secs: u64,
    mode: String,
    names: Vec<String>,
    zone: String,
}

fn args() -> Args {
    let mut a = Args {
        server: "127.0.0.1:53".parse().unwrap(),
        qps: 1000,
        secs: 10,
        mode: "hit".into(),
        names: Vec::new(),
        zone: "stress.invalid".into(),
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let v = argv.get(i + 1).cloned().unwrap_or_default();
        match argv[i].as_str() {
            "--server" => a.server = v.parse().expect("--server ip:port"),
            "--qps" => a.qps = v.parse().expect("--qps n"),
            "--secs" => a.secs = v.parse().expect("--secs n"),
            "--mode" => a.mode = v,
            "--zone" => a.zone = v,
            "--names" => {
                a.names = std::fs::read_to_string(&v)
                    .expect("--names file")
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            other => panic!("unknown argument {other}"),
        }
        i += 2;
    }
    a
}

fn popular(i: u64) -> String {
    // 500 names: the real popular ones plus numbered subdomains of them.
    let base = POPULAR[(i % POPULAR.len() as u64) as usize];
    let n = (i / POPULAR.len() as u64) % 21;
    if n == 0 {
        base.to_owned()
    } else {
        format!("s{n}.{base}")
    }
}

fn pick(a: &Args, seq: u64, rng: &mut u64) -> String {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    let mode = match a.mode.as_str() {
        "mix" => match *rng % 10 {
            0 => "blocked",
            1 => "miss",
            _ => "hit",
        },
        m => m,
    };
    match mode {
        "hit" => popular(*rng % 500),
        "blocked" => {
            assert!(!a.names.is_empty(), "--mode blocked needs --names");
            a.names[(*rng % a.names.len() as u64) as usize].clone()
        }
        "miss" => format!("q{seq}-{:x}.{}", *rng & 0xffff_ffff, a.zone),
        other => panic!("unknown mode {other}"),
    }
}

#[derive(Default)]
struct Stats {
    latencies_us: Vec<u64>,
    rcodes: BTreeMap<String, u64>,
}

#[tokio::main]
async fn main() {
    let a = Arc::new(args());
    let stats = Arc::new(Mutex::new(Stats::default()));
    let sent = Arc::new(AtomicU64::new(0));
    let mut sockets = Vec::new();
    let mut pending: Vec<Arc<Mutex<HashMap<u16, Instant>>>> = Vec::new();
    for _ in 0..SOCKETS {
        let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        sock.connect(a.server).await.unwrap();
        let map: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let (rs, rm, st) = (Arc::clone(&sock), Arc::clone(&map), Arc::clone(&stats));
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok(n) = rs.recv(&mut buf).await else {
                    return;
                };
                let Ok(msg) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let Some(t0) = rm.lock().await.remove(&msg.metadata.id) else {
                    continue;
                };
                let mut s = st.lock().await;
                s.latencies_us.push(t0.elapsed().as_micros() as u64);
                *s.rcodes
                    .entry(msg.metadata.response_code.to_string())
                    .or_default() += 1;
            }
        });
        sockets.push(sock);
        pending.push(map);
    }

    // Open loop: every millisecond, send what the schedule says is due.
    let started = Instant::now();
    let total = a.qps * a.secs;
    let mut seq = 0u64;
    // Fresh names every run: a rerun must not find the last run's misses
    // in the cache.
    let mut rng = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0x9e37_79b9_7f4a_7c15, |d| d.as_nanos() as u64)
        | 1;
    let mut tick = tokio::time::interval(Duration::from_millis(1));
    while seq < total {
        tick.tick().await;
        let due = ((started.elapsed().as_secs_f64() * a.qps as f64) as u64).min(total);
        while seq < due {
            let k = (seq as usize) % SOCKETS;
            let id = ((seq / SOCKETS as u64) & 0xffff) as u16;
            let name = pick(&a, seq, &mut rng);
            let mut q = Message::new(id, MessageType::Query, OpCode::Query);
            q.add_query(Query::query(
                Name::from_ascii(format!("{name}.")).unwrap(),
                RecordType::A,
            ));
            q.metadata.recursion_desired = true;
            pending[k].lock().await.insert(id, Instant::now());
            let _ = sockets[k].send(&q.to_vec().unwrap()).await;
            sent.fetch_add(1, Ordering::Relaxed);
            seq += 1;
        }
    }
    let send_secs = started.elapsed().as_secs_f64();
    tokio::time::sleep(LOSS_AFTER).await;

    let s = stats.lock().await;
    let mut lat = s.latencies_us.clone();
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        if lat.is_empty() {
            return f64::NAN;
        }
        lat[((lat.len() as f64 - 1.0) * p).round() as usize] as f64 / 1000.0
    };
    let sent = sent.load(Ordering::Relaxed);
    let answered = lat.len() as u64;
    println!(
        "{{\"server\":\"{}\",\"mode\":\"{}\",\"target_qps\":{},\"achieved_send_qps\":{:.0},\"sent\":{sent},\
         \"answered\":{answered},\"lost\":{},\"loss_pct\":{:.3},\"p50_ms\":{:.3},\"p90_ms\":{:.3},\
         \"p99_ms\":{:.3},\"p999_ms\":{:.3},\"max_ms\":{:.3},\"rcodes\":{}}}",
        a.server,
        a.mode,
        a.qps,
        sent as f64 / send_secs,
        sent - answered,
        (sent - answered) as f64 * 100.0 / sent.max(1) as f64,
        pct(0.50),
        pct(0.90),
        pct(0.99),
        pct(0.999),
        pct(1.0),
        serde_json::to_string(&s.rcodes).unwrap(),
    );
}
