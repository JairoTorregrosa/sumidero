//! The real daemon (`sumidero serve`, the shipped binary) against real
//! local servers: a `DoH` upstream and an HTTPS list host from
//! `sumidero-testkit`. Start-up, reload, failed reload, restart from
//! stored copies, shutdown: what the household and the operator see.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use serde_json::Value;
use sumidero_testkit::{DnsUpstream, ListHost, ListMode, Pki, free_port, query_udp};

struct World {
    _pki: Arc<Pki>,
    _upstream: DnsUpstream,
    host: ListHost,
    dir: tempfile::TempDir,
    config: PathBuf,
    dns: SocketAddr,
    upstream_url: String,
    ca: PathBuf,
}

impl World {
    async fn new() -> Self {
        let pki = Arc::new(Pki::new());
        let upstream = DnsUpstream::start(Arc::clone(&pki)).await;
        upstream.add_a("lists.test", &[Ipv4Addr::LOCALHOST]);
        let host = ListHost::start(&pki).await;
        host.put("remote.txt", "||blocked.test^\n");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("user.txt"), "||mask.icloud.test^\n").unwrap();
        let dns: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let world = Self {
            upstream_url: upstream.doh_url(),
            ca: pki.ca_pem_path().to_path_buf(),
            _pki: pki,
            _upstream: upstream,
            host,
            config: dir.path().join("config.toml"),
            dir,
            dns,
        };
        world.write_config(&[]);
        world
    }

    /// Config with the remote and user lists plus `extra` (name, url).
    fn write_config(&self, extra: &[(&str, String)]) {
        let d = self.dir.path();
        let mut lists = format!(
            "[[filtering.lists]]\nname = \"remote\"\nurl = \"{}\"\n\n\
             [[filtering.lists]]\nname = \"user\"\npath = \"{}\"\n",
            self.host.named_url("remote.txt"),
            d.join("user.txt").display(),
        );
        for (name, url) in extra {
            let _ = write!(
                lists,
                "\n[[filtering.lists]]\nname = \"{name}\"\nurl = \"{url}\"\n"
            );
        }
        std::fs::write(
            &self.config,
            format!(
                "[server]\nbind = [\"{dns}\"]\nallow = [\"127.0.0.0/8\"]\n\n\
                 [filtering]\nlist_dir = \"{list_dir}\"\n\n{lists}\n\
                 [upstreams]\nservers = [\"{up}\"]\nbootstrap = [\"127.0.0.1\"]\ntimeout_ms = 2000\n\n\
                 [database]\npath = \"{db}\"\n\n\
                 [tls]\nextra_roots = [\"{ca}\"]\n",
                dns = self.dns,
                list_dir = d.join("lists").display(),
                up = self.upstream_url,
                db = d.join("sumidero.sqlite").display(),
                ca = self.ca.display(),
            ),
        )
        .unwrap();
    }

    fn cli(&self, args: &[&str]) -> (Option<i32>, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_sumidero"))
            .arg("--config")
            .arg(&self.config)
            .arg("--json")
            .args(args)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{args:?}: not JSON ({e}): {stdout}"));
        (out.status.code(), v)
    }

    fn start(&self) -> Daemon {
        let log = std::fs::File::create(self.dir.path().join("daemon.log")).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_sumidero"))
            .arg("--config")
            .arg(&self.config)
            .arg("serve")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        Daemon {
            child,
            log: self.dir.path().join("daemon.log"),
        }
    }

    async fn rcode(&self, name: &str) -> ResponseCode {
        query_udp(self.dns, name, RecordType::A).await.rcode
    }

    /// Wait until the daemon answers on its socket.
    async fn wait_serving(&self, daemon: &mut Daemon, within: Duration) -> Duration {
        let started = Instant::now();
        loop {
            if let Some(status) = daemon.child.try_wait().unwrap() {
                panic!("daemon exited {status}: {}", daemon.log_text());
            }
            if tokio::time::timeout(
                Duration::from_millis(300),
                query_udp(self.dns, "blocked.test", RecordType::A),
            )
            .await
            .is_ok()
            {
                return started.elapsed();
            }
            assert!(
                started.elapsed() < within,
                "not serving after {within:?}: {}",
                daemon.log_text()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// SIGTERM and wait; returns how long the exit took.
    fn stop(mut self) -> Duration {
        let pid = nix::unistd::Pid::from_raw(i32::try_from(self.child.id()).unwrap());
        let started = Instant::now();
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).unwrap();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "exit {status}: {}", self.log_text());
                return started.elapsed();
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "no exit: {}",
                self.log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn reasons(status: &Value) -> Vec<String> {
    status["degraded_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["reason"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_starts_reloads_refuses_bad_reloads_and_reports_each_step() {
    let w = World::new().await;
    let mut d = w.start();
    w.wait_serving(&mut d, Duration::from_secs(30)).await;

    // First start: lists downloaded through the upstream, then served.
    assert_eq!(w.rcode("blocked.test").await, ResponseCode::NXDomain);
    assert_eq!(w.rcode("mask.icloud.test").await, ResponseCode::NXDomain);
    assert_eq!(w.rcode("fine.test").await, ResponseCode::NoError);
    let (code, status) = w.cli(&["status"]);
    assert_eq!(code, Some(0), "{status}");
    assert_eq!(status["lists"][0]["origin"], "downloaded", "{status}");
    assert_eq!(status["lists"][1]["origin"], "local_file");

    // The list changes upstream; reload picks it up and says so.
    w.host.put("remote.txt", "||blocked.test^\n||newly.test^\n");
    let (code, out) = w.cli(&["reload"]);
    assert_eq!(code, Some(0), "{out}");
    assert_eq!(out["outcome"]["ok"], true);
    assert_eq!(w.rcode("newly.test").await, ResponseCode::NXDomain);

    // A new list that cannot be downloaded: the reload fails, the daemon
    // keeps filtering with what it had, and status says why.
    w.host.set_mode(ListMode::Status(500));
    w.write_config(&[("extra", w.host.named_url("extra.txt"))]);
    let (code, out) = w.cli(&["reload"]);
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(out["outcome"]["ok"], false);
    assert!(
        out["outcome"]["error"].as_str().unwrap().contains("extra"),
        "{out}"
    );
    assert_eq!(w.rcode("newly.test").await, ResponseCode::NXDomain);
    let (code, status) = w.cli(&["status"]);
    assert_eq!(code, Some(7));
    assert!(
        reasons(&status).contains(&"reload_failed".to_owned()),
        "{status}"
    );

    // Back to a good config: healthy again.
    w.host.set_mode(ListMode::Serve);
    w.write_config(&[]);
    let (code, out) = w.cli(&["reload"]);
    assert_eq!(code, Some(0), "{out}");
    let (code, status) = w.cli(&["status"]);
    assert_eq!(code, Some(0), "{status}");

    // A config that does not parse never reaches the daemon.
    std::fs::write(&w.config, "[server\n").unwrap();
    let (code, _) = w.cli(&["reload"]);
    assert_eq!(code, Some(1));
    assert_eq!(w.rcode("blocked.test").await, ResponseCode::NXDomain);

    assert!(d.stop() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_serves_from_stored_lists_while_the_list_host_hangs() {
    let w = World::new().await;
    let mut d = w.start();
    w.wait_serving(&mut d, Duration::from_secs(30)).await;
    d.stop();

    // The list host now accepts connections and never answers: a start
    // that waited for it would not serve for minutes.
    w.host.set_mode(ListMode::Stall);
    let mut d = w.start();
    let took = w.wait_serving(&mut d, Duration::from_secs(10)).await;
    assert!(took < Duration::from_secs(5), "served after {took:?}");
    assert_eq!(w.rcode("blocked.test").await, ResponseCode::NXDomain);
    let (_, status) = w.cli(&["status"]);
    assert_eq!(status["lists"][0]["origin"], "stored_offline", "{status}");

    // The refresher is stuck on the hung host; shutdown does not wait for it.
    assert!(d.stop() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signal_with_a_broken_config_is_reported_not_applied() {
    let w = World::new().await;
    let mut d = w.start();
    w.wait_serving(&mut d, Duration::from_secs(30)).await;
    std::fs::write(&w.config, "[server\n").unwrap();
    let pid = nix::unistd::Pid::from_raw(i32::try_from(d.child.id()).unwrap());
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGHUP).unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(w.rcode("blocked.test").await, ResponseCode::NXDomain);

    // `status` reads the config too; give it a good one to find the db.
    w.write_config(&[]);
    let (code, status) = w.cli(&["status"]);
    assert_eq!(code, Some(7), "{status}");
    assert_eq!(status["last_reload"]["trigger"], "signal");
    assert!(
        status["last_reload"]["error"]
            .as_str()
            .unwrap()
            .starts_with("config:"),
        "{status}"
    );
    d.stop();
}
