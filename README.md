# sumidero

A DNS blocker in Rust. It replaced AdGuard Home as the only resolver for the
author's household, running on a Jetson Orin Nano, and this repository is that
deployment — not a demo of one.

![sumidero status and stats](docs/img/status.png)

## Why another DNS blocker

AdGuard Home worked, but its control plane is a web UI backed by a YAML file it
rewrites at runtime. sumidero takes the opposite position:

- **The filesystem is the control plane.** One TOML config, read-only to the
  daemon. `SIGHUP` reloads it. There is no web UI and there never will be.
- **Every command speaks JSON on request.** `--json` on any subcommand emits a
  versioned schema, and exit codes carry meaning (`status` exits non-zero when
  the daemon is degraded). You can operate it from a script or an LLM agent
  without parsing prose.
- **Failures are loud.** A missing config key, an unloadable blocklist, an
  unbindable address — the daemon refuses to start rather than degrade
  silently. Reload keeps the old state and logs the failure; it never
  half-applies.

## What it does

- **List-based blocking** — the ABP-DNS rule subset (`||domain^`, exact
  matches, `@@` exceptions, wildcards) plus hosts-file lists. The production
  config loads 3.29 million rules across 6 lists (hagezi, oisd, AdGuard DNS
  filter, local rules).
- **Blocked answers are `NXDOMAIN`** with a synthetic SOA, so clients cache
  the negative answer instead of hammering the resolver.
- **Encrypted upstreams only** — DoH and DoQ. Every query races all configured
  upstreams and the first usable answer wins. Dead connections are detected
  (including ones that hang silently rather than fail), torn down, and rebuilt
  in the background with rate-limited backoff. An upstream that only answers
  SERVFAIL is counted as failing, not healthy.
- **Caching with serve-stale** — an LRU cache bounded both by entry count and
  by an estimated 64 MiB of memory, because the process runs under a hard
  `MemoryMax`. Expired entries are served for up to 30 minutes while a
  background refresh runs.
- **Load discipline** — concurrent misses for the same name share one upstream
  lookup, and queries past a hard in-flight cap get an immediate SERVFAIL
  instead of queueing unbounded work.
- **Safe-search enforcement** — CNAME rewrites to the engines' enforced
  endpoints.
- **SQLite query log and stats**, with retention sweeps, written off the hot
  path (the log can drop entries under pressure and tells you when it did).
- **Shadow mode** — run against your incumbent resolver, mirror real traffic
  to both, and get a divergence report. This is how sumidero was validated on
  the household's live query stream before it took port 53.
- **A hardened systemd unit** — `DynamicUser`, `ProtectSystem=strict`, syscall
  filtering, `CAP_NET_BIND_SERVICE` only. `systemd-analyze security` scores it
  1.6 (OK).

![query log](docs/img/log.png)

## Numbers

Everything below was measured on the deployment target — a Jetson Orin Nano
8GB (6 cores, aarch64) — with the real 3.29M-rule configuration. Commands and
context for each figure are in [PERF.md](PERF.md).

| what | measured |
|---|---:|
| steady RSS at 3.29M rules | 207 MB |
| RSS peak during a SIGHUP reload (two engines coexist) | 429 MB |
| startup to serving, full rule set | ~6 s |
| cache hits, 6 threads contending | 740k lookups/s |
| local burst, 64 clients, mixed cached/blocked | 7.4k qps, 0 dropped |

The burst figure is a loopback test and says nothing about WAN latency; the
resolver's answer latency is dominated by upstream RTT on misses, as it is for
any forwarder. No load-generator QPS ceiling has been measured yet, and
PERF.md says so explicitly.

One number that matters more than the benchmarks: during shadow validation an
earlier build SERVFAILed for seven consecutive hours because a dead upstream
connection was reused forever. That failure mode now has a reproducing test in
the suite — as do the nine further reliability defects a later review
confirmed (hung connections, abandoned reconnects, lying health counters,
unbounded admission, and more). The work is documented in PERF.md with
before/after measurements.

## Install

Linux with systemd. Build from source (Rust 1.94+):

```sh
cargo build --release
sudo install -m 0755 target/release/sumidero /usr/local/bin/sumidero
sudo install -d -m 0755 /etc/sumidero
sudo install -m 0644 packaging/sumidero.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Write a config — `sumidero init` generates a commented starter, or
`sumidero migrate` converts an existing `AdGuardHome.yaml` and warns about
every setting it cannot carry over:

```sh
sudo sumidero --config /etc/sumidero/config.toml init
sudo sumidero --config /etc/sumidero/config.toml check   # validates config + lists
sudo systemctl enable --now sumidero
```

The full walkthrough — including the `DynamicUser` traps, IPv6 bind semantics,
and verification steps — is in [docs/INSTALL.md](docs/INSTALL.md). If you are
replacing a resolver that currently owns port 53, the tested runbook with a
sub-minute rollback path is [docs/CUTOVER.md](docs/CUTOVER.md).

A minimal config:

```toml
[server]
bind = ["0.0.0.0:53", "[::]:53"]
allow = ["192.168.0.0/24", "127.0.0.1/32", "::1/128"]

[filtering]
list_dir = "/var/lib/sumidero/lists"

[[filtering.lists]]
name = "hagezi-pro"
url = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"

[upstreams]
servers = ["https://dns.google/dns-query", "quic://dns.adguard-dns.com"]
bootstrap = ["1.1.1.1", "9.9.9.9"]
timeout_ms = 5000

[database]
path = "/var/lib/sumidero/sumidero.sqlite"
```

## Day-to-day

```
sumidero status    # daemon health, per-upstream counters; exit code reflects it
sumidero log       # recent queries: who asked what, verdict, source, rcode
sumidero stats     # aggregates over a window
sumidero explain   # why a given domain is (not) blocked, and by which rule
sumidero check     # validate config + lists without touching the daemon
sumidero reload    # validate, then SIGHUP the daemon
sumidero shadow    # divergence report against a reference resolver
```

![blocked answer](docs/img/blocked.png)

## Workspace

| crate | purpose |
|---|---|
| `crates/filter` | pure filter engine (parser + matcher), no I/O |
| `crates/core` | daemon library: server, cache, upstream pool, SQLite |
| `crates/cli` | the `sumidero` binary |

The design record, including the decisions above and the ones that were
rejected, is in [DESIGN.md](DESIGN.md).

## License

MIT
