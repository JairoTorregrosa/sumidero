# sumidero performance and reliability measurements

Every number here was measured on the deploy target — Jetson Orin Nano
8GB, aarch64, 6 cores, MAXN_SUPER, Ubuntu 22.04 — with the command
recorded next to it. Filter-engine microbenchmarks live in
`crates/filter/BENCHMARKS.md`; this file covers the daemon as deployed.

Rule set throughout: the user's real configuration, **3,289,168 rules
across 6 lists** (hagezi pro + tif, oisd big + nsfw, adguard dns filter,
user rules).

## Upstream connection lifetime (2026-08-20)

The perf handoff asked whether hickory 0.26 reuses DoH/DoQ connections
across queries, on the theory that a handshake per query would be the
biggest available win. **It reuses them — that was never the problem.**
`UpstreamPool` built one `DnsExchange` per upstream at startup and held
it for the process lifetime: exactly one handshake per upstream, ever.

The bug was the opposite. A `DnsExchange` is a handle onto a background
task; when the task exits, every later send fails with `NetError::Busy`
("resource too busy") forever, and nothing rebuilt it. Measured on the
live shadow:

| window (UTC, 2026-08-20) | upstream successes | `failed` rows |
|---|---:|---:|
| 02:00–04:00 (healthy) | 817 | 0 |
| 05:00 (transition) | 52 | 130 |
| 06:00–12:00 | **0** | **2,439** |

Seven consecutive hours of SERVFAIL, from a daemon whose heartbeat was
fresh the whole time. `shadow report` at the end of it: 2,529
`unexpected` divergences, 2,503 of them us-SERVFAIL / AdGuard-NOERROR.

After the reconnect fix (commit `Reconnect dead DoH/DoQ upstreams`),
same box, same lists, real replayed house traffic:

```sh
sudo journalctl -u sumidero-shadow.service --since <restart> | grep -c "all upstreams failed"
```

- `all upstreams failed`: **0**
- `upstream reconnected`: ~5 per 5 minutes, **all of them Quad9**

Quad9's DoH connection breaks continuously — `stream closed because of a
broken pipe`, `receiver was canceled` — roughly every 30–60 s. Google's
DoH and AdGuard's DoQ have not dropped a connection since deploy. That
is worth knowing before any upstream health-scoring work: the reconnect
cost is real but confined to one upstream, and the raced-upstream design
hides it entirely (0 client-visible failures).

Open follow-up: whether Quad9's churn is their idle policy or something
we do wrong with h2 GOAWAY. Not urgent — it costs one reconnect, not one
answer.

## Memory: steady state and reload peak (2026-08-20)

```sh
systemctl show sumidero-shadow.service -p MemoryCurrent --value
ps -o rss= -p $(systemctl show sumidero-shadow.service -p MainPID --value)
```

| phase | process RSS | cgroup `MemoryCurrent` |
|---|---:|---:|
| steady, ~15 min after load | **208 MB** | 256 MB |
| peak during startup list load | — | **466 MB** |

The cgroup figure runs higher than process RSS because it counts page
cache for the list files. The peak matters for `MemoryMax`: the current
shadow unit sets 768 MB, which clears the measured 466 MB peak with 65%
headroom. AdGuard on the same lists: ~650 MB steady.

### Reload peak (SIGHUP), the number `MemoryMax` is sized from

During a SIGHUP reload the old and new engines coexist, which is the
true high-water mark for a long-running daemon — the daily list refresh
takes the same path. Sampled every 0.5 s across a reload of the full
3.29M-rule set:

```sh
sudo kill -HUP $(systemctl show sumidero-shadow.service -p MainPID --value)
# sampling MemoryCurrent and /proc/$PID/status VmRSS at 2 Hz
```

| | before | **peak** | after |
|---|---:|---:|---:|
| process RSS | 226 MB | **429 MB** | 233 MB |
| cgroup `MemoryCurrent` | 287 MB | **491 MB** | 298 MB |

Memory returns to baseline after the swap — the old engine is dropped,
not leaked. `MemoryMax=768M` clears the 491 MB peak with 56% headroom
and is the value used in `packaging/sumidero.service`; it has now
survived this reload in production-shaped conditions.

Caveat: this reload parsed the on-disk list copies. A daily refresh that
re-downloads first holds response buffers as well, so the true peak is
somewhat above 491 MB. The 768 MB ceiling was chosen to absorb that;
if `MemoryMax` is ever tightened, re-measure across a refresh that
actually downloads.

## Cold start

```sh
journalctl -u sumidero-shadow.service | grep -E "Started|filter engine ready|serving"
```

Systemd `Started` to `serving`, including parsing 3.29M rules from the
on-disk list copies: **6 s** (07:58:08 → 07:58:14). Inside the "sub-10s
is fine" bar in the handoff. The daemon binds no socket until the engine
is ready, so it never serves unfiltered during that window.

## Production bind shape and the hardened unit (2026-08-20)

The shipped unit `packaging/sumidero.service` was verified in a sandbox
on port 5355 with the **real** configuration shape — both wildcards, the
full 3.29M-rule corpus, `DynamicUser`, `ProtectSystem=strict`, the
syscall filter, and `MemoryMax=768M`:

| check | result |
|---|---|
| `bind = ["0.0.0.0:5355", "[::]:5355"]` | both bound (needed the `IPV6_V6ONLY` fix; see below) |
| A/AAAA over IPv4, IPv6 and the LAN address | resolves |
| blocking over IPv6 | NXDOMAIN |
| TCP over IPv6 | NOERROR |
| non-EDNS UDP, 4,879-byte answer | TC set, 31 bytes on the wire |
| EDNS bufsize 4096, same answer | TC set (answer exceeds 4096) |
| non-EDNS over TCP, same answer | full 61 records, 4,879 bytes |
| SQLite writes under `DynamicUser` | ok |
| SIGHUP reload, full corpus | `reload complete` |
| steady RSS at 3.29M rules | **207 MB**, 224 MB after reload |
| `systemd-analyze security` | **1.6 (OK)** |

The dual-bind check found a cutover blocker. Linux defaults to
`net.ipv6.bindv6only=0`, so a socket on `[::]:53` also claims every IPv4
address, and binding `0.0.0.0:53` first made the second entry fail with
`EADDRINUSE` against itself — exactly the configuration `docs/CUTOVER.md`
prescribes, failing at the point of no return with AdGuard already
stopped. Sockets are now opened `IPV6_V6ONLY`, so each configured
address means the family it names, and bind failures name the address
and protocol.

## Reliability review: nine suspected defects, measured (2026-08-20)

A reliability review before cutover treated nine suspected defects as
hypotheses and reproduced each before fixing anything. All nine were
confirmed on this box; none was disproved. Fixes landed in four commits
(`Make upstream failure handling survive hangs…`, `Bound in-flight
queries…`, `Cap the post-install holddown…`, `Bound the cache by
bytes…`), each carrying the test that reproduced its defect.

Cache measurements (release build, this Jetson, 6 worker threads):

| measurement | before | after |
|---|---:|---:|
| RSS of 16,384 cached DNSSEC-signed answers (~6.1 KB wire) | 141.6 MB | 47.5 MB (64 MiB estimated budget) |
| `Cache::get` aggregate, 6 threads on 1024 signed entries | 276k ops/s | 740k ops/s |
| `Cache::get` single thread (same load) | 393k ops/s | 375k ops/s |

Before the fix the cache **anti-scaled** — six cores were slower in
aggregate than one, because every hit cloned the full record set inside
the global mutex. The entry-count bound alone did not bound memory:
141.6 MB of cache was over half the ~270 MB of `MemoryMax` headroom
above the reload peak.

Live check after the fixes (throwaway instance, port 15353, real
upstreams): 2,000 concurrent queries at 7,372 QPS from 64 client
threads — 0 timeouts, 0 SERVFAIL, correct NXDOMAIN for blocked names,
9.8 MB RSS, 1,575 cache hits with the initial miss-burst collapsed to
~26 upstream fetches by single-flight.

Upstream failure modes are covered by deterministic fake-transport
tests rather than live numbers: a silently hung connection (the mode
the pool-level timeout used to hide), repair cancelled by a faster
racing upstream (the mode that never let a slower upstream recover),
handshake-per-query against an upstream that accepts connections it
cannot serve, and SERVFAIL-only upstreams that used to read healthy.

## Still to measure

The load-testing harness (mandate 1a) has not been built yet, so there
are **no** QPS-ceiling, p50/p99/p999-under-load, UDP-loss or
sustained-CPU numbers in this file. The latency figures quoted in
`crates/filter/BENCHMARKS.md` come from the passive query log, not from
a load generator, and the throughput figure there (~9.8k QPS) was
client-bound. Nothing in this file should be read as a load-test result.
