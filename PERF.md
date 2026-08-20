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

## Browsing-lag investigation: answer latency vs the upstreams (2026-08-20)

Question: pages "feel laggy on connection" — is it DNS, and if so where
does sumidero spend the time? Method: the passive query log
(`duration_us` per query) plus a new active harness,
`crates/core/examples/latency_probe.rs`, which sends browsing-shaped
bursts (A + AAAA + HTTPS(65) per name, concurrently) at any mix of
targets: single upstreams through the daemon's own `UpstreamPool`
transport code, the raced pool exactly as the daemon runs it, and a
throwaway daemon instance over plain UDP. Name sets are partitioned
disjointly across targets so no target warms a provider edge cache for
another. Public name list: `bench/names-tranco-1000.txt` (Tranco
sample; household names never go in committed files).

All numbers measured on the deploy target during normal household
traffic. Cutover to production happened this same day, so the first
~25 minutes of query log are cold-cache restart artifacts; log-derived
numbers below exclude everything before 12:38:23 local.

### What a page load actually pays (production query log)

Grouping the log per client into bursts split at 2 s gaps — a page load
is one burst — and taking the slowest answer in each burst:

```sh
sumidero --json log  # then group rows by client into 2s-gap bursts
```

| burst-max answer time | value |
|---|---:|
| p50 | **0.1 ms** (all-cache page) |
| p90 | 52 ms |
| p95 | 64 ms |
| p99 | 104 ms |

DNS worst case adds ~0.1 s once per page load at p99, with zero
SERVFAILs, zero shed queries, and zero >1 s answers served to any real
client in the whole day's log. **Multi-second page lag cannot be DNS
through sumidero.** Perceived lag needs a different suspect (client
DoH bypass, a stale secondary resolver in DHCP/RA, Wi-Fi, TLS…).

### Where the milliseconds go (per-source, clean window)

| source | share | p50 | p90 | p99 |
|---|---:|---:|---:|---:|
| cache hit | ~24% | 84 µs | 101 µs | 121 µs |
| stale hit (+bg refresh) | ~15% | 90 µs | 106 µs | 143 µs |
| blocked (synth NXDOMAIN) | ~30% | 38 µs | 81 µs | 104 µs |
| cold miss (upstream) | ~32% | 11.6 ms | 57 ms | 104 ms |

### Cold-miss attribution: sumidero vs its upstreams directly

Network floor from this box: `ping 8.8.8.8` ≈ 10 ms. A provider
edge-cached name over plain UDP (`dig @8.8.8.8 google.com`) ≈ 12 ms; an
uncached name ≈ 80–116 ms — that is the provider's own recursion, paid
by any resolver.

Harness, 1000 Tranco names split 250/target, browsing-shaped bursts,
concurrency 4:

```sh
cargo run --release -p sumidero-core --example latency_probe -- \
  --names bench/names-tranco-1000.txt --seed 1 \
  'pool:https://dns.google/dns-query' \
  'pool:https://dns.quad9.net/dns-query' \
  'pool:quic://dns.adguard-dns.com' \
  'pool:https://dns.google/dns-query,https://dns.quad9.net/dns-query,quic://dns.adguard-dns.com'
```

| target | p50 | p90 | p99 |
|---|---:|---:|---:|
| Google DoH alone | 111 ms | 251 ms | 450 ms |
| Quad9 DoH alone | 108 ms | 329 ms | 687 ms |
| AdGuard DoQ alone | 167 ms | 638 ms | 2.8 s |
| raced pool (all 3) | **93 ms** | **245 ms** | 461 ms |

(High p50s here are the name mix: 70% of the sample is long-tail, i.e.
provider-recursion territory. The race tracks the best leg and clips
AdGuard's multi-second tail.)

End-to-end through a throwaway daemon (fresh cache, port 15353, full
3.3M-rule engine, real upstreams) vs the raced pool directly, disjoint
500-name sets, same run:

| | p50 | p90 | p99 |
|---|---:|---:|---:|
| sumidero e2e, cold miss | 74 ms | 221 ms | 453 ms |
| raced pool direct | 61 ms | 192 ms | 470 ms |
| sumidero e2e, warm (same names again) | **205 µs** | 292 µs | 516 µs |

The cold-miss delta vs the direct race is within name-set noise, and
the cache-hit path bounds daemon+UDP overhead at ~0.2 ms. **Cold-miss
latency is upstream recursion physics; sumidero adds nothing
measurable.**

### Overload shapes (throwaway instance)

- **Same-name stampede**: one never-seen name, 200 concurrent bursts
  (600 queries). All answered, wall time 108 ms, max 106 ms — exactly
  one upstream RTT; single-flight collapsed the stampede.
- **Distinct cold-miss flood**: 300 deep-long-tail names × 3 qtypes at
  concurrency 100 (~160 QPS of pure misses, ~3× that in upstream legs).
  sumidero e2e p50 482 ms vs direct race p50 453 ms on a disjoint
  equal-size set — the slowdown under flood is provider/uplink
  queueing, identical with and without sumidero, and the shape is far
  beyond any household burst.

### Hypotheses from the investigation brief, each against evidence

- **AAAA/HTTPS(65) handled or cached worse than A** — disproved.
  Per-qtype latency is equal in every probe run, log hit-rates match
  A, and an empty-answer NOERROR (NODATA) re-queried through the
  throwaway logs a 69 µs cache hit (`Cache::insert` stores NOERROR
  regardless of answer count, `MIN_TTL_SECS` floor applies).
- **Cold miss pays full upstream RTT, no prefetch** — confirmed but
  benign: the race already takes the best of three, serve-stale answers
  repeat visitors in ~90 µs, and the remaining cost is the provider's
  recursion, which prefetching can only hide for names already seen.
- **30 s stale TTL causes tight client re-query loops** — disproved:
  stale hits are ~15% of answers; a client re-querying after a stale
  answer finds the refreshed entry (background refresh completes in one
  upstream RTT) and gets a normal decremented TTL.
- **Rebuild holddown / Quad9 & AdGuard connection churn leaves queries
  on a slower upstream** — not client-visible: bucketing cold-miss
  latency by idle gap before the query shows no elevation right after
  idle periods (p50 13.6/12.0/10.8 ms for gaps ≤1 s / 2–10 s / 11–60 s),
  and the churn (Quad9 ~every 30–60 s, AdGuard DoQ ~every 1–2 min in
  the journal) never surfaced as a slow or failed client answer.
- **Single-flight is per (name, qtype, class) so a browser burst still
  fans out ×3 upstreams per qtype** — confirmed as designed; it is a
  bandwidth cost, not latency: e2e cold misses match the direct race.
- **UDP truncation forcing TCP retries** — not implicated: no
  truncation-shaped latency in any burst, and TC/TCP behavior was
  verified correct in the hardened-unit sandbox battery above.
- **Within-TTL cache misses** (queries re-fetched upstream <300 s after
  a fetch) — the pre-cutover log showed a handful, all explained by
  manual restarts during cutover (each restart empties the in-process
  cache). Current epoch after 29 min: 182 upstream fetches, **0**
  within-TTL refetches. Watch this stays 0 over longer uptimes.

### Verdict

No fix warranted by this evidence. The only real costs are (a) the
provider's own recursion on long-tail cold misses, which every resolver
pays, and (b) a cold cache after every restart, which matters only on
deploy days. If perceived lag persists, instrument the client side
next; the resolver is exonerated by these numbers.

## Still to measure

The latency/stress harness now exists (`latency_probe`, above); what it
has not yet produced is a QPS ceiling (all runs so far were
client-bound or upstream-bound, not daemon-bound), UDP-loss-under-load,
or sustained-CPU numbers. The throughput figure in
`crates/filter/BENCHMARKS.md` (~9.8k QPS) was client-bound. Nothing in
this file should be read as a daemon saturation result.
