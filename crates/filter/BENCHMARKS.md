# filter benchmarks

Measured 2026-08-19 on the deploy target (Jetson Orin Nano 8GB, aarch64,
MAXN_SUPER), `cargo bench -p sumidero-filter`, criterion defaults.

Rule set: three real lists totalling **613,524 rules** —
HaGeZi Pro++ (246,594), HaGeZi Ultimate (271,264, overlapping),
StevenBlack hosts (95,666). No single public hagezi list reaches the 1M
rules originally hoped for; this is the honest measured set.

Parse + compile: ~150 ms per 250k-rule ABP list, ~48 ms for the 95k hosts
list (single-threaded, release).

Lookup (median of criterion's 100-sample run):

| case | time |
|---|---|
| miss, short allowed name (`www.wikipedia.org`) | 189 ns |
| hit, blocked apex | 319 ns |
| hit, blocked subdomain | 291 ns |
| miss, 10-label deep name | 146 ns |

That is roughly 3–7 M lookups/s per core — four orders of magnitude above
this network's DNS query rate. Memory for the compiled engine plus rule
storage stays within the daemon's planned MemoryMax budget.

Reproduce:

```sh
SUMIDERO_BENCH_LISTS=hagezi-big.txt:hagezi-ultimate.txt:stevenblack-hosts.txt \
  cargo bench -p sumidero-filter
```

The bench refuses to run without `SUMIDERO_BENCH_LISTS` — numbers from a
toy list would be meaningless.

## Fuzzing

2026-08-19, on the post-review parser/matcher (commit 001a530), local
Jetson runs with libFuzzer + ASan, seeded with real-list snippets:

- `parse` target: 11 min, ~1.4M+ executions, 0 crashes/OOMs.
- `verdict` target: 11 min, 0 crashes/OOMs.

The nightly CI workflow repeats 5-minute runs of both targets.

## Real-deployment validation (shadow, 2026-08-19)

Live on the Jetson: `sumidero-shadow.service` serving 127.0.0.1:5353
with the user's migrated config — **3,287,544 rules across 6 lists**
(hagezi TIF alone is 2.1M; 5× the original bench set), shadowing the
production AdGuard and fed by a replay of the house's real query
stream.

Latency (from the query log, real traffic):

| path | p50 | p90 | p99 |
|---|---|---|---|
| blocked (synth NXDOMAIN) | 145 µs | 1.3 ms | 7.8 ms |
| cache hit | 58 µs | 154 µs | — |
| upstream (raced DoH/DoQ from Bogotá) | 77 ms | 112 ms | 145 ms |

Cold-name side-by-side (6 samples): sumidero 88–124 ms vs AdGuard
184–320 ms — racing all upstreams roughly halves cold latency here.
Warm answers: ≤4 ms via dig for both.

Throughput: 5,000 pipelined UDP queries of a cached name from a
single-socket Python client: **0 loss, ~9,800 QPS** (client-bound;
daemon CPU stayed ~2.5%).

Memory at 3.29M rules: ~1.3 GB RSS after a fresh list load, settling
around 1.0 GB (plateau — no growth under load). AdGuard with the same
lists: ~650 MiB. `MALLOC_ARENA_MAX=2` makes no material difference;
the cost is the engine representation (~300 B/rule: per-rule text +
pattern strings, HashMap-per-node label tree). Known pre-cutover
optimization target; unit runs with `MemoryMax=1536M` meanwhile.

## Compact engine rewrite (2026-08-19, memory-critical host)

The HashMap-per-node label tree and per-rule `String`s were replaced by
arena storage: one shared text arena, sorted reversed-label key spans
resolved by binary search, and parallel per-rule metadata arrays. List
loading now streams line-by-line straight into compact storage (no
intermediate `Vec<Rule>` for multi-million-line lists).

Measured on the real 3,287,544-rule set (same Jetson):

| metric | before | after |
|---|---|---|
| engine steady RSS | 1,328 MB | **200 MB** |
| peak during load | 1,328 MB | **207 MB** |
| lookup (criterion, hot, 2.6M rules) | 0.15–0.34 µs | 1.2–4.5 µs |
| lookup (mixed names, cold-ish) | — | ~17 µs |

The lookup regression is a deliberate trade: binary search over a 95 MB
index takes cache misses a pointer-chasing trie kept warm, but even the
cold ~17 µs is ~60k QPS on one core — three orders of magnitude above
house traffic, and invisible next to the 77 ms upstream path. Memory is
the binding constraint on the shared 8 GB Jetson (settled with the
owner).

Further levers if ever needed (measured estimates from review): an FST
over unique keys + postings (~130–165 MB total), SoA key index
(−13 MB), an inline u64 key-prefix array (+26 MB for roughly half the
lookup misses).
