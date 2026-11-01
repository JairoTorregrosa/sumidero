# sumidero — performance record

Numbers measured on the reference host: an NVIDIA Jetson
(6-core aarch64, 7.6 GB RAM), with the production rule set (adguard-dns-filter,
hagezi pro and tif, oisd nsfw and big: 2,993,064 rules) and the
production upstreams (Google DoH, Quad9 DoH, AdGuard DoQ). Measured
2026-10-31. Re-measure before changing a limit that depends on these.

## How to reproduce

```sh
# filter engine alone: build time, heap, verdict cost
cargo run --release -p sumidero-filter --example measure -- lists/*.txt

# one daemon under load (open-loop UDP, 32 sockets, JSON per phase)
cargo build --release -p sumidero -p sumidero-core --examples
LOADGEN=target/release/examples/loadgen NAMES=blocked-names.txt \
  scripts/stress.sh new target/release/sumidero lab.toml 15354
```

`loadgen` sends at a fixed rate whatever the server does, so a slow
server shows up as latency and loss, not as a slower client. Modes:
`hit` (500 popular names), `blocked` (names from `--names`), `miss` (a
fresh name every query, so every query goes upstream), `mix` (80/10/10).
Load generator and daemon share the host; CPU figures are the daemon's
own (`/proc/<pid>/stat`).

## Filter engine

| | |
|---|---:|
| rules | 2,993,064 |
| build | 3.39 s |
| engine heap | 108 MB |
| verdict, allowed name | 2.0 µs |
| verdict, blocked name | 3.5 µs |

## Daemon: before and after the 2026-10 work

Before: 8f9eb8d (in production since 2026-08). After: main as of #13.
Same host, same lists, same upstreams, loopback.

| | before | after |
|---|---:|---:|
| start to serving (lists on disk) | 7.6 s (downloads first) | 3.9 s |
| start to serving (first start, nothing on disk) | 7.6 s | 12.2 s |
| RSS once serving | 206 MB | 120 MB |
| hits 2k qps: p50 / p99 | 0.123 / 0.220 ms | 0.083 / 0.175 ms |
| hits 8k qps: p50 / p99 | 0.172 / 0.431 ms | 0.124 / 0.273 ms |
| hits 16k qps: p50 / p99 | 0.230 / 0.724 ms | 0.160 / 0.450 ms |
| blocked 8k qps: p50 / p99 | 0.157 / 0.357 ms | 0.119 / 0.263 ms |
| daemon CPU per query, hits 16k qps | 89 µs | 57 µs |
| daemon CPU per query, blocked 8k qps | 97 µs | 69 µs |
| loss, every run above | 0 | 0 |
| reload under 3k qps: lost / p99 | 0 / 0.246 ms | 0 / 0.216 ms |
| reload peak RSS | 430 MB | 317 MB (with the unit's malloc settings) |
| RSS after two reloads | 275–301 MB | 117 MB (with the unit's malloc settings) |
| SIGTERM to exit | 0.05 s | 0.05–0.1 s |

The first start is slower by design: it now downloads every list
through the encrypted upstreams and validates it before serving. Every
later start serves from the stored copies and downloads afterwards.

## Misses

A miss costs the upstream's latency, as for any forwarder: about
70 ms p50 from this host, for both binaries. Interleaved runs with
each upstream alone and in pairs (300 qps of unique names, 20 s, two
rounds each) show no difference between the binaries beyond run-to-run
noise (p99 88–165 ms for both). Under load shedding by Quad9 (`403 DoH
dropped query`) the after-binary no longer reconnects per shed query
(#16).

Known limit, in both binaries: a burst of ~4000 qps against a cold cache
right after ~25 s idle, with 10% unique misses, is bimodal. Some runs
answer at p90 10 ms, others at p90 55–68 ms with ~110 queries refused by
the 512 in-flight cap during the first second, while the upstream
connections warm up. A home network does not produce this burst; a
restart under real traffic does not either, because traffic ramps.

## Memory

`MALLOC_MMAP_THRESHOLD_=1048576` (in the shipped unit) is what keeps
RSS flat across reloads; see `packaging/sumidero.service`.

| setting | serving | after start refresh | after reload 1 | after reload 2 | peak |
|---|---:|---:|---:|---:|---:|
| glibc default | 127 MB | 207 MB | 301 MB | 275 MB | 432 MB |
| `MALLOC_ARENA_MAX=2` | 130 MB | 188 MB | 185 MB | 297 MB | 402 MB |
| `MALLOC_MMAP_THRESHOLD_=1048576` | 128 MB | 119 MB | 119 MB | 120 MB | 317 MB |
| both (shipped) | 123 MB | 117 MB | 117 MB | 117 MB | 317 MB |
