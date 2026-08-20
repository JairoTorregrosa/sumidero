# sumidero — design record

Design phase closed 2026-08-19 and confirmed by the owner. The decisions below
are settled; changing any of them requires an explicit owner decision, not a
code review comment.

## Purpose

Replace AdGuard Home on a Jetson Orin Nano (aarch64) serving house DNS.
Priorities: correctness, operability by both humans and LLM agents through the
CLI, and a small, auditable codebase.

## Scope (v1)

**In**: list-based blocking (ABP-DNS subset + hosts format), local safe-search
CNAME rewrites, encrypted upstreams, query log/stats, shadow mode against a
live resolver, one-shot migration from AdGuard Home's YAML config.

**Out**: AdGuard cloud features (parental control, safe-browsing service),
DHCP, web UI, HTTP API, Prometheus metrics, per-client rule sets.

## Blocking semantics

- A blocked query is answered **NXDOMAIN** with a synthetic SOA in the
  authority section (negative-caching friendly, unambiguous to clients).
- AdGuard answers blocked queries with `0.0.0.0`. In shadow mode this
  divergence is **expected** and auto-classified as such.
- Exceptions (`@@`) always win over block rules.
- `ANY` queries are refused.

## Stack

- **tokio** for async runtime, **hickory-dns** for wire protocol, server
  plumbing, and DoH/DoQ upstream transports.
- **Own filter engine** (`crates/filter`): no third-party ABP parser.
- **rusqlite** (bundled SQLite, WAL mode) is the only C dependency.
- `#![forbid(unsafe_code)]` in all crates; clippy pedantic, `-D warnings`.
- Edition 2024. MSRV = current stable minus 2 (tracked in `rust-version`).

## Workspace

Single repo, three crates, one shipped binary.

- **`crates/filter`** — pure, no I/O, publishable standalone.
  - Parser: ABP-DNS subset — `||domain^`, exact domains, `@@` exceptions,
    wildcards, hosts-file lines. Cosmetic/element-hiding rules are rejected
    with a warning, never silently dropped.
  - Matcher: inverted label tree; exceptions win; case-insensitive;
    trailing-dot insensitive.
  - Owns the fuzz targets and criterion benches.
- **`crates/core`** — daemon library.
  - UDP/TCP server on :53 (binds v4+v6), client-IP allowlist.
  - Pipeline: filter → safe-search rewrite → cache → parallel DoH/DoQ
    upstreams (bootstrap resolution, per-upstream timeout).
  - Cache: own LRU, min TTL 300 s, optimistic serve-stale.
  - DNSSEC v1: set the DO bit, trust the validating upstream.
  - SQLite writer: query log, aggregate stats, shadow divergences, runtime
    heartbeat row (PID, started-at, list hashes, config hash). Retention
    7 days via hourly DELETE.
  - Shadow mode: also forward each query to a reference resolver, compare
    verdict + rcode class, record divergences.
- **`crates/cli`** — binary `sumidero`: `serve`, `status`, `log`, `stats`,
  `explain`, `check`, `reload` (= `check` then SIGHUP), `init --profile`,
  `migrate`, `shadow report`.

## Control plane: the filesystem is the API

- TOML config file. Profiles `minimal` / `balanced` / `strict` expand to
  named blocklists; every list individually overridable.
- The CLI reads state from SQLite directly; `explain` warns when its list
  hash differs from the daemon's heartbeat row.
- Reload = `sumidero check` (validate) then SIGHUP to the daemon (nginx
  pattern). No control socket, no HTTP, no web UI in v1.
- `migrate` converts an `AdGuardHome.yaml` one-shot.

## Agent-native CLI contract

- Every command supports `--json`, emitting a versioned schema
  (`"schema": "v1"`); schema changes bump the version, never mutate v1.
- Exit codes are semantic and documented per command. An LLM agent must be
  able to operate sumidero without parsing human-oriented text.

## Fail loud (non-negotiable)

Missing or invalid config, or a configured blocklist that cannot be fetched
**and** has no last-good disk copy ⇒ the daemon refuses to start. No silent
defaults, no degraded half-running states that mask failures.

## Lists

- Update every 24 h with ETag/If-None-Match; always keep the last good disk
  copy; a fetch failure with a disk copy present logs loudly and serves the
  copy.

## Deployment

- Native binary + hardened systemd unit: `DynamicUser=yes`,
  `CAP_NET_BIND_SERVICE`, `ProtectSystem=strict`, `MemoryMax`. Not docker.
- Rollout: shadow mode on :5353 against the live AdGuard ≥ 48 h, divergences
  triaged; cutover to :53 is the owner's explicit call.

## Licensing / repo

MIT. `github.com/JairoTorregrosa/sumidero`, private until shadow-validated,
then public; `sumidero-filter` (then core) published to crates.io at v0.1.0
with cargo-dist binaries for aarch64 and x86_64-musl. Code, docs, and commits
in English.
