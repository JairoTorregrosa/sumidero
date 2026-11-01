# sumidero — query semantics

What happens to one DNS query, in order, and what each outcome looks like
to the client and in the log. Everything here is enforced by a test that
talks to real sockets (`crates/core/tests`, `crates/cli/tests/daemon.rs`).

Each query is decided against **one policy snapshot** — engine, safe
search table, client allowlist — taken when it arrives. A reload that
lands mid-query affects the next query, never half of this one.

## 1. Admission

| condition | answer | log `source` |
|---|---|---|
| more than 512 queries in flight | SERVFAIL at once | `failed` |
| no question section | FORMERR | `synth` |
| client IP outside `server.allow` | REFUSED | `synth` |
| `ANY` query | REFUSED | `synth` |

Over TCP, a client outside `server.allow` is not answered at all: the
connection is closed at accept. At most 128 TCP connections are served at
once; each must send a query, and take its answer, within 10 s.

## 2. Filter verdict on the queried name

The name is lowercased and stripped of its trailing dot, then matched
against every list at once:

- **Exception** (`@@…`) anywhere wins over every block rule. Verdict
  `excepted`; resolution continues as for an allowed name, and the
  exception covers the whole CNAME chain (step 5).
- **Block**: `NXDOMAIN` with a synthetic SOA (`sumidero.invalid.`, TTL
  300) in the authority section, so clients cache the negative answer.
  Verdict `blocked`; the log names the rule text and the list index.
  The query never leaves the house.
- **No match**: continue.

Rule forms (ABP-DNS subset plus hosts files):

| form | matches |
|---|---|
| `||example.com^` | `example.com` and every subdomain |
| `example.com`, `0.0.0.0 example.com`, `127.0.0.1 example.com` | exactly `example.com` |
| `*.example.com`, `ads*.example.com` | glob, `*` spans dots |
| `||ads.*^` | glob, and every subdomain of a match |
| `@@` + any of the above | exception |

Rejected with a reason (logged once per list, counted in `status`):
cosmetic rules (`##`), `$modifiers`, regex rules, hosts lines pointing at
a real address, invalid names. `[Adblock Plus]` headers and `!` comments
are not issues.

## 3. Safe search

When `safe_search.enabled`, these names are answered locally with a
CNAME to the provider's enforced endpoint plus that endpoint's own
records (resolved through steps 4–5), verdict `rewritten`, rule
`safe-search -> <target>`:

| provider | names | target |
|---|---|---|
| `google` | `www.google.<tld>` for all 194 Google TLDs | `forcesafesearch.google.com` |
| `youtube` | `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` | `restrictmoderate.youtube.com` |
| `bing` | `www.bing.com`, `edgeservices.bing.com` | `strict.bing.com` |
| `duckduckgo` | `duckduckgo.com`, `www.duckduckgo.com`, `start.duckduckgo.com` | `safe.duckduckgo.com` |

`providers = []` with `enabled = true` means all four. An unknown
provider name is a config error. If the target cannot be resolved, the
CNAME is still sent with the target's rcode (never a clean NOERROR).

## 4. Cache, then upstreams

Key: `(name, type, class)`. One entry serves clients with and without the
DNSSEC DO bit: RRSIGs are stripped for clients that did not ask, and a
client without EDNS never gets an OPT record back.

| state | condition | answer | `source` |
|---|---|---|---|
| fresh | age < smallest TTL in the answer | cached, TTLs counted down | `cache` |
| stale | age < TTL + `cache.serve_stale_secs` (12 h) | cached, every TTL 30 s; one background refresh | `stale` |
| held | the name failed within its hold-down | SERVFAIL at once | `failure_cached` |
| miss | otherwise | upstream race | `upstream` / `failed` |

- **Lifetime** is the smallest record TTL; an SOA in a negative answer
  counts as `min(SOA TTL, SOA MINIMUM)` (RFC 2308). No floor is applied.
  A negative answer without an SOA is not cached. Only NOERROR and
  NXDOMAIN are cached.
- **Serve-stale** (RFC 8767): a stale hit is answered at once and
  refreshed behind the client's back, at most one refresh per key.
  `serve_stale_secs = 0` turns expiry into a miss.
- **Failure hold-down** (RFC 9520): when no upstream can resolve a key
  (every leg failed, or the upstreams said SERVFAIL), repeats get SERVFAIL
  without asking again for 5 s, then 10, 20, 40, capped at 60 s for
  consecutive failures. A success clears it. A stale entry always wins
  over a hold, and a hold never becomes NXDOMAIN.
- **Single flight**: concurrent misses for one key share one upstream
  lookup and its result (or its failure).
- **Upstream race**: the query (RD set, DO set) goes to every configured
  upstream at once; the first usable answer wins and gets the client's
  id. SERVFAIL, REFUSED and NOTIMP from an upstream are not usable and
  count as that upstream failing. Each leg is bounded by
  `upstreams.timeout_ms`.

## 5. CNAME chain check

After step 4, every CNAME target in the answer is matched against the
same engine (unless the queried name was excepted). If any target is
blocked and not excepted, the whole answer is replaced by the block
NXDOMAIN; verdict `blocked`, rule `<rule> (CNAME target <name>)`. This
applies to cache hits as well as misses, so it stops first-party tracker
cloaking and neutral aliases of blocked hosts.

## 6. The answer on the wire

- UDP answers are capped at the client's EDNS size, never above 1232
  bytes and never below 512; larger answers are truncated with TC set.
- TCP answers are length-prefixed and complete.
- Every query, whatever the outcome, is written to the query log
  (`sumidero log`), off the hot path. If the writer falls behind, records
  are dropped and counted (`status` reason `log_events_dropped`).

## Lists

- `url` lists are downloaded over HTTPS only, with the list host resolved
  **through the encrypted upstreams**, never the host resolver (a
  filtering host resolver must not be able to hide the list that blocks
  what it blocks). Connect 10 s, read 30 s, whole download 3 min, body at
  most 64 MB.
- A 200 replaces the stored copy atomically, but only if the body holds
  at least one rule (a captive portal page never replaces a list). A 304
  marks the stored copy as confirmed now.
- A failed download serves the last stored copy, then the `path` seed;
  with neither, the load fails (at start-up: the daemon does not start).
- Each list reports its `origin`: `downloaded`, `not_modified`,
  `stored_after_fetch_failure`, `seed_after_fetch_failure`, `local_file`,
  `stored_offline`, `seed_offline`, and how long ago its content was
  last confirmed.
- `path`-only lists (user rules) are re-read on every load.
