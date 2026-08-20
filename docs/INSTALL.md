# Installing sumidero

Linux with systemd. Everything below was executed and verified on the
reference target (Jetson Orin Nano, aarch64, Ubuntu 22.04); the unit's
sandboxing in particular was tested end to end rather than written from
the systemd manual.

## Layout

| path | what | owner |
|---|---|---|
| `/usr/local/bin/sumidero` | the binary | root |
| `/etc/sumidero/config.toml` | configuration | root, read-only to the daemon |
| `/var/lib/sumidero/sumidero.sqlite` | query log, stats, heartbeat | the daemon |
| `/var/lib/sumidero/lists/` | downloaded blocklist copies | the daemon |

The daemon runs under `DynamicUser=yes`: there is no `sumidero` account
to create, and systemd creates and chowns `/var/lib/sumidero` on first
start. Nothing outside `/var/lib/sumidero` is writable to it.

Two consequences of `DynamicUser` that will bite you otherwise:

- **Do not create `/var/lib/sumidero` yourself.** systemd makes it a
  symlink to `/var/lib/private/sumidero`; a real directory in the way
  makes the unit fail at `STATE_DIRECTORY` with `File exists`. Let the
  first start create it. (`list_dir` inside it *is* created by the
  daemon, so a clean first start needs no manual setup at all.)
- **The state directory is mode 0700 and owned by a UID that changes
  between starts**, so every CLI command that reads the database —
  `status`, `log`, `stats`, and `explain`'s hash check — needs `sudo`.
  There is no group to add yourself to, because the group is dynamic
  too. All the examples below reflect that.

## Build and install

```sh
cargo build --release
sudo install -m 0755 target/release/sumidero /usr/local/bin/sumidero
sudo install -d -m 0755 /etc/sumidero
sudo install -m 0644 packaging/sumidero.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Configure

Start from a generated skeleton, or migrate an existing AdGuard Home
install:

```sh
# from scratch
sumidero --config /etc/sumidero/config.toml init

# or from AdGuard Home — prints a warning for every setting that has no
# sumidero equivalent rather than silently dropping it
sudo sumidero migrate --from /path/to/AdGuardHome.yaml \
  --out /etc/sumidero/config.toml
```

Then set, at minimum:

- `server.bind` — `["0.0.0.0:53", "[::]:53"]` for a LAN resolver.
  Binding a privileged port works because the unit grants
  `CAP_NET_BIND_SERVICE`; nothing runs as root.

  **Each entry means exactly the family it names.** IPv6 sockets are
  opened `IPV6_V6ONLY`, so you must list both wildcards to serve both
  families — `["[::]:53"]` alone serves IPv6 *only* and IPv4 clients get
  no answer at all. (Without `IPV6_V6ONLY` the opposite trap applies:
  Linux's default `net.ipv6.bindv6only=0` would let `[::]:53` swallow
  IPv4 too, making the two-entry list fail against itself with
  `EADDRINUSE`. Explicit is the lesser evil.) A bind failure names the
  address and protocol that failed.
- `server.allow` — the networks allowed to query. Anything else is
  REFUSED. **An open resolver is an abuse vector: keep this tight.**
- `filtering.list_dir` — `/var/lib/sumidero/lists`.
- `database.path` — `/var/lib/sumidero/sumidero.sqlite`.

Validate before starting. `check` parses the config and every list and
reports the rule count; it never touches the running daemon:

```sh
sumidero --config /etc/sumidero/config.toml check
```

## Run

```sh
sudo systemctl enable --now sumidero
```

The daemon fetches and compiles every list **before** it binds a socket,
so it never serves unfiltered answers. At ~3.3M rules that takes about
6 s. A list that cannot be fetched and has no stored copy is a fatal
startup error, by design — refusing to start beats silently serving with
filtering disabled.

## Operate

```sh
# health: exit 0 healthy, 5 not running, 7 running but cannot resolve
sudo sumidero --config /etc/sumidero/config.toml status
sudo sumidero --config /etc/sumidero/config.toml --json status

# reload config, lists, allowlist and safe-search without dropping queries
sudo systemctl reload sumidero        # SIGHUP

# why was this name blocked? (no sudo needed: filter-only, no database)
sumidero --config /etc/sumidero/config.toml explain ads.example.com

# recent queries and aggregate stats
sudo sumidero --config /etc/sumidero/config.toml log --limit 50
sudo sumidero --config /etc/sumidero/config.toml stats --hours 24

# logs
journalctl -u sumidero -f
```

`reload` re-reads the config file, re-fetches lists, and swaps the
engine, allowlist and safe-search table atomically. A bad config or an
unfetchable list leaves the running state untouched and logs loudly.
Changes to `server.bind`, `[upstreams]` or `database.path` need a
restart; the daemon says so when it sees them.

Lists also refresh on their own daily.

## Monitoring

`status --json` is the integration point. The fields that matter for
alerting:

| field | meaning |
|---|---|
| `running` | heartbeat is fresh |
| `degraded` | running, but cannot resolve or is dropping log events |
| `consecutive_all_upstreams_failed` | queries since any upstream last answered — non-zero means clients are getting SERVFAIL |
| `log_events_dropped_recent` | events lost since the last sample — **this is the alertable one** |
| `log_events_dropped` | lifetime total, diagnostic only (never goes back down) |
| `upstreams[].last_success_secs_ago` | per-upstream last answer |

Alert on exit code 5 or 7:

```sh
sudo sumidero --config /etc/sumidero/config.toml --json status >/tmp/sumidero-status.json
case $? in
  0) ;;                                     # healthy
  5) echo "sumidero is not running" >&2 ;;
  7) echo "sumidero is degraded" >&2; cat /tmp/sumidero-status.json >&2 ;;
esac
```

Do **not** alert on `log_events_dropped` either. It is a lifetime total,
so a single transient queue-full spike would pin the daemon degraded
until the next restart. `degraded` keys off `log_events_dropped_recent`.

Do **not** alert on `upstreams[].connected` being false. Connections are
rebuilt lazily on the next query, so a healthy raced pool shows
disconnected slots routinely — on the reference host one upstream reads
disconnected a majority of the time while every query is answered. That
field is diagnostic, not a health signal.

## Resource limits

`MemoryMax=768M` in the shipped unit is sized from a measured reload
peak (429 MB RSS / 491 MB cgroup at 3.29M rules, when the old and new
engines briefly coexist). See `PERF.md`. With a much smaller rule set
you can lower it; re-measure a SIGHUP reload on your own lists first,
because the reload peak — not the steady state — is what has to fit.

## Uninstall

```sh
sudo systemctl disable --now sumidero
sudo rm /etc/systemd/system/sumidero.service /usr/local/bin/sumidero
sudo rm -rf /etc/sumidero /var/lib/sumidero /var/lib/private/sumidero
sudo systemctl daemon-reload
```
