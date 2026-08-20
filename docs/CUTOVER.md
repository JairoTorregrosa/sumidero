# Cutover: replacing your resolver on port 53

Runbook for making sumidero the resolver your network already points
at. **An operator executes this, not an agent.** Nothing here is
reversible by accident, and step 4 is the point of no return until you
roll back.

The whole swap is two commands. Everything around them is verification.

## What actually changes

Only *which process owns port 53 on the host*. Clients keep pointing at
the same address, so there is no DHCP change, no router change, and no
per-device reconfiguration. That is what makes rollback fast.

The incumbent and sumidero cannot own the port at once: the incumbent
stops first, then sumidero starts.

Two preconditions worth checking before the swap window:

- The host's own `/etc/resolv.conf` should list a resolver that is not
  this host first, so the host keeps working DNS during the swap — that
  is what lets you `apt`/`docker` your way out of trouble mid-cutover.
- Be reachable on the host **by IP**, not by a hostname that needs DNS
  to resolve.

## 1. Gates — do not start until all of these are true

- [ ] Shadow mode (`serve --shadow <incumbent-addr>`) has run against
      the incumbent long enough to cover real traffic — days, not
      minutes — and `sumidero shadow report` shows only triaged
      divergences: your bug (fixed), a known dialect difference (e.g.
      the incumbent answers blocks with `0.0.0.0`, sumidero with
      NXDOMAIN), or a documented list difference.
- [ ] `sumidero status` exits 0 and has not reported a degraded daemon
      during the soak; upstream health shows no unexplained
      all-upstreams-failed queries.
- [ ] TCP, EDNS/>512-byte answers, and the qtypes your clients really
      send (A, AAAA, HTTPS, PTR, SRV) have been exercised from a real
      client, not just `dig` on localhost.
- [ ] `server.allow` covers **every** source that will reach the new
      listener: the LAN range(s), `127.0.0.1/32`, `::1/128`, any VPN or
      overlay addresses — and the LAN's IPv6 prefix if it has one. A
      test instance that only listened on IPv4 loopback never saw v6
      clients; a `[::]:53` listener will, and anything not in `allow`
      is REFUSED. v6 failing while v4 works is a miserable thing to
      diagnose.
- [ ] The firewall allows 53/udp and 53/tcp from those same sources.

## 2. Install the production config

Follow `docs/INSTALL.md`. If you validated with a test instance on a
high port, derive the production config from it, changing exactly:

```toml
[server]
# BOTH wildcards. IPv6 sockets are IPV6_V6ONLY, so each entry serves
# exactly the family it names — "[::]:53" alone would leave every IPv4
# client unanswered.
bind = ["0.0.0.0:53", "[::]:53"]

[filtering]
list_dir = "/var/lib/sumidero/lists"

[database]
path = "/var/lib/sumidero/sumidero.sqlite"
```

Validate without starting anything:

```sh
sumidero --config /etc/sumidero/config.toml check
```

Do **not** create `/var/lib/sumidero` by hand — systemd's
`StateDirectory` makes it a symlink into `/var/lib/private`, and a real
directory in the way makes the unit fail at `STATE_DIRECTORY`. The
daemon creates `lists/` inside it on first start.

Do **not** `systemctl enable --now sumidero` yet: port 53 still belongs
to the incumbent, and the daemon would fail to bind.

## 3. Note the rollback state

Record how the incumbent runs right now (container status, unit state)
and confirm it holds the port:

```sh
sudo ss -lntup | grep ':53'
```

Write down what you see. You are about to change it.

## 4. The swap

```sh
# stop the incumbent in a way that STAYS stopped across reboots
# (docker compose stop with `restart: unless-stopped`, or
#  systemctl disable --now <incumbent>)

# port 53 must now be free; if anything still holds it, STOP and
# investigate rather than forcing
sudo ss -lntup | grep ':53' || echo "port 53 is free"

sudo systemctl enable --now sumidero
```

`enable --now` is deliberate: it also makes sumidero the resolver after
a reboot. The socket is not bound until the lists are compiled (a few
seconds at millions of rules), so a brief connection-refused window is
expected and correct.

## 5. Verify — from a real client, not just the host

```sh
# on the host — sudo, because the state dir is 0700 under DynamicUser
sudo sumidero --config /etc/sumidero/config.toml status   # expect exit 0

# substitute your host's LAN address
dig @<host> wikipedia.org A +short          # resolves
dig @<host> doubleclick.net A               # NXDOMAIN (blocked)
dig @<host> +tcp github.com A +short        # TCP path
dig @::1 wikipedia.org A +short             # IPv6 listener
dig @::1 doubleclick.net A                  # IPv6 filtering

# large answer: TC over UDP, full answer over TCP
dig @<host> +noedns +ignore microsoft.com TXT | grep flags   # expect tc
dig @<host> +tcp microsoft.com TXT +noall +answer | wc -l    # expect many
```

Then leave a browser and a phone on the network for ten minutes and
watch:

```sh
journalctl -u sumidero -f
sudo sumidero --config /etc/sumidero/config.toml log --limit 50
```

What would send you to rollback: `status` exiting non-zero, `all
upstreams failed` in the journal, REFUSED for a client that should be
allowed, or any device that cannot reach a site it should.

## 6. Rollback — under a minute

Two commands, in this order:

```sh
sudo systemctl disable --now sumidero
# start the incumbent again (docker compose start / systemctl enable --now)
```

Verify the incumbent has the port back (`ss -lntup | grep ':53'`, then
a `dig` from a client). Nothing on the client side has to change,
because nothing on the client side ever changed. sumidero writes only
to `/var/lib/sumidero`; the incumbent's config and data are untouched.

`disable` matters as much as `stop`: without it, a reboot brings
sumidero back up and it takes port 53 from the incumbent again.

## 7. After a stable week

Only once the network has run on sumidero for a week with no
complaints: retire the shadow/test rigs, and decommission the
incumbent. Keep the incumbent's configuration archived until you are
certain — it is the rollback path of last resort and the provenance of
a migrated configuration.
