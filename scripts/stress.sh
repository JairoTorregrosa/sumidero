#!/usr/bin/env bash
# Stress one sumidero binary on the jetson lab. Prints JSON lines.
# usage: stress.sh <label> <binary> <config> <port>
# env: LOADGEN (path to the loadgen example binary), NAMES (blocked names,
# one per line, for the blocked and mix modes). Needs dig and Linux /proc.
# Writes the daemon log to $TMPDIR/stress-<label>.log.
set -euo pipefail
label=$1 bin=$2 cfg=$3 port=$4
lg=${LOADGEN:?set LOADGEN to target/release/examples/loadgen}
names=${NAMES:?set NAMES to a file of blocked names}
log=${TMPDIR:-/tmp}/stress-$label.log

pid_of() { pgrep -f -- "$bin --config $cfg serve" | head -1; }
cpu_ticks() { awk '{print $14+$15}' "/proc/$1/stat"; }
rss_kb() { awk '/^VmRSS/{print $2}' "/proc/$1/status"; }
hwm_kb() { awk '/^VmHWM/{print $2}' "/proc/$1/status"; }
emit() { printf '{"label":"%s",%s}\n' "$label" "$1"; }

start=$(date +%s.%N)
RUST_LOG=info "$bin" --config "$cfg" serve >"$log" 2>&1 &
until dig +time=1 +tries=1 @127.0.0.1 -p "$port" example.com >/dev/null 2>&1; do
  sleep 0.05
  if ! kill -0 $! 2>/dev/null; then echo "daemon died" >&2; tail "$log" >&2; exit 1; fi
done
ready=$(date +%s.%N)
pid=$(pid_of)
emit "\"phase\":\"startup\",\"secs_to_serving\":$(echo "$ready - $start" | bc),\"rss_mb\":$(( $(rss_kb "$pid") / 1024 )),\"hwm_mb\":$(( $(hwm_kb "$pid") / 1024 ))"

# Let a post-start refresh (new binary) settle before measuring.
sleep 25
"$lg" --server 127.0.0.1:"$port" --qps 300 --secs 4 --mode hit >/dev/null

run() { # mode qps secs
  local t0 t1 out
  t0=$(cpu_ticks "$pid")
  out=$("$lg" --server 127.0.0.1:"$port" --qps "$2" --secs "$3" --mode "$1" --names "$names")
  t1=$(cpu_ticks "$pid")
  local served=$(( $2 * $3 ))
  emit "\"phase\":\"load\",\"cpu_us_per_query\":$(echo "scale=1; ($t1 - $t0) * 10000 / $served" | bc),\"rss_mb\":$(( $(rss_kb "$pid") / 1024 )),\"loadgen\":$out"
}
run hit 2000 15
run hit 8000 15
run hit 16000 10
run blocked 8000 10
run mix 4000 15
run miss 150 15

# Reload under load: SIGHUP 5 s into a 30 s hit run.
"$lg" --server 127.0.0.1:"$port" --qps 3000 --secs 30 --mode hit > "${TMPDIR:-/tmp}/stress-$label-reload.json" &
lgpid=$!
sleep 5
before=$(grep -c "reload complete" "$log" || true)
t=$(date +%s.%N)
kill -HUP "$pid"
until [ "$(grep -c "reload complete" "$log" || true)" -gt "$before" ]; do sleep 0.1; done
reload_s=$(echo "$(date +%s.%N) - $t" | bc)
wait $lgpid
emit "\"phase\":\"reload_under_load\",\"reload_secs\":$reload_s,\"hwm_mb\":$(( $(hwm_kb "$pid") / 1024 )),\"loadgen\":$(cat "${TMPDIR:-/tmp}/stress-$label-reload.json")"

kill -TERM "$pid"
t=$(date +%s.%N)
while kill -0 "$pid" 2>/dev/null; do sleep 0.05; done
emit "\"phase\":\"shutdown\",\"secs\":$(echo "$(date +%s.%N) - $t" | bc)"
