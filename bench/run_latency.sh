#!/usr/bin/env bash
#
# The latency inputs of design §8 step 13f, which `bench/run.sh --latency` runs: the throughput
# and the latency of servers that route, at fixed request rates. colibri's test-only server routes
# the GitHub API's 203 routes of bench/router/competitors/github_routes.txt with `--routes github`,
# and Go's chi, axum, http.zig and Fastify route the same routes, from bench/competitors/. Every
# route answers 200 and "ok\n". oha, pinned by release and commit, sends GET requests over the 131
# GET routes at each rate of `rates`, with its latency correction, so the latency holds the queue
# time that coordinated omission hides. It sends h11, and h2 in cleartext with prior knowledge to
# every server but http.zig, which has no h2. Over TLS 1.3 it sends h2-tls, h2 with ALPN, to
# every server but http.zig, which has no TLS, so the h3 numbers have a TLS baseline over TCP.
# It also sends h3 to colibri's UDP server with
# `routes=github`, to chi on quic-go's http3.Server and to axum on quinn and the h3 crate, the
# three that speak it. oha's release builds have no h3, so the script builds oha from its tag.
#
#   bench/run_latency.sh [--rounds <n>] [--network | --waits] [report.md]
#
# With --network it measures what h3 changes on a path with delay and loss (design §8 step 13i),
# in place of the inputs above. tc netem adds each profile of `profiles` to the loopback device,
# whose MTU becomes 1500 and whose TCP offloads turn off, so netem drops one packet at a time. Each
# h3 server sends each datagram in a send of its own, because netem drops a send of segments
# whole. colibri, chi and axum serve h2-tls and h3 with 512 requests in flight, and the script
# puts the device back as it was when it exits. It needs sudo -n, tc, ethtool and sch_netem.
#
# With --waits it records where a server spends the time between its requests (design §8 step
# 13j, https://github.com/c4milo/colibri/issues/113), in place of the inputs above. colibri and
# axum serve h2 and h2-tls at `waits_rates`, and 1 s into each load `perf sched record` records the
# server's core for 3 s. `perf sched timehist` then gives each time the server ran: how long it ran,
# how long it waited for the core once woken, and how long it slept before. It needs sudo -n and
# perf.
#
# It runs on Linux, with the server and oha pinned to cores of their own by taskset, as the judge
# runs bench/run.sh (decision 33 as amended). Round 0 is a warm-up that the report discards. A time
# is compared only inside one job (design §11.4). It needs Zig, Go, cargo, Node and npm, curl and
# python3, and BENCH_ZIG_HTTPZ naming the Zig 0.17.0 that builds http.zig. --network and --waits
# need no Node and no BENCH_ZIG_HTTPZ. BENCH_OHA names an oha with h3 built already.
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rounds=5
network=false
waits=false
report="${repository_root}/bench-report.md"
while [ $# -gt 0 ]; do
  case "$1" in
    --rounds) rounds="$2"; shift 2 ;;
    --network) network=true; shift ;;
    --waits) waits=true; shift ;;
    *) report="$1"; shift ;;
  esac
done

# The first port a server listens on. Each start takes the next one: a server that stopped a moment
# before leaves its connections on its port, and a server that binds without SO_REUSEADDR is
# refused it, as axum was on the judge.
readonly first_port=18490
port="$first_port"
# Decision 33 as amended: the server and the load generator each run on cores of their own. On
# its one core colibri's server runs one worker, which holds 32 connections at once
# (`connections_per_worker_max`), so every server gets 32 requests in flight: 32 h11 connections,
# or 8 h2 connections of 4 streams each.
readonly server_core=1
readonly load_cores=2,3
readonly h11_connections=32
readonly h2_connections=8
readonly h2_streams=4
# h3 carries the same 32 requests as h2: 8 QUIC connections of 4 streams each.
readonly h3_connections=8
readonly h3_streams=4
# The rates oha sends at, in requests per second, the seconds of each measurement, and the p99 in
# milliseconds that a server holds at the rates the report counts as sustained. The first judge
# run found colibri and axum sustained at 80,000, so the rates go past it.
rates=(2000 5000 10000 20000 40000 80000 160000 320000)
seconds=5
readonly p99_bound_ms=10
# The requests the script sends, 0.1 s apart, before it gives up on a server that has not started.
readonly ready_tries=100
# oha's release, and the commit its tag names, which cargo builds with its Cargo.lock.
readonly oha_version=v1.16.0
readonly oha_commit=c156bf3d442f5150fb1ad73e8c5144bd882ac4cd
readonly routes="${repository_root}/bench/router/competitors/github_routes.txt"
servers=(colibri chi axum httpz fastify)
protocols=(h11 h2 h2-tls h3)

# The network profiles of --network, as netem arguments, each applied to every packet on the
# loopback device. A packet passes the device once in each direction, so the round trip is twice
# the delay. `rate 10gbit` keeps the packets in order under jitter, as a real link does: without
# it, netem reordered about half of them. `limit` holds every packet in flight.
readonly profiles=(clean far lossy mobile)
profile_arguments() {  # profile_arguments <profile>
  case "$1" in
    clean) echo "" ;;
    far) echo "delay 25ms" ;;
    lossy) echo "delay 25ms loss 1%" ;;
    mobile) echo "delay 50ms 5ms loss 2%" ;;
  esac
}
readonly netem_limit=100000
readonly netem_rate=10gbit
readonly network_mtu=1500
# With a round trip of 100 ms, 32 requests in flight cap a server at 320 req/s, so --network
# keeps 512 in flight: 8 connections of 64 streams, under the 100 streams each server allows.
readonly network_streams=64
readonly network_rates=(1000 2000 4000)
# At 1,000 req/s, 10 s gives p99.9 ten requests to stand on.
readonly network_seconds=10
if [ "$network" = true ]; then
  servers=(colibri chi axum)
  protocols=(h2-tls h3)
  rates=("${network_rates[@]}")
  seconds="$network_seconds"
fi

# --waits: the rate where colibri's p99 over h2-tls lost to axum's, and the one past it where
# colibri's rounds spread (https://github.com/c4milo/colibri/issues/113). The record starts once
# the load has run a second, and it ends a second before the load does.
readonly waits_rates=(40000 80000)
readonly waits_delay_seconds=1
readonly waits_record_seconds=3
if [ "$waits" = true ]; then
  if [ "$network" = true ]; then
    echo "run_latency.sh: --network and --waits are two runs" >&2
    exit 1
  fi
  servers=(colibri axum)
  protocols=(h2 h2-tls)
  rates=("${waits_rates[@]}")
fi
# Whether the run builds and names http.zig and Fastify, which --network and --waits leave out.
every_server=true
if [ "$network" = true ] || [ "$waits" = true ]; then every_server=false; fi

scratch="$(mktemp -d)"
server_pid=""
lo_mtu=""
lo_offloads=()
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ -n "$lo_mtu" ]; then restore_lo; fi
  rm -rf "$scratch"
}
trap cleanup EXIT

# cargo runs in axum's directory, whose rust-toolchain.toml names the Rust release that builds oha.
build_oha() {
  echo "run_latency.sh: building oha ${oha_version} with h3" >&2
  (cd "$repository_root/bench/competitors/axum" &&
    cargo install --quiet --locked --git https://github.com/hatoo/oha --rev "$oha_commit" \
      --features http3 --root "$scratch/oha" oha >&2)
  echo "$scratch/oha/bin/oha"
}

build_servers() {
  echo "run_latency.sh: building the servers" >&2
  (cd "$repository_root" && zig build install -Drelease --prefix "$scratch/colibri" >/dev/null)
  (cd "$repository_root/bench/competitors/chi" && go build -o "$scratch/chi" .)
  (cd "$repository_root/bench/competitors/axum" &&
    cargo build --release --locked --quiet --target-dir "$scratch/axum-target")
  # The identity h3's servers present, and the empty files directory colibri's UDP server takes.
  (cd "$repository_root" && go run tools/h2_interop/tls_identity.go "$scratch/identity")
  mkdir -p "$scratch/www"
  # --network and --waits measure fewer servers.
  if [ "$every_server" = false ]; then return 0; fi
  # From a copy, so the packages that Zig fetches beside build.zig.zon stay out of bench/.
  cp -R "$repository_root/bench/competitors/httpz" "$scratch/httpz-source"
  (cd "$scratch/httpz-source" &&
    "${BENCH_ZIG_HTTPZ:?BENCH_ZIG_HTTPZ names the Zig 0.17.0 that builds http.zig}" build \
      --prefix "$scratch/httpz" --cache-dir "$scratch/httpz-cache" >/dev/null)
  cp -R "$repository_root/bench/competitors/fastify" "$scratch/fastify"
  (cd "$scratch/fastify" && npm ci --silent --no-audit --no-fund >/dev/null)
}

# Whether <server> speaks <protocol>: http.zig has no h2 and no TLS, and h3 is colibri's, chi's
# and axum's.
serves() {  # serves <server> <protocol>
  case "$2" in
    h11) return 0 ;;
    h2 | h2-tls) [ "$1" != httpz ] ;;
    h3) [ "$1" = colibri ] || [ "$1" = chi ] || [ "$1" = axum ] ;;
  esac
}

# The command that starts <server> for <protocol>, into the array `command`. GOMAXPROCS=1 and a
# one-thread runtime keep chi and axum on one thread, as taskset keeps every server on one core.
server_command() {  # server_command <server> <protocol>
  local tls=()
  case "$2" in
    h2-tls) tls=(--tls "$scratch/identity") ;;
    h3) tls=(--h3 --tls "$scratch/identity") ;;
  esac
  case "$1" in
    colibri)
      if [ "$2" = h3 ]; then
        command=("$scratch/colibri/bin/quic-udp" server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" h3 routes=github)
        if [ "$network" = true ]; then command+=(no-gso); fi
      else
        command=("$scratch/colibri/bin/http-server" --port "$port" --routes github "${tls[@]}")
      fi
      ;;
    chi) command=(env GOMAXPROCS=1 QUIC_GO_DISABLE_GSO="$network" "$scratch/chi" --port "$port" --routes "$routes" "${tls[@]}") ;;
    axum)
      command=("$scratch/axum-target/release/colibri-bench-axum" --port "$port" --routes "$routes" "${tls[@]}")
      if [ "$network" = true ] && [ "$2" = h3 ]; then command+=(--no-gso); fi
      ;;
    httpz) command=("$scratch/httpz/bin/colibri-bench-httpz" --port "$port" --routes "$routes") ;;
    fastify)
      command=(node "$scratch/fastify/main.js" --port "$port" --routes "$routes")
      # A Fastify server speaks h11, or h2 alone.
      case "$2" in
        h2) command+=(--h2) ;;
        h2-tls) command+=(--h2 "${tls[@]}") ;;
      esac
      ;;
  esac
}

start_server() {  # start_server <server> <protocol>
  port=$((port + 1))
  local scheme=http
  if [ "$2" = h2-tls ] || [ "$2" = h3 ]; then scheme=https; fi
  sed -E "s#^#${scheme}://127.0.0.1:${port}#" "$scratch/paths.txt" >"$scratch/urls.txt"
  server_command "$1" "$2"
  taskset -c "$server_core" "${command[@]}" >"$scratch/server.log" 2>&1 &
  server_pid=$!
  # curl may speak no h3, so an h3 server is ready once it says it listens: each of the three
  # prints that line once its socket is bound.
  if [ "$2" = h3 ]; then
    for _ in $(seq "$ready_tries"); do
      if grep -q "listening on port" "$scratch/server.log"; then return 0; fi
      sleep 0.1
    done
    echo "run_latency.sh: $1 did not start for $2" >&2
    cat "$scratch/server.log" >&2
    exit 1
  fi
  local probe=(curl -s -o /dev/null --max-time 1)
  case "$2" in
    h2) probe+=(--http2-prior-knowledge) ;;
    # The servers present a test identity, which the probe does not verify.
    h2-tls) probe+=(--http2 --insecure) ;;
  esac
  for _ in $(seq "$ready_tries"); do
    if "${probe[@]}" "${scheme}://127.0.0.1:${port}/events"; then return 0; fi
    sleep 0.1
  done
  echo "run_latency.sh: $1 did not start for $2" >&2
  cat "$scratch/server.log" >&2
  exit 1
}

stop_server() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
}

# oha's load at <rate> for <protocol>, into <out>, as JSON.
load() {  # load <protocol> <rate> <out>
  local shape=(-c "$h11_connections")
  local h2_parallel="$h2_streams" h3_parallel="$h3_streams"
  if [ "$network" = true ]; then h2_parallel="$network_streams" h3_parallel="$network_streams"; fi
  case "$1" in
    h2) shape=(--http2 -c "$h2_connections" -p "$h2_parallel") ;;
    h2-tls) shape=(--http2 --insecure -c "$h2_connections" -p "$h2_parallel") ;;
    # The servers present a test identity, which oha does not verify.
    h3) shape=(--http-version 3 --insecure -c "$h3_connections" -p "$h3_parallel") ;;
  esac
  taskset -c "$load_cores" "$oha" --no-tui --urls-from-file "$scratch/urls.txt" -z "${seconds}s" \
    -q "$2" --latency-correction "${shape[@]}" --output-format json >"$3"
}

machine() {
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -sr)"
  echo "cpu=$(sed -n 's/^model name\t*: //p;s/^CPU part\t*: //p' /proc/cpuinfo 2>/dev/null | sort -u | paste -sd ' ' -)"
  echo "colibri=$(git -C "$repository_root" rev-parse --short HEAD), zig $(zig version)"
  echo "chi=$(sed -n 's|.*go-chi/chi/v5 \(v[0-9.]*\).*|\1|p' "$repository_root/bench/competitors/chi/go.mod" | head -1), $(go version | cut -d' ' -f3)"
  echo "axum=$(awk '$0 == "name = \"axum\"" { getline; gsub(/version = |"/, ""); print; exit }' "$repository_root/bench/competitors/axum/Cargo.lock"), $(cd "$repository_root/bench/competitors/axum" && rustc --version)"
  if [ "$every_server" = true ]; then
    echo "http.zig=$(sed -n 's|.*karlseguin/http.zig#\([0-9a-f]*\).*|\1|p' "$repository_root/bench/competitors/httpz/build.zig.zon" | head -1), zig $("$BENCH_ZIG_HTTPZ" version)"
    echo "fastify=$(sed -n 's/.*"fastify": "\(.*\)".*/\1/p' "$repository_root/bench/competitors/fastify/package.json"), node $(node --version)"
  fi
  echo "quic-go=$(sed -n 's|.*quic-go/quic-go \(v[0-9.]*\).*|\1|p' "$repository_root/bench/competitors/chi/go.mod" | head -1)"
  echo "h3=$(awk '$0 == "name = \"h3\"" { getline; gsub(/version = |"/, ""); print; exit }' "$repository_root/bench/competitors/axum/Cargo.lock"), quinn $(awk '$0 == "name = \"quinn\"" { getline; gsub(/version = |"/, ""); print; exit }' "$repository_root/bench/competitors/axum/Cargo.lock")"
  echo "oha=${oha_version} ${oha_commit}, with h3"
  echo "rounds=$rounds seconds=$seconds p99_bound_ms=$p99_bound_ms"
  if [ "$network" = false ]; then
    echo "load=h11 ${h11_connections} connections, h2 and h2-tls ${h2_connections} connections of ${h2_streams} streams, h3 ${h3_connections} connections of ${h3_streams} streams"
  fi
  if [ "$network" = true ]; then
    echo "load=h2-tls and h3 ${h2_connections} connections of ${network_streams} streams"
    echo "path=loopback, 127.0.0.1, MTU ${network_mtu}, TSO, GSO and GRO off, no GSO in the h3 servers"
    for profile in "${profiles[@]}"; do
      echo "profile ${profile}=netem limit ${netem_limit} $(profile_arguments "$profile") rate ${netem_rate}"
    done
  else
    echo "path=loopback, 127.0.0.1"
  fi
  if [ "$waits" = true ]; then
    echo "waits=perf sched record of core ${server_core} for ${waits_record_seconds} s, ${waits_delay_seconds} s into each load, $(sudo -n perf --version)"
  fi
}

# oha's load at <rate> for <protocol>, into <out>.json, with the server's runs on its core recorded
# into <out>.waits: the lines of `perf sched timehist` for the server's process.
load_with_waits() {  # load_with_waits <protocol> <rate> <out>
  load "$1" "$2" "$3.json" &
  local load_pid=$!
  sleep "$waits_delay_seconds"
  sudo -n perf sched record -C "$server_core" -o "$3.data" -- sleep "$waits_record_seconds" >/dev/null 2>&1
  wait "$load_pid"
  sudo -n perf sched timehist -i "$3.data" --pid "$server_pid" >"$3.waits" 2>/dev/null
  sudo -n rm -f "$3.data"
}

# Makes the loopback device a path netem drops single packets on: an MTU of 1500, and no TCP
# segmentation or receive coalescing, so that each packet is one unit netem keeps or drops.
prepare_lo() {
  for tool in tc ethtool; do
    if ! command -v "$tool" >/dev/null; then
      echo "run_latency.sh: --network needs $tool" >&2
      exit 1
    fi
  done
  sudo -n modprobe sch_netem 2>/dev/null || true
  lo_mtu="$(cat /sys/class/net/lo/mtu)"
  # The state of each offload before, as the words `ethtool -K` takes back.
  local feature
  for feature in tcp-segmentation-offload generic-segmentation-offload generic-receive-offload; do
    lo_offloads+=("$(ethtool -k lo | sed -n "s/^${feature}: \(on\|off\).*/\1/p")")
  done
  sudo -n ip link set dev lo mtu "$network_mtu"
  sudo -n ethtool -K lo tso off gso off gro off >/dev/null
}

restore_lo() {
  sudo -n tc qdisc del dev lo root 2>/dev/null || true
  sudo -n ethtool -K lo tso "${lo_offloads[0]}" gso "${lo_offloads[1]}" gro "${lo_offloads[2]}" >/dev/null 2>&1 || true
  sudo -n ip link set dev lo mtu "$lo_mtu" || true
  lo_mtu=""
}

# Puts <profile>'s netem on the loopback device, in place of the one before it.
apply_profile() {  # apply_profile <profile>
  sudo -n tc qdisc del dev lo root 2>/dev/null || true
  local arguments
  arguments="$(profile_arguments "$1")"
  if [ -z "$arguments" ]; then return 0; fi
  # shellcheck disable=SC2086 # The profile's arguments are words for tc.
  if ! sudo -n tc qdisc add dev lo root netem limit "$netem_limit" $arguments rate "$netem_rate"; then
    echo "run_latency.sh: netem did not start; --network needs sch_netem" >&2
    exit 1
  fi
}

oha="${BENCH_OHA:-}"
if [ -z "$oha" ]; then oha="$(build_oha)"; fi
# set -e does not stop the script inside a command substitution, so a failed build shows here.
if [ ! -x "$oha" ]; then
  echo "run_latency.sh: no oha at $oha" >&2
  exit 1
fi
build_servers
# The GET routes, with each parameter given a value, as the paths oha sends to each server's port.
awk '$1 == "GET" { print $2 }' "$routes" | sed -E "s#:[a-z_]+#v1#g" >"$scratch/paths.txt"
machine >"$scratch/machine.txt"
if [ "$network" = true ]; then prepare_lo; fi
if [ "$waits" = true ] && ! sudo -n perf --version >/dev/null 2>&1; then
  echo "run_latency.sh: --waits needs perf through sudo -n" >&2
  exit 1
fi

# In each round the servers take turns, each through every rate of a protocol. Their list starts
# one place later each round, so in n rounds that follow one another, each of n servers goes
# first once.
# One round of every protocol, its servers in turns, into runs/<round>/<label>/: the protocol, or
# under --network the protocol and the profile, as h3@lossy.
measure_round() {  # measure_round <round> <label suffix>
  local round="$1" suffix="$2"
  for protocol in "${protocols[@]}"; do
    serving=()
    for server in "${servers[@]}"; do
      if serves "$server" "$protocol"; then serving+=("$server"); fi
    done
    for ((place = 0; place < ${#serving[@]}; place++)); do
      server="${serving[(round + place) % ${#serving[@]}]}"
      echo "run_latency.sh: round $round, $protocol$suffix, $server" >&2
      start_server "$server" "$protocol"
      mkdir -p "$scratch/runs/$round/$protocol$suffix/$server"
      for rate in "${rates[@]}"; do
        local out="$scratch/runs/$round/$protocol$suffix/$server/$rate"
        if [ "$waits" = true ]; then load_with_waits "$protocol" "$rate" "$out"; else load "$protocol" "$rate" "$out.json"; fi
      done
      stop_server
    done
  done
}

for round in $(seq 0 "$rounds"); do
  if [ "$network" = false ]; then
    measure_round "$round" ""
    continue
  fi
  for profile in "${profiles[@]}"; do
    apply_profile "$profile"
    measure_round "$round" "@$profile"
  done
done

report_arguments=(--p99-bound-ms "$p99_bound_ms")
if [ "$network" = true ]; then report_arguments=(--network); fi
if [ "$waits" = true ]; then report_arguments=(--waits); fi
python3 "$repository_root/bench/report_latency.py" "$scratch" "$report" "${report_arguments[@]}"
