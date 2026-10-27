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
#   bench/run_latency.sh [--rounds <n>] [report.md]
#
# It runs on Linux, with the server and oha pinned to cores of their own by taskset, as the judge
# runs bench/run.sh (decision 33 as amended). Round 0 is a warm-up that the report discards. A time
# is compared only inside one job (design §11.4). It needs Zig, Go, cargo, Node and npm, curl and
# python3, and BENCH_ZIG_HTTPZ naming the Zig 0.17.0 that builds http.zig. BENCH_OHA names an oha
# with h3 built already.
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rounds=5
report="${repository_root}/bench-report.md"
while [ $# -gt 0 ]; do
  case "$1" in
    --rounds) rounds="$2"; shift 2 ;;
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
readonly rates=(2000 5000 10000 20000 40000 80000 160000 320000)
readonly seconds=5
readonly p99_bound_ms=10
# The requests the script sends, 0.1 s apart, before it gives up on a server that has not started.
readonly ready_tries=100
# oha's release, and the commit its tag names, which cargo builds with its Cargo.lock.
readonly oha_version=v1.16.0
readonly oha_commit=c156bf3d442f5150fb1ad73e8c5144bd882ac4cd
readonly routes="${repository_root}/bench/router/competitors/github_routes.txt"
readonly servers=(colibri chi axum httpz fastify)
readonly protocols=(h11 h2 h2-tls h3)

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
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
  # From a copy, so the packages that Zig fetches beside build.zig.zon stay out of bench/.
  cp -R "$repository_root/bench/competitors/httpz" "$scratch/httpz-source"
  (cd "$scratch/httpz-source" &&
    "${BENCH_ZIG_HTTPZ:?BENCH_ZIG_HTTPZ names the Zig 0.17.0 that builds http.zig}" build \
      --prefix "$scratch/httpz" --cache-dir "$scratch/httpz-cache" >/dev/null)
  # The identity h3's servers present, and the empty files directory colibri's UDP server takes.
  (cd "$repository_root" && go run tools/h2_interop/tls_identity.go "$scratch/identity")
  mkdir -p "$scratch/www"
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
      else
        command=("$scratch/colibri/bin/http-server" --port "$port" --routes github "${tls[@]}")
      fi
      ;;
    chi) command=(env GOMAXPROCS=1 "$scratch/chi" --port "$port" --routes "$routes" "${tls[@]}") ;;
    axum) command=("$scratch/axum-target/release/colibri-bench-axum" --port "$port" --routes "$routes" "${tls[@]}") ;;
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
  case "$1" in
    h2) shape=(--http2 -c "$h2_connections" -p "$h2_streams") ;;
    h2-tls) shape=(--http2 --insecure -c "$h2_connections" -p "$h2_streams") ;;
    # The servers present a test identity, which oha does not verify.
    h3) shape=(--http-version 3 --insecure -c "$h3_connections" -p "$h3_streams") ;;
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
  echo "http.zig=$(sed -n 's|.*karlseguin/http.zig#\([0-9a-f]*\).*|\1|p' "$repository_root/bench/competitors/httpz/build.zig.zon" | head -1), zig $("$BENCH_ZIG_HTTPZ" version)"
  echo "fastify=$(sed -n 's/.*"fastify": "\(.*\)".*/\1/p' "$repository_root/bench/competitors/fastify/package.json"), node $(node --version)"
  echo "quic-go=$(sed -n 's|.*quic-go/quic-go \(v[0-9.]*\).*|\1|p' "$repository_root/bench/competitors/chi/go.mod" | head -1)"
  echo "h3=$(awk '$0 == "name = \"h3\"" { getline; gsub(/version = |"/, ""); print; exit }' "$repository_root/bench/competitors/axum/Cargo.lock"), quinn $(awk '$0 == "name = \"quinn\"" { getline; gsub(/version = |"/, ""); print; exit }' "$repository_root/bench/competitors/axum/Cargo.lock")"
  echo "oha=${oha_version} ${oha_commit}, with h3"
  echo "rounds=$rounds seconds=$seconds p99_bound_ms=$p99_bound_ms"
  echo "load=h11 ${h11_connections} connections, h2 and h2-tls ${h2_connections} connections of ${h2_streams} streams, h3 ${h3_connections} connections of ${h3_streams} streams"
  echo "path=loopback, 127.0.0.1"
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

# In each round the servers take turns, each through every rate of a protocol. Their list starts
# one place later each round, so in n rounds that follow one another, each of n servers goes
# first once.
for round in $(seq 0 "$rounds"); do
  for protocol in "${protocols[@]}"; do
    serving=()
    for server in "${servers[@]}"; do
      if serves "$server" "$protocol"; then serving+=("$server"); fi
    done
    for ((place = 0; place < ${#serving[@]}; place++)); do
      server="${serving[(round + place) % ${#serving[@]}]}"
      echo "run_latency.sh: round $round, $protocol, $server" >&2
      start_server "$server" "$protocol"
      mkdir -p "$scratch/runs/$round/$protocol/$server"
      for rate in "${rates[@]}"; do
        load "$protocol" "$rate" "$scratch/runs/$round/$protocol/$server/$rate.json"
      done
      stop_server
    done
  done
done

python3 "$repository_root/bench/report_latency.py" "$scratch" "$report" --p99-bound-ms "$p99_bound_ms"
