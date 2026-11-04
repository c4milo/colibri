#!/usr/bin/env bash
#
# The bulk input of design §8 step 13k (decision 136), which `bench/run.sh --latency --bulk` runs:
# downloads of one file at a bottleneck, where the congestion controller sets the rate. The loads
# of step 13i keep each connection's window at its first value, so they cannot tell two
# controllers apart.
#
#   bench/run_bulk.sh [--rounds <n>] [report.md]
#
# Each server serves the files of one directory: colibri's UDP server in its `h3` mode, under CUBIC
# and, as `colibri-bbr`, under BBRv3 (design §8 step 29c), as `colibri-newreno` under RFC 9002's
# NewReno (design §8 step 34), chi and axum with --www, and ngtcp2's
# server under its own BBRv3, from its QUIC Interop Runner image (design §8 step 29d). oha
# downloads `bulk_file` again and again for `seconds`, over h3 from each of the six, and over
# h2-tls from chi and axum, whose TCP is the kernel's, as the baseline. It runs from
# 1 and then from 4 connections, one download at a time on each. A second oha sends a GET of a
# small file each 100 ms on a connection of its own, and its latency is the delay the queue adds.
#
# tc puts a prio qdisc on the loopback device, with a netem below each of its two bands. The
# packets the server sends go through the first band, which holds the bottleneck: the delay, the
# rate and a queue of `queue_packets`. Every other packet goes through the second, which holds the
# delay alone, so the peer's acknowledgments wait in no queue behind the data, as on a real path.
# The device's MTU becomes 1500 and its TCP offloads turn off, so netem drops one packet at a time,
# and each h3 server sends each datagram in a send of its own (design §8 step 13i).
#
# A load over h3 takes about 30 s more than `seconds`: oha drops the downloads the end of the load
# cuts, and then holds their connections until its idle timeout. A round takes about 24 minutes.
#
# Each round then runs `h3-shared`, which decision 136 asks for: colibri under CUBIC and under BBRv3
# at once, each serving its own downloads through the one bottleneck, so the report can give the
# share each controller takes. Each server has its own probe of small GETs. It adds about 4 minutes
# a round.
#
# It runs on Linux, with the server and oha pinned to cores of their own by taskset (decision 33 as
# amended). Round 0 is a warm-up that the report discards. It needs sudo -n, tc, ethtool,
# sch_netem, Zig, Go, cargo, curl, Docker and python3. BENCH_OHA names an oha with h3 built
# already. BENCH_BULK_QLOG names a directory: colibri's servers then write each connection's qlog
# into <directory>/<round>/<protocol>@<profile>/<server>, to find where their goodput goes
# (https://github.com/c4milo/colibri/issues/123). A load that logs costs the server more, so no
# report publishes its numbers.
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

# The directory each colibri server's qlog goes in, or empty for none, and the part of its path
# the loop sets: <round>/<protocol>@<profile>.
qlog_root="${BENCH_BULK_QLOG:-}"
if [ -n "$qlog_root" ]; then qlog_root="$(mkdir -p "$qlog_root" && cd "$qlog_root" && pwd)"; fi
qlog_run=""

# Each start takes the next port, as in bench/run_latency.sh.
port=18590
readonly server_core=1
# The second server of `h3-shared`, which runs beside the first. The judge has 4 cores, and at
# 20 Mbit/s neither server needs a whole one, so it takes the core the script runs on.
readonly pair_core=0
readonly load_cores=2,3
# The two servers that share the bottleneck: colibri under CUBIC and under BBRv3.
readonly shared_servers=(colibri colibri-bbr)
pair_pids=()
readonly ready_tries=100
readonly oha_version=v1.16.0
readonly oha_commit=c156bf3d442f5150fb1ad73e8c5144bd882ac4cd
readonly servers=(colibri colibri-bbr colibri-newreno chi axum ngtcp2)
# ngtcp2's image for the QUIC Interop Runner, pinned by digest: a second BBRv3, which the report
# sets beside colibri's. Its label names the commit it was built from.
readonly ngtcp2_image="ghcr.io/ngtcp2/ngtcp2-interop@sha256:fa6bf697aaa6badf64d57ff87fb9296c0d50c2e054a09ab54cdbe02ba598c865"
server_container=""
readonly protocols=(h3 h2-tls)
readonly connection_counts=(1 4)
# 2 MiB takes 0.84 s at 20 Mbit/s, so one connection downloads it about 35 times in 30 s, and
# each of 4 connections about 9 times.
readonly bulk_file=bulk
readonly bulk_len=2097152
readonly small_file=small
readonly seconds=30
readonly probe_rate=10
# The GETs the probe holds open at once, so a GET that waits in the queue holds no later one back.
readonly probe_parallel=16

# The profiles: the bottleneck's netem arguments, and the netem arguments of every other packet.
# The path holds 20 Mbit/s for a round trip of 50 ms, about 125,000 octets, and the queue holds
# 1,000 packets, about 12 times that. `rate 10gbit` keeps the second band's packets in order
# under its delay, as in step 13i.
readonly profiles=(bottleneck bottleneck-lossy)
readonly delay=25ms
readonly bottleneck_rate=20mbit
readonly queue_packets=1000
readonly other_rate=10gbit
readonly other_limit=100000
readonly network_mtu=1500
profile_loss() {  # profile_loss <profile>
  case "$1" in
    bottleneck) echo "" ;;
    bottleneck-lossy) echo "loss 1%" ;;
  esac
}

scratch="$(mktemp -d)"
server_pid=""
lo_mtu=""
lo_offloads=()
cleanup() {
  if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
  if [ -n "$server_container" ]; then docker rm -f "$server_container" >/dev/null 2>&1 || true; fi
  for pid in "${pair_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [ -n "$lo_mtu" ]; then restore_lo; fi
  rm -rf "$scratch"
}
trap cleanup EXIT

# cargo runs in axum's directory, whose rust-toolchain.toml names the Rust release that builds oha.
build_oha() {
  echo "run_bulk.sh: building oha ${oha_version} with h3" >&2
  (cd "$repository_root/bench/competitors/axum" &&
    cargo install --quiet --locked --git https://github.com/hatoo/oha --rev "$oha_commit" \
      --features http3 --root "$scratch/oha" oha >&2)
  echo "$scratch/oha/bin/oha"
}

build_servers() {
  echo "run_bulk.sh: building the servers" >&2
  (cd "$repository_root" && zig build install -Drelease --prefix "$scratch/colibri" >/dev/null)
  (cd "$repository_root/bench/competitors/chi" && go build -o "$scratch/chi" .)
  (cd "$repository_root/bench/competitors/axum" &&
    cargo build --release --locked --quiet --target-dir "$scratch/axum-target")
  (cd "$repository_root" && go run tools/h2_interop/tls_identity.go "$scratch/identity")
  docker pull -q "$ngtcp2_image" >/dev/null
  mkdir -p "$scratch/www"
  head -c "$bulk_len" /dev/zero >"$scratch/www/$bulk_file"
  printf 'ok\n' >"$scratch/www/$small_file"
}

# Whether <server> serves <protocol>: h2-tls is the kernel's TCP, which chi and axum measure.
serves() {  # serves <server> <protocol>
  [ "$2" = h3 ] || [[ "$1" != colibri* && "$1" != ngtcp2 ]]
}

# The command that starts <server> for <protocol>, into the array `command`, each with one thread
# and with no GSO, as bench/run_latency.sh --network starts them.
server_command() {  # server_command <server> <protocol>
  local tls=(--tls "$scratch/identity")
  local qlog=()
  if [ -n "$qlog_root" ]; then
    mkdir -p "$qlog_root/$qlog_run/$1"
    qlog=("qlogdir=$qlog_root/$qlog_run/$1")
  fi
  if [ "$2" = h3 ]; then tls=(--h3 --tls "$scratch/identity"); fi
  case "$1" in
    colibri) command=("$scratch/colibri/bin/quic-udp" server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" h3 no-gso "${qlog[@]}") ;;
    colibri-bbr) command=("$scratch/colibri/bin/quic-udp" server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" h3 no-gso bbr "${qlog[@]}") ;;
    colibri-newreno) command=("$scratch/colibri/bin/quic-udp" server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" h3 no-gso newreno "${qlog[@]}") ;;
    chi) command=(env GOMAXPROCS=1 QUIC_GO_DISABLE_GSO=true "$scratch/chi" --port "$port" --www "$scratch/www" "${tls[@]}") ;;
    axum)
      command=("$scratch/axum-target/release/colibri-bench-axum" --port "$port" --www "$scratch/www" "${tls[@]}")
      if [ "$2" = h3 ]; then command+=(--no-gso); fi
      ;;
  esac
}

# Starts ngtcp2's server in a container on the host's network, pinned to the server's core, with
# the identity and the files copied in, under BBRv3 and with no GSO. Its log names no port, so it
# is ready once its UDP socket is bound.
start_container() {
  server_container="colibri-bulk-ngtcp2-$$"
  docker create --name "$server_container" --network host --cpuset-cpus "$server_core" \
    --entrypoint /usr/local/bin/wsslserver "$ngtcp2_image" 127.0.0.1 "$port" \
    /identity/key.pem /identity/chain.pem -q -d /www --cc bbr --no-gso >/dev/null
  # docker cp makes the directory it copies a directory into, and not the one of a single file.
  mkdir -p "$scratch/ngtcp2-identity"
  cp "$scratch/identity.key.pem" "$scratch/ngtcp2-identity/key.pem"
  cp "$scratch/identity.chain.pem" "$scratch/ngtcp2-identity/chain.pem"
  docker cp -q "$scratch/ngtcp2-identity/." "$server_container:/identity"
  docker cp -q "$scratch/www/." "$server_container:/www"
  docker start "$server_container" >/dev/null
  for _ in $(seq "$ready_tries"); do
    if [ -n "$(ss -Hlun "sport = :$port")" ]; then return 0; fi
    sleep 0.1
  done
  echo "run_bulk.sh: ngtcp2 did not start" >&2
  docker logs "$server_container" >&2
  exit 1
}

start_server() {  # start_server <server> <protocol>
  port=$((port + 1))
  if [ "$1" = ngtcp2 ]; then start_container; return; fi
  server_command "$1" "$2"
  taskset -c "$server_core" "${command[@]}" >"$scratch/server.log" 2>&1 &
  server_pid=$!
  for _ in $(seq "$ready_tries"); do
    if [ "$2" = h3 ] && grep -q "listening on port" "$scratch/server.log"; then return 0; fi
    if [ "$2" = h2-tls ] && curl -s -o /dev/null --max-time 1 --http2 --insecure "https://127.0.0.1:${port}/${small_file}"; then
      return 0
    fi
    sleep 0.1
  done
  echo "run_bulk.sh: $1 did not start for $2" >&2
  cat "$scratch/server.log" >&2
  exit 1
}

stop_server() {
  if [ -n "$server_container" ]; then
    docker rm -f "$server_container" >/dev/null
    server_container=""
    return
  fi
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=""
}

# The words that make oha speak <protocol>. The servers present a test identity, which oha does
# not verify.
oha_protocol() {  # oha_protocol <protocol>
  case "$1" in
    h3) echo "--http-version 3 --insecure" ;;
    h2-tls) echo "--http2 --insecure" ;;
  esac
}

# The downloads from <connections> connections into <out>.json, and the small GETs beside them
# into <out>.probe.json, from the server on <port>, which is `port` when it is not given.
load() {  # load <protocol> <connections> <out> [port]
  local words
  local to="${4:-$port}"
  read -r -a words <<<"$(oha_protocol "$1")"
  taskset -c "$load_cores" "$oha" --no-tui -z "${seconds}s" -q "$probe_rate" --latency-correction \
    -c 1 -p "$probe_parallel" "${words[@]}" --output-format json "https://127.0.0.1:${to}/${small_file}" >"$3.probe.json" &
  local probe_pid=$!
  taskset -c "$load_cores" "$oha" --no-tui -z "${seconds}s" -c "$2" -p 1 "${words[@]}" \
    --output-format json "https://127.0.0.1:${to}/${bulk_file}" >"$3.json"
  wait "$probe_pid"
}

# Makes the loopback device a path netem drops single packets on, as bench/run_latency.sh does.
prepare_lo() {
  for tool in tc ethtool; do
    if ! command -v "$tool" >/dev/null; then
      echo "run_bulk.sh: it needs $tool" >&2
      exit 1
    fi
  done
  sudo -n modprobe sch_netem 2>/dev/null || true
  lo_mtu="$(cat /sys/class/net/lo/mtu)"
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

# Puts <profile> on the loopback device for the server on `port`, or on each of <ports> when given:
# their packets, TCP or UDP, take band 1:1 by their source port, and every other packet takes band
# 1:2. Servers given together share band 1:1's queue and rate.
apply_profile() {  # apply_profile <profile> [ports...]
  local loss
  local profile="$1"
  shift
  local ports=("$@")
  if [ ${#ports[@]} -eq 0 ]; then ports=("$port"); fi
  read -r -a loss <<<"$(profile_loss "$profile")"
  sudo -n tc qdisc del dev lo root 2>/dev/null || true
  if ! sudo -n tc qdisc add dev lo root handle 1: prio bands 2 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 ||
    ! sudo -n tc qdisc add dev lo parent 1:1 handle 10: netem limit "$queue_packets" delay "$delay" \
      "${loss[@]}" rate "$bottleneck_rate" ||
    ! sudo -n tc qdisc add dev lo parent 1:2 handle 20: netem limit "$other_limit" delay "$delay" \
      "${loss[@]}" rate "$other_rate"; then
    echo "run_bulk.sh: tc did not take the profile $profile; it needs sch_prio and sch_netem" >&2
    exit 1
  fi
  local each
  for each in "${ports[@]}"; do
    if ! sudo -n tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip sport "$each" 0xffff flowid 1:1; then
      echo "run_bulk.sh: tc did not take the filter of port $each" >&2
      exit 1
    fi
  done
}

# Starts <first> and <second> for h3 on two ports, each pinned to a core of its own, into
# `pair_ports` and `pair_pids`.
start_pair() {  # start_pair <first> <second>
  pair_ports=()
  pair_pids=()
  local cores=("$server_core" "$pair_core")
  local index
  for index in 0 1; do
    local server=("$1" "$2")
    port=$((port + 1))
    server_command "${server[$index]}" h3
    taskset -c "${cores[$index]}" "${command[@]}" >"$scratch/server.$index.log" 2>&1 &
    pair_pids+=($!)
    pair_ports+=("$port")
    local ready=false
    for _ in $(seq "$ready_tries"); do
      if grep -q "listening on port" "$scratch/server.$index.log"; then ready=true; break; fi
      sleep 0.1
    done
    if [ "$ready" = false ]; then
      echo "run_bulk.sh: ${server[$index]} did not start for h3-shared" >&2
      cat "$scratch/server.$index.log" >&2
      exit 1
    fi
  done
}

stop_pair() {
  local pid
  for pid in "${pair_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  pair_pids=()
}

machine() {
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -sr)"
  echo "cpu=$(sed -n 's/^model name\t*: //p;s/^CPU part\t*: //p' /proc/cpuinfo 2>/dev/null | sort -u | paste -sd ' ' -)"
  echo "colibri=$(git -C "$repository_root" rev-parse --short HEAD), zig $(zig version)"
  echo "chi=$(sed -n 's|.*go-chi/chi/v5 \(v[0-9.]*\).*|\1|p' "$repository_root/bench/competitors/chi/go.mod" | head -1), $(go version | cut -d' ' -f3)"
  echo "quic-go=$(sed -n 's|.*quic-go/quic-go \(v[0-9.]*\).*|\1|p' "$repository_root/bench/competitors/chi/go.mod" | head -1)"
  echo "quinn=$(awk '$0 == "name = \"quinn\"" { getline; gsub(/version = |"/, ""); print; exit }' "$repository_root/bench/competitors/axum/Cargo.lock")"
  echo "ngtcp2=commit $(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$ngtcp2_image"), --cc bbr, $ngtcp2_image"
  echo "oha=${oha_version} ${oha_commit}, with h3"
  echo "rounds=$rounds seconds=$seconds file=$bulk_len octets probe=$probe_rate GET/s"
  echo "path=loopback, 127.0.0.1, MTU ${network_mtu}, TSO, GSO and GRO off, no GSO in the h3 servers"
  for profile in "${profiles[@]}"; do
    echo "profile ${profile}=the server's packets netem limit ${queue_packets} delay ${delay} $(profile_loss "$profile") rate ${bottleneck_rate}; others netem delay ${delay} $(profile_loss "$profile") rate ${other_rate}"
  done
}

oha="${BENCH_OHA:-}"
if [ -z "$oha" ]; then oha="$(build_oha)"; fi
if [ ! -x "$oha" ]; then
  echo "run_bulk.sh: no oha at $oha" >&2
  exit 1
fi
build_servers
machine >"$scratch/machine.txt"
prepare_lo

# In each round the servers take turns, their list starting one place later each round, as in
# bench/run_latency.sh, into runs/<round>/<protocol>@<profile>/<server>/<connections>.
for round in $(seq 0 "$rounds"); do
  for profile in "${profiles[@]}"; do
    for protocol in "${protocols[@]}"; do
      serving=()
      for server in "${servers[@]}"; do
        if serves "$server" "$protocol"; then serving+=("$server"); fi
      done
      for ((place = 0; place < ${#serving[@]}; place++)); do
        server="${serving[(round + place) % ${#serving[@]}]}"
        echo "run_bulk.sh: round $round, $protocol@$profile, $server" >&2
        qlog_run="$round/$protocol@$profile"
        start_server "$server" "$protocol"
        apply_profile "$profile"
        mkdir -p "$scratch/runs/$round/$protocol@$profile/$server"
        for connections in "${connection_counts[@]}"; do
          load "$protocol" "$connections" "$scratch/runs/$round/$protocol@$profile/$server/$connections"
        done
        stop_server
      done
    done
    # Both controllers at once through the one bottleneck, each loaded by its own oha.
    echo "run_bulk.sh: round $round, h3-shared@$profile" >&2
    qlog_run="$round/h3-shared@$profile"
    start_pair "${shared_servers[@]}"
    apply_profile "$profile" "${pair_ports[@]}"
    for connections in "${connection_counts[@]}"; do
      loads=()
      for index in 0 1; do
        mkdir -p "$scratch/runs/$round/h3-shared@$profile/${shared_servers[$index]}"
        load h3 "$connections" "$scratch/runs/$round/h3-shared@$profile/${shared_servers[$index]}/$connections" "${pair_ports[$index]}" &
        loads+=($!)
      done
      # The servers run in the background too, so the wait names the two loads.
      wait "${loads[@]}"
    done
    stop_pair
  done
done

python3 "$repository_root/bench/report_bulk.py" "$scratch" "$report" --file-len "$bulk_len" --seconds "$seconds"
