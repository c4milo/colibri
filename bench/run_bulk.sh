#!/usr/bin/env bash
#
# The bulk input of design §8 step 13k (decision 136), which `bench/run.sh --latency --bulk` runs:
# downloads of one file at a bottleneck, where the congestion controller sets the rate. The loads
# of step 13i keep each connection's window at its first value, so they cannot tell two
# controllers apart.
#
#   bench/run_bulk.sh [--rounds <n>] [report.md]
#
# Each server serves the files of one directory: colibri's UDP server in its `h3` mode, and chi and
# axum with --www. oha downloads `bulk_file` again and again for `seconds`, over h3 from each of the
# three, and over h2-tls from chi and axum, whose TCP is the kernel's, as the baseline. It runs from
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
# cuts, and then holds their connections until its idle timeout. A round takes about 16 minutes.
#
# It runs on Linux, with the server and oha pinned to cores of their own by taskset (decision 33 as
# amended). Round 0 is a warm-up that the report discards. It needs sudo -n, tc, ethtool,
# sch_netem, Zig, Go, cargo, curl and python3. BENCH_OHA names an oha with h3 built already.
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

# Each start takes the next port, as in bench/run_latency.sh.
port=18590
readonly server_core=1
readonly load_cores=2,3
readonly ready_tries=100
readonly oha_version=v1.16.0
readonly oha_commit=c156bf3d442f5150fb1ad73e8c5144bd882ac4cd
readonly servers=(colibri chi axum)
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
  mkdir -p "$scratch/www"
  head -c "$bulk_len" /dev/zero >"$scratch/www/$bulk_file"
  printf 'ok\n' >"$scratch/www/$small_file"
}

# Whether <server> serves <protocol>: h2-tls is the kernel's TCP, which chi and axum measure.
serves() {  # serves <server> <protocol>
  [ "$2" = h3 ] || [ "$1" != colibri ]
}

# The command that starts <server> for <protocol>, into the array `command`, each with one thread
# and with no GSO, as bench/run_latency.sh --network starts them.
server_command() {  # server_command <server> <protocol>
  local tls=(--tls "$scratch/identity")
  if [ "$2" = h3 ]; then tls=(--h3 --tls "$scratch/identity"); fi
  case "$1" in
    colibri) command=("$scratch/colibri/bin/quic-udp" server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" h3 no-gso) ;;
    chi) command=(env GOMAXPROCS=1 QUIC_GO_DISABLE_GSO=true "$scratch/chi" --port "$port" --www "$scratch/www" "${tls[@]}") ;;
    axum)
      command=("$scratch/axum-target/release/colibri-bench-axum" --port "$port" --www "$scratch/www" "${tls[@]}")
      if [ "$2" = h3 ]; then command+=(--no-gso); fi
      ;;
  esac
}

start_server() {  # start_server <server> <protocol>
  port=$((port + 1))
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
# into <out>.probe.json.
load() {  # load <protocol> <connections> <out>
  local words
  read -r -a words <<<"$(oha_protocol "$1")"
  taskset -c "$load_cores" "$oha" --no-tui -z "${seconds}s" -q "$probe_rate" --latency-correction \
    -c 1 -p "$probe_parallel" "${words[@]}" --output-format json "https://127.0.0.1:${port}/${small_file}" >"$3.probe.json" &
  local probe_pid=$!
  taskset -c "$load_cores" "$oha" --no-tui -z "${seconds}s" -c "$2" -p 1 "${words[@]}" \
    --output-format json "https://127.0.0.1:${port}/${bulk_file}" >"$3.json"
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

# Puts <profile> on the loopback device for the server on `port`: its packets, TCP or UDP, take
# band 1:1 by their source port, and every other packet takes band 1:2.
apply_profile() {  # apply_profile <profile>
  local loss
  read -r -a loss <<<"$(profile_loss "$1")"
  sudo -n tc qdisc del dev lo root 2>/dev/null || true
  if ! sudo -n tc qdisc add dev lo root handle 1: prio bands 2 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 ||
    ! sudo -n tc qdisc add dev lo parent 1:1 handle 10: netem limit "$queue_packets" delay "$delay" \
      "${loss[@]}" rate "$bottleneck_rate" ||
    ! sudo -n tc qdisc add dev lo parent 1:2 handle 20: netem limit "$other_limit" delay "$delay" \
      "${loss[@]}" rate "$other_rate" ||
    ! sudo -n tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip sport "$port" 0xffff flowid 1:1; then
    echo "run_bulk.sh: tc did not take the profile $1; it needs sch_prio and sch_netem" >&2
    exit 1
  fi
}

machine() {
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -sr)"
  echo "cpu=$(sed -n 's/^model name\t*: //p;s/^CPU part\t*: //p' /proc/cpuinfo 2>/dev/null | sort -u | paste -sd ' ' -)"
  echo "colibri=$(git -C "$repository_root" rev-parse --short HEAD), zig $(zig version)"
  echo "chi=$(sed -n 's|.*go-chi/chi/v5 \(v[0-9.]*\).*|\1|p' "$repository_root/bench/competitors/chi/go.mod" | head -1), $(go version | cut -d' ' -f3)"
  echo "quic-go=$(sed -n 's|.*quic-go/quic-go \(v[0-9.]*\).*|\1|p' "$repository_root/bench/competitors/chi/go.mod" | head -1)"
  echo "quinn=$(awk '$0 == "name = \"quinn\"" { getline; gsub(/version = |"/, ""); print; exit }' "$repository_root/bench/competitors/axum/Cargo.lock")"
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
        start_server "$server" "$protocol"
        apply_profile "$profile"
        mkdir -p "$scratch/runs/$round/$protocol@$profile/$server"
        for connections in "${connection_counts[@]}"; do
          load "$protocol" "$connections" "$scratch/runs/$round/$protocol@$profile/$server/$connections"
        done
        stop_server
      done
    done
  done
done

python3 "$repository_root/bench/report_bulk.py" "$scratch" "$report" --file-len "$bulk_len" --seconds "$seconds"
