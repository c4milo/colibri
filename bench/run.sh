#!/usr/bin/env bash
#
# The judge of design §8 step 13a (decision 33 as amended on 2026-09-30): colibri's test-only h2
# server under h2load, with the server's instructions, cycles and system calls counted per request
# and per connection by perf stat. With --base, a second tree is built and measured in turns with
# this one, and the report gives each input's ratio of the change to the base; the run fails when
# an input loses past the floor. With --competitors, nginx and h2o answer the same requests from
# memory, set up by bench/competitors/, in turns with colibri's server, and the report gives
# colibri's ratio to each without failing the run (design §8 step 13c). hyper, in Rust, and
# http.zig, in Zig, answer too (design §8 step 13g); BENCH_COMPETITORS names a part of the list.
# With --h11, four h11 inputs join the four h2 ones. wrk sends them, for h11_seconds each: h2load
# counts no answer whose reason phrase is empty, as http.zig's is (RFC 9112 §4 allows it). With
# --h3, the test-only UDP server answers the same load over h3, from h2load built with HTTP/3
# (design §8 step 13d). With --latency, bench/run_latency.sh runs instead: the throughput and the
# latency of servers that route, at fixed request rates, under oha (design §8 step 13f).
#
#   bench/run.sh [--filter] [--base <tree>] [--competitors] [--h11] [--h3] [--latency] [--rounds <n>] [report.md]
#
# The judge runs on Linux with perf and taskset, as .github/workflows/bench.yml runs it on the
# ubuntu-24.04-arm runner. --filter runs without either and reads the server's CPU time from each
# thread's /proc schedstat: its numbers order candidates on a laptop and are never published
# (docs/performance.md).
# It needs Zig, h2load, python3, and Go for the TLS identity unless BENCH_IDENTITY names one, and
# wrk and curl with --h11. With --competitors it needs nginx and h2o on the PATH, cargo to build
# hyper, and BENCH_ZIG_HTTPZ naming the Zig 0.17.0 that builds http.zig. BENCH_HYPER and
# BENCH_HTTPZ name servers built already. Ubuntu's and Debian's h2load have no HTTP/3, so --h3
# runs the image tools/h3load/Dockerfile builds, on the load generator's cores, and needs Docker;
# BENCH_H3LOAD=native says the h2load on the PATH has HTTP/3 itself.
# BENCH_SERVER and BENCH_BASE_SERVER name servers built already, for a machine with no Zig, and
# BENCH_QUIC_SERVER and BENCH_BASE_QUIC_SERVER the UDP servers.
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode=judge
base=""
competitors=""
h11=""
h3=""
rounds=5
report="${repository_root}/bench-report.md"
while [ $# -gt 0 ]; do
  case "$1" in
    --filter) mode=filter; shift ;;
    --base) base="$(cd "$2" && pwd)"; shift 2 ;;
    --competitors) competitors=yes; shift ;;
    --h11) h11=yes; shift ;;
    --h3) h3=yes; shift ;;
    --latency) shift; exec "$repository_root/bench/run_latency.sh" --rounds "$rounds" "$@" ;;
    --rounds) rounds="$2"; shift 2 ;;
    *) report="$1"; shift ;;
  esac
done

readonly port=18480
# Decision 33 as amended: the server and the load generator each run on cores of their own.
readonly server_core=1
readonly load_cores=2,3
# Many requests on a connection: the requests, the connections at once and the streams on each.
readonly many_requests=20000
readonly many_clients=16
readonly many_streams=10
# One request on each connection: h2load runs this many times, with this many connections each,
# within the 32 connections one worker holds at once.
readonly one_runs=40
readonly one_clients=16
# The requests before each measurement that are never counted: the server's first connections
# touch memory the operating system has not mapped yet.
readonly warm_requests=2000
# The requests the script sends, 0.1 s apart, before it gives up on a server that has not started,
# and the seconds each may take: a TCP connection nothing listens for is refused at once, and
# h2load waits out a QUIC handshake nothing answers.
readonly ready_tries=100
readonly ready_seconds=1
inputs=(h2-many h2-tls-many h2-one h2-tls-one)
if [ -n "$h11" ]; then inputs+=(h11-many h11-tls-many h11-one h11-tls-one); fi
if [ -n "$h3" ]; then inputs+=(h3-many h3-one); fi
readonly inputs
# The competitors --competitors measures, each in turns with colibri's server: the h2 and h11
# servers, and with --h3 the h3 servers too.
default_competitors="nginx h2o hyper httpz"
if [ -n "$h3" ]; then default_competitors+=" quic-go"; fi
read -r -a competitor_names <<<"${BENCH_COMPETITORS:-$default_competitors}"
readonly competitor_names
# The seconds wrk sends each h11 input for, and before it the seconds of its warm-up, with one
# thread on each core of load_cores.
readonly h11_seconds=2
readonly h11_warm_seconds=1
readonly wrk_threads=2
# The one TLS 1.3 suite h2load offers, so that every server runs the same cipher: colibri's server
# chooses by its own order, which puts this suite first, and nginx and h2o follow the client's.
readonly tls_suite=TLS_AES_256_GCM_SHA384
# The h3 pieces: the load of the h3 inputs, colibri's UDP servers and quic-go's container.
# shellcheck source-path=SCRIPTDIR source=run_h3.sh
source "$repository_root/bench/run_h3.sh"

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  if [ -n "$server_container" ]; then
    docker rm -f "$server_container" >/dev/null 2>&1 || true
  elif [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$scratch"
}
trap cleanup EXIT

build() {  # build <tree> <prefix>
  echo "run.sh: building $1" >&2
  (cd "$1" && zig build install -Drelease --prefix "$2" >/dev/null)
}

url() {  # url <variant> <input>
  local at
  at="$(port_of "$1")"
  case "$2" in
    h3-*) echo "https://127.0.0.1:${at}/${h3_file}" ;;
    *-tls-*) echo "https://127.0.0.1:${at}/" ;;
    *) echo "http://127.0.0.1:${at}/" ;;
  esac
}

# What h2load offers for <input>, into the array `offer`: over TLS the one suite of tls_suite. For
# an h3 input, `succeeded` adds that suite itself, as load.sh does.
offer_of() {  # offer_of <input>
  offer=()
  case "$1" in *-tls-*) offer+=(--tls13-ciphers="$tls_suite") ;; esac
}

# Whether <variant> serves <input>. A build of colibri serves every input. http.zig has no TLS and
# speaks h11 alone, nginx, h2o and hyper serve no h3 input, and quic-go serves h3 inputs alone.
serves() {  # serves <variant> <input>
  case "$1" in
    httpz) [[ "$2" == h11-* && "$2" != *-tls-* ]] ;;
    nginx | h2o | hyper) [[ "$2" != h3-* ]] ;;
    quic-go) [[ "$2" == h3-* ]] ;;
    *) true ;;
  esac
}

# wrk has no option for TLS 1.3 suites, so OpenSSL's configuration offers tls_suite alone to it.
cat >"$scratch/openssl.cnf" <<EOF
openssl_conf = colibri_bench
[colibri_bench]
ssl_conf = colibri_bench_ssl
[colibri_bench_ssl]
system_default = colibri_bench_tls
[colibri_bench_tls]
MinProtocol = TLSv1.3
Ciphersuites = ${tls_suite}
EOF

# The load each input names, against the port its second argument names, as a script of its own,
# because perf runs it under sudo, which keeps no function or variable of this shell. h2load's
# reports go to standard output.
cat >"$scratch/load.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
case "\$1" in
  *-tls-*) target=https://127.0.0.1:\$2/; options=(--tls13-ciphers=${tls_suite}) ;;
  *) target=http://127.0.0.1:\$2/; options=() ;;
esac
# An h11 input: wrk, for the seconds the third argument names, one request at a time on each
# connection, and with -one a close after each, which the request's Connection asks for. The
# command goes first in the output, where report.py reads it.
case "\$1" in
  h11-*)
    headers=()
    case "\$1" in *-one) headers=(-H "Connection: close") ;; esac
    echo "load: wrk \${headers[*]} \$target"
    OPENSSL_CONF=${scratch}/openssl.cnf exec wrk -t ${wrk_threads} -c ${many_clients} \\
      -d "\${3:-${h11_seconds}}s" "\${headers[@]}" "\$target"
    ;;
esac
# An h3 input's load is one shell command, so that the image starts once for all of its runs.
h3="h2load --alpn-list=h3 --tls13-ciphers=${tls_suite}"
h3_target=https://127.0.0.1:\$2/${h3_file}
case "\$1" in
  h3-many) ${h3_shell[*]} "\$h3 -n ${many_requests} -c ${many_clients} -m ${many_streams} \$h3_target" ;;
  h3-one) ${h3_shell[*]} "for run in \\\$(seq 1 ${one_h3_runs}); do \$h3 -n ${one_h3_clients} -c ${one_h3_clients} \$h3_target; done" ;;
  *-many) h2load "\${options[@]}" -n ${many_requests} -c ${many_clients} -m ${many_streams} "\$target" ;;
  *-one) for _ in \$(seq 1 ${one_runs}); do h2load "\${options[@]}" -n ${one_clients} -c ${one_clients} "\$target"; done ;;
esac
EOF

# h2load exits 0 even when every request fails, so each use of it here reads the count it reports.
# The output is read whole, because a reader that stops at the first match ends h2load early.
# <seconds> bounds h2load's run, and 0 leaves it unbounded.
succeeded() {  # succeeded <requests> <input> <seconds> <h2load arguments...>: whether all succeeded
  local requests="$1" input="$2" bound=() output
  if [ "$3" -gt 0 ]; then bound=(timeout "$3"); fi
  shift 3
  case "$input" in
    h3-*) output="$("${h3_shell[@]}" "${bound[*]} h2load --alpn-list=h3 --tls13-ciphers=${tls_suite} $*" 2>/dev/null)" || true ;;
    *) output="$("${bound[@]}" h2load "$@" 2>/dev/null)" || true ;;
  esac
  [[ "$output" == *", ${requests} succeeded, 0 failed,"* ]]
}

# Whether wrk's report <output> shows answers, none outside 2xx and 3xx, and no socket error but
# the read errors that a server's close after `Connection: close` counts as.
wrk_clean() {  # wrk_clean <output>
  [[ "$1" == *" requests in "* && "$1" != *"Non-2xx or 3xx responses"* ]] || return 1
  [[ "$1" != *"Socket errors:"* || "$1" == *"Socket errors: connect 0, read "*", write 0, timeout 0"* ]]
}

# Whether <variant>'s server answers one request for <input>: curl for h11, as wrk speaks it, and
# h2load for h2 and h3, which may take ready_seconds.
answers() {  # answers <variant> <input>
  local offer
  case "$2" in
    h11-*)
      [ "$(curl -sk --http1.1 --tls13-ciphers "$tls_suite" -o /dev/null -w '%{http_code}' "$(url "$1" "$2")")" = 200 ]
      ;;
    *)
      offer_of "$2"
      succeeded 1 "$2" "$ready_seconds" "${offer[@]}" -n 1 -c 1 "$(url "$1" "$2")"
      ;;
  esac
}

# Whether <variant>'s warm-up for <input> answers every request: load.sh's wrk for
# h11_warm_seconds, or h2load.
warms() {  # warms <variant> <input>
  local offer
  case "$2" in
    h11-*) wrk_clean "$(bash "$scratch/load.sh" "$2" "$(port_of "$1")" "$h11_warm_seconds" 2>/dev/null || true)" ;;
    *)
      offer_of "$2"
      succeeded "$warm_requests" "$2" 0 "${offer[@]}" -n "$warm_requests" -c "$many_clients" -m "$many_streams" "$(url "$1" "$2")"
      ;;
  esac
}

fail() {  # fail <message> <server log>
  save_container_log
  echo "run.sh: $1; the server's log ends:" >&2
  tail -20 "$2" >&2
  # A server that cannot bind the port shows AddressInUse in its log, and these lines name the
  # sockets that hold the port and their processes.
  echo "run.sh: the sockets on port $port:" >&2
  { sudo -n ss -tuanp "sport = :$port" 2>/dev/null || ss -tuan "sport = :$port"; } >&2 || true
  exit 1
}

# Writes a competitor's configuration from bench/competitors/ into the scratch directory. @SSL@
# goes first, because what it writes for h2o names @CHAIN@ and @KEY@ in turn. h2o's `user: root`
# line stays only when root runs this script, as its configuration says why.
render() {  # render <competitor> <ssl>
  local drop_user_line=(-e "/^user: root\$/d")
  if [ "$(id -u)" -eq 0 ]; then drop_user_line=(); fi
  sed -e "s|@SSL@|$2|g" -e "s|@PORT@|$port|g" -e "s|@SCRATCH@|$scratch|g" \
    -e "s|@CHAIN@|$identity.chain.pem|g" -e "s|@KEY@|$identity.key.pem|g" "${drop_user_line[@]}" \
    "$repository_root/bench/competitors/$1.conf" >"$scratch/$1.conf"
}

# The command that serves <input> as <variant>, into the array `command`: colibri's server built
# from the change or from the base, or a competitor configured for cleartext or for TLS.
server_command() {  # server_command <variant> <input>
  local tls=""
  case "$2" in *-tls-*) tls=yes ;; esac
  case "$1" in
    nginx)
      # The listen parameters. nginx 1.24 speaks no h11 on a cleartext port that has http2, and
      # over TLS it chooses by ALPN.
      local listen=http2
      case "$2" in h11-*) listen="" ;; esac
      if [ -n "$tls" ]; then listen="ssl http2"; fi
      render nginx "$listen"
      command=(nginx -p "$scratch" -e "$scratch/nginx.error.log" -c "$scratch/nginx.conf")
      ;;
    h2o)
      if [ -n "$tls" ]; then
        render h2o ", ssl: {certificate-file: @CHAIN@, key-file: @KEY@}"
      else
        render h2o ""
      fi
      command=(h2o -c "$scratch/h2o.conf")
      ;;
    hyper)
      command=("$hyper_server" --port "$port")
      if [ -n "$tls" ]; then command+=(--tls "$identity"); fi
      ;;
    httpz)
      command=("$httpz_server" --port "$port")
      ;;
    *)
      if [[ "$2" == h3-* ]]; then quic_server_command "$1"; return; fi
      if [ "$1" = base ]; then command=("$base_server"); else command=("$change_server"); fi
      command+=(--port "$port")
      if [ -n "$tls" ]; then command+=(--tls "$identity"); fi
      ;;
  esac
}

start_server() {  # start_server <variant> <input> <log>
  server_log="$3"
  if runs_from_image "$1"; then
    start_container "$1"
  else
    server_command "$1" "$2"
    # The process started here is the server itself, which taskset executes in place of itself, so
    # that stop_server ends the server and no later measurement reaches an earlier one.
    if [ "$mode" = judge ]; then
      taskset -c "$server_core" "${command[@]}" >"$3" 2>&1 &
    else
      "${command[@]}" >"$3" 2>&1 &
    fi
    server_pid=$!
  fi
  local ready=""
  for _ in $(seq 1 "$ready_tries"); do
    if answers "$1" "$2"; then ready=yes; break; fi
    sleep 0.1
  done
  [ -n "$ready" ] || fail "$1 answered no request for $2 in $ready_tries tries" "$3"
  warms "$1" "$2" || fail "the warm-up of $1 for $2 did not succeed in full" "$3"
}

stop_server() {
  if [ -n "$server_container" ]; then stop_container; return; fi
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  if kill -0 "$server_pid" 2>/dev/null; then
    echo "run.sh: the server $server_pid did not stop" >&2
    exit 1
  fi
  server_pid=""
  wait_udp_port_free
}

# A server on io_uring can hold its UDP socket after it exits, because the kernel ends the ring's
# requests after the process. The next h3 server then fails with AddressInUse, so this waits until
# no UDP socket holds the port, for at most ready_tries tenths of a second, and logs each wait.
wait_udp_port_free() {
  local tries
  for tries in $(seq 0 "$ready_tries"); do
    if [ -z "$(ss -Huan "sport = :$port")" ]; then
      if [ "$tries" -gt 0 ]; then echo "run.sh: UDP port $port free after $tries waits" >&2; fi
      return 0
    fi
    sleep 0.1
  done
  echo "run.sh: UDP port $port is still in use after the server stopped" >&2
  exit 1
}

# The nanoseconds the process's threads have run, from the first field of each thread's schedstat.
# /proc/<pid>/stat counts in ticks of 10 ms, too coarse for a run that lasts a second. The server's
# threads all start before the warm-up and none ends before the server does.
cpu_nanoseconds() {  # cpu_nanoseconds <pid>
  cat "/proc/$1/task/"*/schedstat | awk '{ total += $1 } END { printf "%.0f\n", total }'
}

measure() {  # measure <variant> <input> <round>
  local name="$1-$2-$3"
  # Each measurement keeps its server's log, which report.py prints when the load failed.
  start_server "$1" "$2" "$scratch/$name.server"
  if [ "$mode" = judge ]; then
    sudo -n "${PERF:-perf}" stat -x, -o "$scratch/$name.perf" \
      -e instructions:u,instructions:k,cycles:u,cycles:k,task-clock,raw_syscalls:sys_enter \
      -p "$server_pid" -- taskset -c "$load_cores" bash "$scratch/load.sh" "$2" "$(port_of "$1")" >"$scratch/$name.h2load"
  else
    local before
    before="$(cpu_nanoseconds "$server_pid")"
    bash "$scratch/load.sh" "$2" "$(port_of "$1")" >"$scratch/$name.h2load"
    echo "$(($(cpu_nanoseconds "$server_pid") - before)),,cpu_nanoseconds" >"$scratch/$name.perf"
  fi
  stop_server
  echo "$1,$2,$3,$scratch/$name.perf,$scratch/$name.h2load" >>"$scratch/records.csv"
}

# Whose memset a server links: its own, which src/testing/memset.zig exports on Linux under Zig
# 0.16, or compiler_rt's, which writes one octet at a time. nm's output is read whole, as h2load's is.
memset_of() {  # memset_of <server>
  local symbols
  symbols="$(nm "$1" 2>/dev/null)" || true
  if [ -z "$symbols" ]; then
    echo unknown
  elif [[ "$symbols" == *" memset.memset"* ]]; then
    echo "its own, src/testing/memset.zig"
  else
    echo "compiler_rt's"
  fi
}

machine() {
  echo "mode=$mode"
  echo "cpu=$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
  echo "cores=$(nproc)"
  echo "kernel=$(uname -sr)"
  echo "runner=${RUNNER_LABEL:-none}"
  echo "change=${BENCH_SERVER:-$(git -C "$repository_root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
  [ -n "$base" ] && echo "base=${BENCH_BASE_SERVER:-$(git -C "$base" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
  echo "zig=$(zig version 2>/dev/null || echo none)"
  echo "memset, change=$(memset_of "$change_server")"
  [ -n "$base" ] && echo "memset, base=$(memset_of "$base_server")"
  echo "h2load=$(h2load --version 2>/dev/null | head -1)"
  if [ -n "$h11" ]; then
    echo "wrk=$(wrk --version 2>&1 | head -1 | cut -d' ' -f1-2), TLS 1.3 with ${tls_suite} alone"
  fi
  h3_machine
  if [ -n "$competitors" ]; then
    if wants nginx; then
      echo "nginx=$(nginx -v 2>&1 | sed 's/^nginx version: //'), $(nginx -V 2>&1 | sed -n 's/^built with //p')"
    fi
    if wants h2o; then
      echo "h2o=$(h2o --version 2>/dev/null | sed -n 's/^h2o version //p'), $(h2o --version 2>/dev/null | sed -n 's/^OpenSSL: //p')"
    fi
    # Cargo.lock names each crate's version; rustls's provider is aws-lc-rs.
    if wants hyper; then
      # rustc runs in hyper's directory, whose rust-toolchain.toml names the release.
      echo "hyper=$(locked hyper), hyper-util $(locked hyper-util), tokio $(locked tokio), rustls $(locked rustls), aws-lc-rs $(locked aws-lc-rs), $(cd "$repository_root/bench/competitors/hyper" && rustc --version 2>/dev/null || echo 'rustc unknown')"
    fi
    if wants httpz; then
      echo "http.zig=$(sed -n 's|.*karlseguin/http.zig#\([0-9a-f]*\).*|\1|p' "$repository_root/bench/competitors/httpz/build.zig.zon" | head -1), zig $("${BENCH_ZIG_HTTPZ:-zig}" version 2>/dev/null || echo unknown)"
    fi
  fi
  [ "$mode" = judge ] && echo "perf=$(sudo -n "${PERF:-perf}" --version)"
  echo "rounds=$rounds"
  # Decision 33: the path, the socket buffer sizes and the certificate type go beside the numbers.
  # The report adds the cipher suite each build ran, from h2load's output.
  echo "path=loopback, 127.0.0.1"
  echo "tcp_rmem=$(tr '\t' ' ' 2>/dev/null </proc/sys/net/ipv4/tcp_rmem || echo unknown)"
  echo "tcp_wmem=$(tr '\t' ' ' 2>/dev/null </proc/sys/net/ipv4/tcp_wmem || echo unknown)"
  local certificate
  certificate="$(openssl x509 -in "$identity.chain.pem" -noout -text 2>/dev/null |
    sed -n 's/^ *\(Public Key Algorithm\|NIST CURVE\): *//p' | paste -sd ' ' -)"
  echo "certificate=${certificate:-unknown}"
}

change_server="${BENCH_SERVER:-}"
if [ -z "$change_server" ]; then
  build "$repository_root" "$scratch/change"
  change_server="$scratch/change/bin/http-server"
fi
base_server="${BENCH_BASE_SERVER:-}"
if [ -z "$base_server" ] && [ -n "$base" ]; then
  build "$base" "$scratch/base"
  base_server="$scratch/base/bin/http-server"
fi
# Whether --competitors measures <competitor>.
wants() {  # wants <competitor>
  local name
  for name in "${competitor_names[@]}"; do [ "$name" = "$1" ] && return 0; done
  return 1
}

# The version of <crate> that bench/competitors/hyper/Cargo.lock pins.
locked() {  # locked <crate>
  awk -v crate="$1" '$0 == "name = \"" crate "\"" { getline; gsub(/version = |"/, ""); print; exit }' \
    "$repository_root/bench/competitors/hyper/Cargo.lock"
}

hyper_server="${BENCH_HYPER:-}"
if [ -n "$competitors" ] && wants hyper && [ -z "$hyper_server" ]; then
  echo "run.sh: building hyper" >&2
  # rustup reads the release that rust-toolchain.toml names in the directory cargo runs in.
  (cd "$repository_root/bench/competitors/hyper" && cargo build --release --locked --quiet --target-dir "$scratch/hyper")
  hyper_server="$scratch/hyper/release/colibri-bench-hyper"
fi
httpz_server="${BENCH_HTTPZ:-}"
if [ -n "$competitors" ] && wants httpz && [ -z "$httpz_server" ]; then
  echo "run.sh: building http.zig" >&2
  (cd "$repository_root/bench/competitors/httpz" &&
    "${BENCH_ZIG_HTTPZ:?BENCH_ZIG_HTTPZ names the Zig 0.17.0 that builds http.zig}" build \
      --prefix "$scratch/httpz" --cache-dir "$scratch/httpz-cache" >/dev/null)
  httpz_server="$scratch/httpz/bin/colibri-bench-httpz"
fi
identity="${BENCH_IDENTITY:-}"
if [ -z "$identity" ]; then
  (cd "$repository_root" && go run tools/h2_interop/tls_identity.go "$scratch/identity")
  identity="$scratch/identity"
fi
prepare_h3
machine >"$scratch/machine.txt"

variants=(change)
if [ -n "$base_server" ]; then variants+=(base); fi
if [ -n "$competitors" ]; then variants+=("${competitor_names[@]}"); fi

# Round 0 is the warm-up, which the report discards. In each later round, the variants that serve
# an input take turns. Their list starts one place later each round, so in n rounds that follow
# one another, each of n variants goes first once.
for round in $(seq 0 "$rounds"); do
  for input in "${inputs[@]}"; do
    echo "run.sh: round $round, $input" >&2
    serving=()
    for variant in "${variants[@]}"; do
      if serves "$variant" "$input"; then serving+=("$variant"); fi
    done
    for ((place = 0; place < ${#serving[@]}; place++)); do
      measure "${serving[(round + place) % ${#serving[@]}]}" "$input" "$round"
    done
  done
done

python3 "$repository_root/bench/report.py" "$scratch" "$report" \
  --many-requests "$many_requests" --one-connections "$((one_runs * one_clients))"
