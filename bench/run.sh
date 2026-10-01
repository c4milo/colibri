#!/usr/bin/env bash
#
# The judge of design §8 step 13a (decision 33 as amended on 2026-09-30): colibri's test-only h2
# server under h2load, with the server's instructions, cycles and system calls counted per request
# and per connection by perf stat. With --base, a second tree is built and measured in turns with
# this one, and the report gives each input's ratio of the change to the base; the run fails when
# an input loses past the floor. With --competitors, nginx and h2o answer the same requests from
# memory, set up by bench/competitors/, in turns with colibri's server, and the report gives
# colibri's ratio to each without failing the run (design §8 step 13c).
#
#   bench/run.sh [--filter] [--base <tree>] [--competitors] [--rounds <n>] [report.md]
#
# The judge runs on Linux with perf and taskset, as .github/workflows/bench.yml runs it on the
# ubuntu-24.04-arm runner. --filter runs without either and reads the server's CPU time from each
# thread's /proc schedstat: its numbers order candidates on a laptop and are never published
# (docs/performance.md).
# It needs Zig, h2load, python3, and Go for the TLS identity unless BENCH_IDENTITY names one, and
# nginx and h2o on the PATH with --competitors.
# BENCH_SERVER and BENCH_BASE_SERVER name servers built already, for a machine with no Zig.
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode=judge
base=""
competitors=""
rounds=5
report="${repository_root}/bench-report.md"
while [ $# -gt 0 ]; do
  case "$1" in
    --filter) mode=filter; shift ;;
    --base) base="$(cd "$2" && pwd)"; shift 2 ;;
    --competitors) competitors=yes; shift ;;
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
# The requests the script sends, 0.1 s apart, before it gives up on a server that has not started.
readonly ready_tries=100
readonly inputs=(h2-many h2-tls-many h2-one h2-tls-one)
# The one TLS 1.3 suite h2load offers, so that every server runs the same cipher: colibri's server
# chooses by its own order, which puts this suite first, and nginx and h2o follow the client's.
readonly tls_suite=TLS_AES_256_GCM_SHA384

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

build() {  # build <tree> <prefix>
  echo "run.sh: building $1" >&2
  (cd "$1" && zig build install -Drelease --prefix "$2" >/dev/null)
}

url() {  # url <input>
  case "$1" in
    h2-tls-*) echo "https://127.0.0.1:${port}/" ;;
    *) echo "http://127.0.0.1:${port}/" ;;
  esac
}

# The load each input names, as a script of its own, because perf runs it under sudo, which keeps
# no function or variable of this shell. h2load's reports go to standard output.
cat >"$scratch/load.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
case "\$1" in
  h2-tls-*) target=https://127.0.0.1:${port}/; options=(--tls13-ciphers=${tls_suite}) ;;
  *) target=http://127.0.0.1:${port}/; options=() ;;
esac
case "\$1" in
  *-many) h2load "\${options[@]}" -n ${many_requests} -c ${many_clients} -m ${many_streams} "\$target" ;;
  *-one) for _ in \$(seq 1 ${one_runs}); do h2load "\${options[@]}" -n ${one_clients} -c ${one_clients} "\$target"; done ;;
esac
EOF

# h2load exits 0 even when every request fails, so each use of it here reads the count it reports.
# The output is read whole, because a reader that stops at the first match ends h2load early.
succeeded() {  # succeeded <requests> <h2load arguments...>: whether all of them succeeded
  local requests="$1" output
  shift
  output="$(h2load "$@" 2>/dev/null)" || true
  [[ "$output" == *", ${requests} succeeded, 0 failed,"* ]]
}

fail() {  # fail <message> <server log>
  echo "run.sh: $1; the server's log ends:" >&2
  tail -20 "$2" >&2
  exit 1
}

# Writes a competitor's configuration from bench/competitors/ into the scratch directory. @SSL@
# goes first, because what it writes for h2o names @CHAIN@ and @KEY@ in turn.
render() {  # render <competitor> <ssl>
  sed -e "s|@SSL@|$2|g" -e "s|@PORT@|$port|g" -e "s|@SCRATCH@|$scratch|g" \
    -e "s|@CHAIN@|$identity.chain.pem|g" -e "s|@KEY@|$identity.key.pem|g" -e "s|@USER@|$(id -un)|g" \
    "$repository_root/bench/competitors/$1.conf" >"$scratch/$1.conf"
}

# The command that serves <input> as <variant>, into the array `command`: colibri's server built
# from the change or from the base, or a competitor configured for cleartext or for TLS.
server_command() {  # server_command <variant> <input>
  local tls=""
  case "$2" in h2-tls-*) tls=yes ;; esac
  case "$1" in
    nginx)
      if [ -n "$tls" ]; then render nginx "ssl "; else render nginx ""; fi
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
    *)
      if [ "$1" = base ]; then command=("$base_server"); else command=("$change_server"); fi
      command+=(--port "$port")
      if [ -n "$tls" ]; then command+=(--tls "$identity"); fi
      ;;
  esac
}

start_server() {  # start_server <variant> <input> <log>
  server_command "$1" "$2"
  # The process started here is the server itself, which taskset executes in place of itself, so
  # that stop_server ends the server and no later measurement reaches an earlier one.
  if [ "$mode" = judge ]; then
    taskset -c "$server_core" "${command[@]}" >"$3" 2>&1 &
  else
    "${command[@]}" >"$3" 2>&1 &
  fi
  server_pid=$!
  # Over TLS, h2load offers tls_suite alone, as load.sh makes it do.
  local offer=()
  case "$2" in h2-tls-*) offer=(--tls13-ciphers="$tls_suite") ;; esac
  local ready=""
  for _ in $(seq 1 "$ready_tries"); do
    if succeeded 1 "${offer[@]}" -n 1 -c 1 "$(url "$2")"; then ready=yes; break; fi
    sleep 0.1
  done
  [ -n "$ready" ] || fail "$1 answered no request for $2 in $ready_tries tries" "$3"
  succeeded "$warm_requests" "${offer[@]}" -n "$warm_requests" -c "$many_clients" -m "$many_streams" "$(url "$2")" ||
    fail "the warm-up of $1 for $2 did not succeed in full" "$3"
}

stop_server() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  if kill -0 "$server_pid" 2>/dev/null; then
    echo "run.sh: the server $server_pid did not stop" >&2
    exit 1
  fi
  server_pid=""
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
      -p "$server_pid" -- taskset -c "$load_cores" bash "$scratch/load.sh" "$2" >"$scratch/$name.h2load"
  else
    local before
    before="$(cpu_nanoseconds "$server_pid")"
    bash "$scratch/load.sh" "$2" >"$scratch/$name.h2load"
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
  if [ -n "$competitors" ]; then
    echo "nginx=$(nginx -v 2>&1 | sed 's/^nginx version: //'), $(nginx -V 2>&1 | sed -n 's/^built with //p')"
    echo "h2o=$(h2o --version 2>/dev/null | sed -n 's/^h2o version //p'), $(h2o --version 2>/dev/null | sed -n 's/^OpenSSL: //p')"
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
identity="${BENCH_IDENTITY:-}"
if [ -z "$identity" ]; then
  (cd "$repository_root" && go run tools/h2_interop/tls_identity.go "$scratch/identity")
  identity="$scratch/identity"
fi
machine >"$scratch/machine.txt"

variants=(change)
if [ -n "$base_server" ]; then variants+=(base); fi
if [ -n "$competitors" ]; then variants+=(nginx h2o); fi

# Round 0 is the warm-up, which the report discards. Each round after it measures the variants in
# turns, starting one place later in the list each round, so that each goes first as often.
for round in $(seq 0 "$rounds"); do
  for input in "${inputs[@]}"; do
    echo "run.sh: round $round, $input" >&2
    for ((place = 0; place < ${#variants[@]}; place++)); do
      measure "${variants[(round + place) % ${#variants[@]}]}" "$input" "$round"
    done
  done
done

python3 "$repository_root/bench/report.py" "$scratch" "$report" \
  --many-requests "$many_requests" --one-connections "$((one_runs * one_clients))"
