#!/usr/bin/env bash
# The client half of the h11 interop check of docs/design.md §8 step 15d: run colibri's test-only
# client (§9) over HTTP/1.1 against other implementations' servers and require every exchange to
# end the way the plan says. Cleartext, and with --tls also over TLS 1.3 through chapulin's
# record-mode client.
#
# The peers are Go's net/http, run with `go run`, and Debian's h2o and Caddy, run in the container
# tools/h2_interop/Dockerfile builds, the same peers tools/h2_interop.sh runs. Over TLS, Go serves
# HTTP/1.1 alone and offers ALPN "http/1.1" alone, so a client offering "h2" and then "http/1.1"
# gets h11 by the server's selection (RFC 7301 §3.2). h2o offers both and prefers h2, so the
# client offers "http/1.1" alone with --h11. Every exchange must report protocol=h11. With --tls a
# client that reads a record that does not authenticate after the handshake must answer
# bad_record_mac.
#
# Usage: tools/h11_interop.sh [--tls] [go] [h2o] [caddy]
#        (no peer runs all three)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly client="${repository_root}/zig-out/bin/http-client"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The image tools/h2_interop.sh builds, tagged by a checksum of what it is built from.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" "${peer_directory}/h2o_tls.conf" "${peer_directory}/Caddyfile" "${peer_directory}/Caddyfile_tls" | shasum -a 256 | cut -c1-16)"
readonly listening_port="${repository_root}/tools/listening_port.sh"
# Octets of request content, sent in slices across many reads and writes.
readonly content_len=300000
# Octets of /large on every peer, whose octet i is i % 251, as the request content's is.
readonly large_len=1048576
# Seconds to wait for a peer to listen before the run gives it up.
readonly listen_wait_seconds=30
# Seconds one peer of each run waits before it binds its port, so a run that took the published
# host port for the peer's own would connect too early, every time (`wait_for_container`).
readonly late_bind_seconds=2

fail() {
  echo "h11_interop.sh: $*" >&2
  exit 1
}

# The CRC-32 of the first $1 octets of the pattern, as the client prints one.
pattern_crc32() {
  python3 -c "import sys, zlib; print('0x%08x' % zlib.crc32(bytes(i % 251 for i in range(int(sys.argv[1])))))" "$1"
}

# wait_for_port <port>: waits until the host accepts a connection on the port.
wait_for_port() {
  for _ in $(seq "${listen_wait_seconds}"); do
    nc -z 127.0.0.1 "$1" 2>/dev/null && return 0
    sleep 1
  done
  fail "nothing listened on port $1 within ${listen_wait_seconds} seconds"
}

# wait_for_container: waits until the peer in ${container} listens on its port 8080. Docker accepts
# a connection on the published host port before the peer has bound its own, and closes it at once,
# so `wait_for_port` alone lets the client connect too early. The run reads the container's own TCP
# sockets too, as tools/channel_interop.sh reads quic-go's UDP ones: 8080 is 1F90 in /proc's
# hexadecimal, and 0A is the listening state.
wait_for_container() {
  for _ in $(seq "${listen_wait_seconds}"); do
    docker exec "${container}" grep -Eq ':1F90 [0-9A-F]+:0000 0A ' /proc/net/tcp /proc/net/tcp6 \
      2>/dev/null && return 0
    sleep 1
  done
  fail "${container} did not listen on port 8080 within ${listen_wait_seconds} seconds"
}

background_pid=""
container=""
# The port the peer now running listens on, which the kernel or Docker chose
# (https://github.com/c4milo/colibri/issues/94).
peer_port=""
readonly scratch="$(mktemp -d)"
readonly identity_directory="${scratch}/tls"
readonly identity="${identity_directory}/colibri"
# The client's arguments for the mode a run is in. The client reads no clock (CLAUDE.md
# non-negotiable 3), so a TLS run passes the instant.
mode_arguments=()
stop_peer() {
  [ -z "${background_pid}" ] || {
    kill "${background_pid}" 2>/dev/null || true
    wait "${background_pid}" 2>/dev/null || true
    background_pid=""
  }
  [ -z "${container}" ] || { docker rm -f "${container}" >/dev/null 2>&1 || true; container=""; }
}
trap 'stop_peer; rm -rf "${scratch}"' EXIT

# run_client <client arguments...>: runs the plan against the peer now running, on one connection
# and then on as many as the client holds at once, and leaves the single-connection report in
# ${report}.
report=""
run_client() {
  report="$("${client}" --port "${peer_port}" ${mode_arguments[@]+"${mode_arguments[@]}"} "$@" 2>&1)" ||
    { echo "${report}"; fail "the client exited non-zero"; }
  echo "${report}"
  # Every exchange ran over h11.
  ! grep -qE " protocol=(h2|none) " <<<"${report}" || fail "an exchange ran over h2, or never connected"
  local many
  many="$("${client}" --port "${peer_port}" --connections 64 ${mode_arguments[@]+"${mode_arguments[@]}"} "$@" 2>&1 | tail -1)" ||
    fail "64 connections: ${many}"
  echo "${many}"
  [ "${many}" = "http-client: connections=64 succeeded=64 failed=0" ] || fail "64 connections did not all succeed"
}

# expect <path> <text>: the report's line for <path> carries <text>.
expect() {
  local line
  line="$(grep -E " (GET|POST) $1 " <<<"${report}" || true)"
  [[ "${line}" == *"$2"* ]] || fail "the exchange for $1 does not carry: $2"
}

run_go() {
  echo "h11_interop.sh: $(go version)"
  # Built first and run as itself: `go run` starts the server as a child that outlives a kill.
  (cd "${peer_directory}" && go build -o "${scratch}/go_server" go_server.go)
  start_go
  mode_arguments=(--h11)
  plan_go
  start_go -gzip
  plan_go_coded
  if [ -n "${tls}" ]; then
    echo "h11_interop.sh: over TLS, h11 by the server's ALPN selection"
    start_go "${identity}"
    mode_arguments=(--tls "${identity}" --seconds "$(date +%s)")
    plan_go
    start_go -gzip "${identity}"
    plan_go_coded
    forge_record
  fi
  mode_arguments=()
  stop_peer
}

# RFC 9846 §5.2: a record that does not authenticate ends the connection with a bad_record_mac
# alert. forged_record.go's server sends one once the handshake is complete, over http/1.1, and reads
# what the client answers. The client counts the connection as failed.
forge_record() {
  stop_peer
  (cd "${peer_directory}" && go build -o "${scratch}/forged_record" forged_record.go)
  "${scratch}/forged_record" server 0 "${identity}" http/1.1 >"${scratch}/forged.log" 2>&1 &
  background_pid=$!
  # The Go server takes one connection, so the run waits for its line: a probe of the port would
  # be that connection.
  peer_port="$("${listening_port}" "${scratch}/forged.log")"
  local outcome=0
  report="$("${client}" --port "${peer_port}" --tls "${identity}" --seconds "$(date +%s)" --get / 2>&1)" || outcome=$?
  [ "${outcome}" -ne 0 ] || fail "the client completed an exchange over a forged record"
  [ "$(tail -1 <<<"${report}")" = "http-client: connections=1 succeeded=0 failed=1" ] ||
    { echo "${report}"; fail "the client did not count the forged record's connection as failed"; }
  wait "${background_pid}" || true
  background_pid=""
  grep -q "remote error: tls: bad record MAC" "${scratch}/forged.log" ||
    { cat "${scratch}/forged.log" >&2; fail "Go's server read no bad_record_mac from the client"; }
  echo "h11_interop.sh: a forged record ends with the client's alert:" \
    "$(sed -n 's/.*remote error: tls: //p' "${scratch}/forged.log" | head -1)"
}

# start_go [-gzip] [<identity-prefix>]: starts Go's HTTP/1.1 server, over TLS when given the identity.
start_go() {
  stop_peer
  local coded=()
  if [ "${1:-}" = -gzip ]; then coded=(-gzip); shift; fi
  "${scratch}/go_server" -h11 ${coded[@]+"${coded[@]}"} 0 "$@" >"${scratch}/go.log" &
  background_pid=$!
  peer_port="$("${listening_port}" "${scratch}/go.log")"
}

plan_go() {
  run_client --get / --get /large --post /echo "${content_len}" \
    --get /interim --get /trailers --get /missing
  expect / "status=200 interim=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=response"
  # The echo returns what was sent, octet for octet, while it is still being sent.
  expect /echo "sent=${content_len} sent_crc32=${content_crc32} received=${content_len} received_crc32=${content_crc32} outcome=response"
  # RFC 9112 §9.2: an interim response, then the final one to the same request.
  expect /interim "status=200 interim=1"
  # RFC 9112 §7.1.2: the content, then a trailer section, in the chunked coding.
  expect /trailers "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=8"
  expect /missing "status=404"
}

# Decision 101: the client offers gzip and deflate, Go's server with -gzip codes each answer in
# gzip, and the client decodes it octet for octet and names the coding it removed.
plan_go_coded() {
  run_client --coded --get / --get /large
  expect / "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=8"
  expect / "coding=gzip"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=response error_code=0 coding=gzip"
}

# Decision 101 as amended: h2o codes a text file in br, the first coding the client offers.
plan_h2o_coded() {
  run_client --coded --get /text.txt
  expect /text.txt "received=${text_len} received_crc32=${text_crc32} outcome=response error_code=0 coding=br"
}

# Decision 101 as amended: Caddy codes a text file in zstd, the coding the client weighs highest of
# those Caddy has.
plan_caddy_coded() {
  run_client --coded --get /text.txt
  expect /text.txt "received=${text_len} received_crc32=${text_crc32} outcome=response error_code=0 coding=zstd"
}

run_caddy() {
  echo "h11_interop.sh: Caddy $(docker run --rm "${image}" caddy version)"
  start_container caddy caddy run --config /etc/caddy/colibri.Caddyfile --adapter caddyfile
  mode_arguments=(--h11)
  plan_caddy_coded
  if [ -n "${tls}" ]; then
    echo "h11_interop.sh: over TLS, h11 by the client's ALPN offer"
    start_container caddy caddy run --config /etc/caddy/colibri_tls.Caddyfile --adapter caddyfile
    mode_arguments=(--h11 --tls "${identity}" --seconds "$(date +%s)")
    plan_caddy_coded
  fi
  mode_arguments=()
  stop_peer
}

# start_container <peer> <command...>: runs the peer in a container, on a host port Docker
# chooses, and under a name this run alone has, so two runs keep their own peers.
start_container() {
  stop_peer
  container="colibri-h11-interop-peer-$1-$$"
  docker run -d --rm --name "${container}" -p "127.0.0.1::8080" \
    -v "${identity_directory}:/identity:ro" "${image}" "${@:2}" >/dev/null
  wait_for_container
  peer_port="$(docker port "${container}" 8080/tcp | head -1)"
  peer_port="${peer_port##*:}"
  [ -n "${peer_port}" ] || fail "Docker published no port for ${container}"
  # The host side of the published port may start to accept a moment after the container runs.
  wait_for_port "${peer_port}"
}

run_h2o() {
  echo "h11_interop.sh: $(docker run --rm "${image}" h2o --version | head -1)"
  # This peer binds its port late, which only `wait_for_container` waits for.
  start_container h2o \
    sh -c "sleep ${late_bind_seconds}; exec h2o -c /etc/h2o/colibri.conf"
  mode_arguments=(--h11)
  plan_h2o
  plan_h2o_coded
  if [ -n "${tls}" ]; then
    echo "h11_interop.sh: over TLS, h11 by the client's ALPN offer"
    start_container h2o h2o -c /etc/h2o/colibri_tls.conf
    mode_arguments=(--h11 --tls "${identity}" --seconds "$(date +%s)")
    plan_h2o
    plan_h2o_coded
  fi
  mode_arguments=()
  stop_peer
}

plan_h2o() {
  run_client --get / --get /large --post /index.html "${content_len}" --get /missing
  expect / "status=200 interim=0 sent=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=response"
  # h2o's file handler refuses the method, and still reads the content whole (RFC 9110 §15.5.6),
  # so the connection carries the next request.
  expect /index.html "status=405 interim=0 sent=${content_len} sent_crc32=${content_crc32}"
  expect /missing "status=404"
}

tls=""
if [ "${1:-}" = "--tls" ]; then
  tls="yes"
  shift
fi
peers=("$@")
[ "${#peers[@]}" -gt 0 ] || peers=(go h2o caddy)

command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"
echo "h11_interop.sh: building the test-only client"
mkdir -p "${identity_directory}"
if [ -n "${tls}" ]; then
  (cd "${repository_root}" && zig build install)
  command -v go >/dev/null 2>&1 || fail "go is not installed, and the TLS identity needs it"
  (cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${identity}")
else
  (cd "${repository_root}" && zig build install)
fi
[ -x "${client}" ] || fail "the client was not built at ${client}"
readonly content_crc32="$(pattern_crc32 "${content_len}")"
readonly large_crc32="$(pattern_crc32 "${large_len}")"
# The text file h2o and Caddy code (tools/h2_interop/Dockerfile): "colibri\n" 8,192 times.
readonly text_len=65536
readonly text_crc32="$(python3 -c "import zlib; print('0x%08x' % zlib.crc32(b'colibri\\n' * 8192))")"

for peer in "${peers[@]}"; do
  case "${peer}" in
    go)
      command -v go >/dev/null 2>&1 || fail "go is not installed"
      run_go
      ;;
    h2o | caddy)
      command -v docker >/dev/null 2>&1 || fail "docker is not installed"
      docker image inspect "${image}" >/dev/null 2>&1 ||
        docker build -q -t "${image}" "${peer_directory}" >/dev/null
      "run_${peer}"
      ;;
    *) fail "unknown peer: ${peer}" ;;
  esac
done
modes="cleartext"
[ -z "${tls}" ] || modes="cleartext and TLS"
echo "h11_interop.sh: every exchange ended as planned over h11, in ${modes}, against: ${peers[*]}"
