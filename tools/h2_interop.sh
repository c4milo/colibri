#!/usr/bin/env bash
# The client half of the interop check of docs/design.md §8 step 5: run colibri's test-only h2
# client (§9) against other implementations' servers and require every exchange to end the way
# the plan says. Cleartext, with prior knowledge (RFC 9113 §3.3), and with --tls also over TLS
# 1.3 (§3.2), through chapulin's record-mode client.
#
# The peers are Go's net/http, run with `go run`, and Debian's nghttpd and h2o, run in a
# container built from tools/h2_interop/Dockerfile. None is installed by this repository: the run
# needs `go`, `docker` and `python3` on the path, and it names the versions it met. Over TLS each
# peer serves the identity tools/h2_interop/tls_identity.go mints, and the client pins its root.
# With --tls a client that pins another root must send the alert it refuses Go's server with.
#
# Usage: tools/h2_interop.sh [--tls] [go] [nghttpd] [h2o]
#        (no peer runs all three)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly client="${repository_root}/zig-out/bin/http-client"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The image is tagged with a checksum of what it is built from, so a run builds it only when one
# of those files changed, and CI can keep it between runs under the same name.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" "${peer_directory}/h2o_tls.conf" | shasum -a 256 | cut -c1-16)"
readonly go_port=18461
readonly nghttpd_port=18462
readonly h2o_port=18463
# Octets of request content: past the 65,535-octet window a stream starts with several times
# over (RFC 9113 §6.9.2), so it finishes only if the client reads the peer's WINDOW_UPDATE frames.
readonly content_len=300000
# Octets of /large on every peer, whose octet i is i % 251, as the request content's is.
readonly large_len=1048576
# Seconds to wait for a peer to listen before the run gives it up.
readonly listen_wait_seconds=30

fail() {
  echo "h2_interop.sh: $*" >&2
  exit 1
}

# The CRC-32 of the first $1 octets of the pattern, as the client prints one.
pattern_crc32() {
  python3 -c "import sys, zlib; print('0x%08x' % zlib.crc32(bytes(i % 251 for i in range(int(sys.argv[1])))))" "$1"
}

wait_for_port() {
  for _ in $(seq "${listen_wait_seconds}"); do
    nc -z 127.0.0.1 "$1" 2>/dev/null && return 0
    sleep 1
  done
  fail "nothing listened on port $1 within ${listen_wait_seconds} seconds"
}

background_pid=""
container=""
readonly scratch="$(mktemp -d)"
# The identity every TLS peer serves. The containers mount its directory at /identity.
readonly identity_directory="${scratch}/tls"
readonly identity="${identity_directory}/colibri"
# The client's arguments for the mode a run is in: none in cleartext, the root and the instant
# over TLS. The client reads no clock (CLAUDE.md non-negotiable 3), so the run passes one.
mode_arguments=()
stop_peer() {
  # A killed server holds its port until it exits, and the next one binds the same port.
  [ -z "${background_pid}" ] || {
    kill "${background_pid}" 2>/dev/null || true
    wait "${background_pid}" 2>/dev/null || true
    background_pid=""
  }
  [ -z "${container}" ] || { docker rm -f "${container}" >/dev/null 2>&1 || true; container=""; }
}
trap 'stop_peer; rm -rf "${scratch}"' EXIT

# run_client <port> <client arguments...>: runs the plan, on one connection and then on as many
# as the client holds at once, and leaves the single-connection report in ${report}.
report=""
run_client() {
  local port="$1"
  shift
  report="$("${client}" --port "${port}" ${mode_arguments[@]+"${mode_arguments[@]}"} "$@" 2>&1)" ||
    { echo "${report}"; fail "the client exited non-zero"; }
  echo "${report}"
  # Every exchange ran over h2, whichever way the connection chose it.
  ! grep -qE " protocol=(h11|none) " <<<"${report}" || fail "an exchange ran over h11, or never connected"
  local many
  many="$("${client}" --port "${port}" --connections 64 ${mode_arguments[@]+"${mode_arguments[@]}"} "$@" 2>&1 | tail -1)" ||
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

# over_tls <plan>: runs the plan with the client in its TLS mode.
over_tls() {
  echo "h2_interop.sh: over TLS"
  mode_arguments=(--tls "${identity}" --seconds "$(date +%s)")
  "$@"
  mode_arguments=()
}

run_go() {
  echo "h2_interop.sh: $(go version)"
  # Built first and run as itself: `go run` starts the server as a child that outlives a kill.
  (cd "${peer_directory}" && go build -o "${scratch}/go_server" go_server.go)
  start_go
  plan_go
  start_go -gzip
  plan_go_coded
  if [ -n "${tls}" ]; then
    start_go "${identity}"
    over_tls plan_go
    start_go -gzip "${identity}"
    over_tls plan_go_coded
    refuse_untrusted
  fi
  stop_peer
}

# RFC 9846 §6.2: a handshake the client refuses ends with its alert, which the server reads. A
# client that pins another root refuses the server's chain. Go's server logs a received alert as a
# "remote error"; a connection closed with no alert is an EOF.
refuse_untrusted() {
  local other="${identity_directory}/other"
  (cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${other}")
  stop_peer
  "${scratch}/go_server" "${go_port}" "${identity}" 2>"${scratch}/refused.log" &
  background_pid=$!
  wait_for_port "${go_port}"
  if "${client}" --port "${go_port}" --tls "${other}" --seconds "$(date +%s)" --get / >/dev/null 2>&1; then
    fail "the client completed a handshake with a chain its anchor did not sign"
  fi
  for _ in $(seq 1 50); do
    grep -q "remote error: tls: " "${scratch}/refused.log" && break
    sleep 0.1
  done
  grep -q "remote error: tls: " "${scratch}/refused.log" ||
    { cat "${scratch}/refused.log" >&2; fail "the server read no alert from the refusing client"; }
  echo "h2_interop.sh: a refused handshake ends with the client's alert:" \
    "$(sed -n 's/.*remote error: tls: //p' "${scratch}/refused.log" | head -1)"
}

# start_go [-gzip] [<identity-prefix>]: starts Go's server, over TLS when given the identity.
start_go() {
  stop_peer
  local coded=()
  if [ "${1:-}" = -gzip ]; then coded=(-gzip); shift; fi
  "${scratch}/go_server" ${coded[@]+"${coded[@]}"} "${go_port}" "$@" &
  background_pid=$!
  wait_for_port "${go_port}"
}

plan_go() {
  run_client "${go_port}" --get / --get /large --post /echo "${content_len}" \
    --get /interim --get /trailers --get /missing
  expect / "status=200 interim=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=response"
  # The echo returns what was sent, octet for octet, while it is still being sent.
  expect /echo "sent=${content_len} sent_crc32=${content_crc32} received=${content_len} received_crc32=${content_crc32} outcome=response"
  # RFC 9113 §8.1: an interim response, then the final one.
  expect /interim "status=200 interim=1"
  expect /trailers "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=8"
  expect /missing "status=404"
}

# Decision 101: the client offers gzip and deflate, Go's server with -gzip codes each answer in
# gzip, and the client decodes it octet for octet and names the coding it removed.
plan_go_coded() {
  run_client "${go_port}" --coded --get / --get /large
  expect / "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=8"
  expect / "coding=gzip"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=response error_code=0 coding=gzip"
}

# Decision 101: h2o codes a text file in gzip for a client that accepts it.
plan_h2o_coded() {
  run_client "${h2o_port}" --coded --get /text.txt
  expect /text.txt "received=${text_len} received_crc32=${text_crc32} outcome=response error_code=0 coding=gzip"
}

start_container() {
  stop_peer
  container="colibri-h2-interop-peer-$1"
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker run -d --rm --name "${container}" -p "127.0.0.1:$2:8080" \
    -v "${identity_directory}:/identity:ro" "${image}" "${@:3}" >/dev/null
  wait_for_port "$2"
}

run_nghttpd() {
  echo "h2_interop.sh: $(docker run --rm "${image}" nghttpd --version)"
  start_container nghttpd "${nghttpd_port}" nghttpd --no-tls -d /www 8080
  plan_nghttpd
  if [ -n "${tls}" ]; then
    start_container nghttpd "${nghttpd_port}" nghttpd -d /www 8080 \
      /identity/colibri.key.pem /identity/colibri.chain.pem
    over_tls plan_nghttpd
  fi
  stop_peer
}

plan_nghttpd() {
  run_client "${nghttpd_port}" --get / --get /large --post /index.html "${content_len}" --get /missing
  expect / "status=200 interim=0 sent=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=response"
  # nghttpd answers a POST with the file, after it has read the content whole.
  expect /index.html "status=200 interim=0 sent=${content_len} sent_crc32=${content_crc32} received=8"
  expect /missing "status=404"
}

run_h2o() {
  echo "h2_interop.sh: $(docker run --rm "${image}" h2o --version | head -1)"
  start_container h2o "${h2o_port}" h2o -c /etc/h2o/colibri.conf
  plan_h2o
  plan_h2o_coded
  if [ -n "${tls}" ]; then
    start_container h2o "${h2o_port}" h2o -c /etc/h2o/colibri_tls.conf
    over_tls plan_h2o
    over_tls plan_h2o_coded
  fi
  stop_peer
}

plan_h2o() {
  run_client "${h2o_port}" --get / --get /large --post /index.html "${content_len}" --get /missing
  expect / "status=200 interim=0 sent=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=response"
  # h2o's file handler refuses the method, and still reads the content whole (RFC 9110 §15.5.6).
  expect /index.html "status=405 interim=0 sent=${content_len} sent_crc32=${content_crc32}"
  expect /missing "status=404"
}

tls=""
if [ "${1:-}" = "--tls" ]; then
  tls="yes"
  shift
fi
peers=("$@")
[ "${#peers[@]}" -gt 0 ] || peers=(go nghttpd h2o)

command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"
echo "h2_interop.sh: building the test-only client"
mkdir -p "${identity_directory}"
if [ -n "${tls}" ]; then
  (cd "${repository_root}" && zig build install)
  command -v go >/dev/null 2>&1 || fail "go is not installed, and the TLS identity needs it"
  (cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${identity}")
  # A webpki chain is valid only at an instant, and the client reads no clock, so a TLS run that
  # names none is refused before it connects.
  refused=0
  "${client}" --tls "${identity}" --get / >/dev/null 2>&1 || refused=$?
  [ "${refused}" -eq 2 ] || fail "a TLS run with no --seconds exited ${refused}, not 2"
else
  (cd "${repository_root}" && zig build install)
fi
[ -x "${client}" ] || fail "the client was not built at ${client}"
readonly content_crc32="$(pattern_crc32 "${content_len}")"
readonly large_crc32="$(pattern_crc32 "${large_len}")"
# The text file h2o codes (tools/h2_interop/Dockerfile): "colibri\n" 8,192 times.
readonly text_len=65536
readonly text_crc32="$(python3 -c "import zlib; print('0x%08x' % zlib.crc32(b'colibri\\n' * 8192))")"

for peer in "${peers[@]}"; do
  case "${peer}" in
    go)
      command -v go >/dev/null 2>&1 || fail "go is not installed"
      run_go
      ;;
    nghttpd | h2o)
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
echo "h2_interop.sh: every exchange ended as planned, in ${modes}, against: ${peers[*]}"
