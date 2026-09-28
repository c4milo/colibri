#!/usr/bin/env bash
# The check of docs/design.md §8 step 17d: the test-only client's origin mode (§9) fetches over h3
# from other implementations' servers, aioquic's and quic-go's, and falls back to h2 over TLS
# against Go's server, which listens on TCP alone. Every exchange must end the way the plan says,
# over the protocol its phase names, with the octets the server holds.
#
# aioquic is pinned and installed once into the cached virtual environment tools/quic_aioquic.sh
# uses. quic-go is the QUIC Interop Runner's image, pinned by digest and run outside the runner as
# an h3 server of this run's files. The run needs python3, docker and go, and it is not part of
# `zig build test`.
#
# Usage: tools/origin_interop.sh [port]
#        (aioquic listens on <port>, quic-go on <port>+1, and Go's h2 server on <port>+2)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly client="${repository_root}/zig-out/bin/http-client"
readonly aioquic_port="${1:-18494}"
readonly quic_go_port="$((aioquic_port + 1))"
readonly go_port="$((aioquic_port + 2))"
readonly aioquic_version="1.3.0"
readonly venv="${XDG_CACHE_HOME:-$HOME/.cache}/colibri/aioquic-${aioquic_version}"
# The image the QUIC Interop Runner runs for quic-go, an index for linux/amd64 and linux/arm64.
readonly quic_go_image="martenseemann/quic-go-interop@sha256:5b921a144cbac11d465f63bd49e0d391b72773643288612fd65a3243cd423f10"
# Octets of request content: past the window a stream starts with, so the upload finishes only if
# the client reads the server's MAX_STREAM_DATA frames (RFC 9000 §4.1), or WINDOW_UPDATE frames
# over h2 (RFC 9113 §6.9.2).
readonly content_len=300000
# Octets of Go's /large, whose octet i is i % 251, as the request content's is.
readonly large_len=1048576
# How long QUIC's handshake runs before TCP opens beside it, in milliseconds. Against an h3 server
# it is long enough that TCP never opens, so the phase shows QUIC carried every exchange.
readonly h3_fallback_ms=5000
# Tenths of a second to wait for a server to listen before the run gives it up.
readonly listen_wait_tenths=300

fail() {
  echo "origin_interop.sh: $*" >&2
  exit 1
}

readonly scratch="$(mktemp -d)"
readonly identity="${scratch}/identity"
server_pid=""
container=""
stop_peer() {
  # A killed server holds its port until it exits.
  [ -z "${server_pid}" ] || {
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
    server_pid=""
  }
  [ -z "${container}" ] || { docker rm -f "${container}" >/dev/null 2>&1 || true; container=""; }
}
trap 'stop_peer; rm -rf "${scratch}"' EXIT

# The CRC-32 of a file, or of the first $1 octets of the pattern, as the client prints one.
file_crc32() {
  python3 -c "import sys, zlib; print('0x%08x' % zlib.crc32(open(sys.argv[1], 'rb').read()))" "$1"
}
pattern_crc32() {
  python3 -c "import sys, zlib; print('0x%08x' % zlib.crc32(bytes(i % 251 for i in range(int(sys.argv[1])))))" "$1"
}

# wait_until <what> <command...>: runs the command every tenth of a second until it succeeds.
wait_until() {
  local what="$1"
  shift
  for _ in $(seq "${listen_wait_tenths}"); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  fail "${what} did not listen within $((listen_wait_tenths / 10)) seconds"
}

# run_client <protocol> <port> <client arguments...>: runs one origin over the plan, requires every
# exchange to have run over <protocol>, and leaves the report in ${report}.
report=""
run_client() {
  local protocol="$1" port="$2"
  shift 2
  report="$("${client}" --origin --port "${port}" --tls "${identity}" --seconds "$(date +%s)" "$@" 2>&1)" ||
    { echo "${report}"; fail "the client exited non-zero"; }
  echo "${report}"
  ! grep -E "^origin " <<<"${report}" | grep -qv " protocol=${protocol} " ||
    fail "an exchange ran over another protocol than ${protocol}"
}

# expect <method and path> <text>: the report's line for the exchange carries <text>.
expect() {
  local line
  line="$(grep -E " $1 " <<<"${report}" || true)"
  [[ "${line}" == *"$2"* ]] || fail "the exchange $1 does not carry: $2"
}

# expect_opened <text>: the report's last line, which counts the transports the origin opened,
# carries <text>.
expect_opened() {
  local line
  line="$(grep -E "^http-client: origin " <<<"${report}" || true)"
  [[ "${line}" == *"$1"* ]] || fail "the origin did not end with: $1"
}

# plan_h3 <port>: the plan both h3 servers run, over files they serve alike, and an upload.
plan_h3() {
  run_client h3 "$1" --fallback-ms "${h3_fallback_ms}" --get /small --get /medium --get /large \
    --post /small "${content_len}" --get /missing
  local file
  for file in small medium large; do
    expect "GET /${file}" "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=$(wc -c <"${scratch}/www/${file}" | tr -d ' ') received_crc32=$(file_crc32 "${scratch}/www/${file}") outcome=response"
  done
  expect "POST /small" "sent=${content_len} sent_crc32=$(pattern_crc32 "${content_len}")"
  expect "POST /small" "outcome=response"
  expect "GET /missing" "status=404"
  # RFC 9114 §3.1: QUIC went first, and its handshake completed well within the delay.
  expect_opened "closed=true quic_opens=1 tcp_opens=0"
}

run_aioquic() {
  echo "origin_interop.sh: aioquic ${aioquic_version}"
  HQ_PEER_SCRATCH="${scratch}" "${venv}/bin/python" "${repository_root}/tools/quic_interop/h3_peer.py" \
    server 127.0.0.1 "${aioquic_port}" "${identity}" "${scratch}/www" >"${scratch}/aioquic.log" 2>&1 &
  server_pid=$!
  wait_until aioquic grep -q listening "${scratch}/aioquic.log"
  plan_h3 "${aioquic_port}"
  stop_peer
}

run_quic_go() {
  echo "origin_interop.sh: quic-go $(quic_go_version) from ${quic_go_image}"
  mkdir -p "${scratch}/certs" "${scratch}/logs"
  # The runner's server reads its chain and key from /certs, and writes into /logs.
  cp "${identity}.chain.pem" "${scratch}/certs/cert.pem"
  cp "${identity}.key.pem" "${scratch}/certs/priv.key"
  chmod 777 "${scratch}/logs"
  container="colibri-origin-quic-go"
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker run -d --name "${container}" -e TESTCASE=http3 -v "${scratch}/certs:/certs:ro" \
    -v "${scratch}/www:/www:ro" -v "${scratch}/logs:/logs" -p "127.0.0.1:${quic_go_port}:443/udp" \
    --entrypoint /quic-go/server "${quic_go_image}" >/dev/null
  # The server prints nothing once it listens, so the run reads the container's UDP sockets for
  # port 443, 01BB in /proc's hexadecimal.
  wait_until quic-go docker exec "${container}" grep -q ":01BB " /proc/net/udp /proc/net/udp6
  plan_h3 "${quic_go_port}"
  stop_peer
}

# The quic-go commit the image's server was built from, which its build info carries.
quic_go_version() {
  local created
  created="$(docker create --entrypoint /quic-go/server "${quic_go_image}")"
  docker cp "${created}:/quic-go/server" "${scratch}/quic-go-server" >/dev/null
  docker rm "${created}" >/dev/null
  go version -m "${scratch}/quic-go-server" | sed -n 's/.*quicGoVersion=\([0-9a-f]*\).*/\1/p'
}

# Go's server listens on TCP alone, so QUIC's handshake is never answered: TCP opens once the
# fallback delay passes, and its h2 connection takes every exchange (RFC 9114 §3.1).
run_fallback() {
  echo "origin_interop.sh: $(go version), no UDP"
  (cd "${repository_root}/tools/h2_interop" && go build -o "${scratch}/go_server" go_server.go)
  "${scratch}/go_server" "${go_port}" "${identity}" >"${scratch}/go.log" 2>&1 &
  server_pid=$!
  wait_until "Go's server" nc -z 127.0.0.1 "${go_port}"
  run_client h2 "${go_port}" --get / --get /large --post /echo "${content_len}"
  expect "GET /" "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=8"
  expect "GET /large" "received=${large_len} received_crc32=$(pattern_crc32 "${large_len}") outcome=response"
  local content_crc32
  content_crc32="$(pattern_crc32 "${content_len}")"
  expect "POST /echo" "sent=${content_len} sent_crc32=${content_crc32} received=${content_len} received_crc32=${content_crc32} outcome=response"
  expect_opened "closed=true quic_opens=1 tcp_opens=1"
  stop_peer
}

for tool in python3 docker go nc; do
  command -v "${tool}" >/dev/null 2>&1 || fail "${tool} is not installed"
done
echo "origin_interop.sh: building the test-only client"
(cd "${repository_root}" && zig build install)
[ -x "${client}" ] || fail "the client was not built at ${client}"
(cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${identity}")
if [ ! -x "${venv}/bin/python" ]; then
  python3 -m venv "${venv}"
  "${venv}/bin/pip" install -q "aioquic==${aioquic_version}"
fi
mkdir -p "${scratch}/www"
# Each fits the octets the client keeps of one response (constants.response_content_len_max).
head -c 1000 /dev/urandom >"${scratch}/www/small"
head -c 100000 /dev/urandom >"${scratch}/www/medium"
head -c 1000000 /dev/urandom >"${scratch}/www/large"

run_aioquic
run_quic_go
run_fallback
echo "origin_interop.sh: every exchange ended as planned: over h3 from aioquic and quic-go, and over h2 from Go's server with no UDP"
