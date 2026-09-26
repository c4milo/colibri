#!/usr/bin/env bash
# The client half of the h11 interop check of docs/design.md §8 step 15d: run colibri's test-only
# client (§9) over HTTP/1.1 against other implementations' servers and require every exchange to
# end the way the plan says. Cleartext, and with --tls also over TLS 1.3 through chapulin's
# record-mode client built from the checkout.
#
# The peers are Go's net/http, run with `go run`, and Debian's h2o, run in the container
# tools/h2_interop/Dockerfile builds, the same peers tools/h2_interop.sh runs. Over TLS, Go serves
# HTTP/1.1 alone and offers ALPN "http/1.1" alone, so a client offering "h2" and then "http/1.1"
# gets h11 by the server's selection (RFC 7301 §3.2). h2o offers both and prefers h2, so the
# client offers "http/1.1" alone with --h11. Every exchange must report stream=0, which is how the
# client reports an h11 exchange.
#
# Usage: tools/h11_interop.sh [--tls <chapulin-checkout>] [go] [h2o]
#        (no peer runs both)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly client="${repository_root}/zig-out/bin/http-client"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The image tools/h2_interop.sh builds, tagged by a checksum of what it is built from.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" "${peer_directory}/h2o_tls.conf" | shasum -a 256 | cut -c1-16)"
readonly go_port=18561
readonly h2o_port=18563
# Octets of request content, sent in slices across many reads and writes.
readonly content_len=300000
# Octets of /large on every peer, whose octet i is i % 251, as the request content's is.
readonly large_len=1048576
# Seconds to wait for a peer to listen before the run gives it up.
readonly listen_wait_seconds=30

fail() {
  echo "h11_interop.sh: $*" >&2
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
readonly identity_directory="${scratch}/tls"
readonly identity="${identity_directory}/colibri"
# The client's arguments for the mode a run is in. The client reads no clock (CLAUDE.md
# non-negotiable 3), so a TLS run passes the instant.
mode_arguments=()
stop_peer() {
  [ -z "${background_pid}" ] || { kill "${background_pid}" 2>/dev/null || true; background_pid=""; }
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
  # Every exchange ran over h11, which has no streams.
  ! grep -qE " stream=[1-9]" <<<"${report}" || fail "an exchange ran over h2, not h11"
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

run_go() {
  echo "h11_interop.sh: $(go version)"
  # Built first and run as itself: `go run` starts the server as a child that outlives a kill.
  (cd "${peer_directory}" && go build -o "${scratch}/go_server" go_server.go)
  start_go
  mode_arguments=(--h11)
  plan_go
  if [ -n "${checkout}" ]; then
    echo "h11_interop.sh: over TLS, h11 by the server's ALPN selection"
    start_go "${identity}"
    mode_arguments=(--tls "${identity}" --seconds "$(date +%s)")
    plan_go
  fi
  mode_arguments=()
  stop_peer
}

# start_go [<identity-prefix>]: starts Go's HTTP/1.1 server, over TLS when given the identity.
start_go() {
  stop_peer
  "${scratch}/go_server" -h11 "${go_port}" "$@" &
  background_pid=$!
  wait_for_port "${go_port}"
}

plan_go() {
  run_client "${go_port}" --get / --get /large --post /echo "${content_len}" \
    --get /interim --get /trailers --get /missing
  expect / "status=200 interim=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=ended"
  # The echo returns what was sent, octet for octet, while it is still being sent.
  expect /echo "sent=${content_len} sent_crc32=${content_crc32} received=${content_len} received_crc32=${content_crc32} outcome=ended"
  # RFC 9112 §9.2: an interim response, then the final one to the same request.
  expect /interim "status=200 interim=1"
  # RFC 9112 §7.1.2: the content, then a trailer section, in the chunked coding.
  expect /trailers "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=8"
  expect /missing "status=404"
}

start_container() {
  stop_peer
  container="colibri-h11-interop-peer-$1"
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker run -d --rm --name "${container}" -p "127.0.0.1:$2:8080" \
    -v "${identity_directory}:/identity:ro" "${image}" "${@:3}" >/dev/null
  wait_for_port "$2"
}

run_h2o() {
  echo "h11_interop.sh: $(docker run --rm "${image}" h2o --version | head -1)"
  start_container h2o "${h2o_port}" h2o -c /etc/h2o/colibri.conf
  mode_arguments=(--h11)
  plan_h2o
  if [ -n "${checkout}" ]; then
    echo "h11_interop.sh: over TLS, h11 by the client's ALPN offer"
    start_container h2o "${h2o_port}" h2o -c /etc/h2o/colibri_tls.conf
    mode_arguments=(--h11 --tls "${identity}" --seconds "$(date +%s)")
    plan_h2o
  fi
  mode_arguments=()
  stop_peer
}

plan_h2o() {
  run_client "${h2o_port}" --get / --get /large --post /index.html "${content_len}" --get /missing
  expect / "status=200 interim=0 sent=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=ended"
  # h2o's file handler refuses the method, and still reads the content whole (RFC 9110 §15.5.6),
  # so the connection carries the next request.
  expect /index.html "status=405 interim=0 sent=${content_len} sent_crc32=${content_crc32}"
  expect /missing "status=404"
}

checkout=""
if [ "${1:-}" = "--tls" ]; then
  [ -n "${2:-}" ] || fail "--tls needs a chapulin checkout"
  checkout="$(cd "$2" && pwd)"
  shift 2
fi
peers=("$@")
[ "${#peers[@]}" -gt 0 ] || peers=(go h2o)

command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"
echo "h11_interop.sh: building the test-only client"
mkdir -p "${identity_directory}"
if [ -n "${checkout}" ]; then
  (cd "${repository_root}" && zig build install -Dchapulin-client="${checkout}")
  command -v go >/dev/null 2>&1 || fail "go is not installed, and the TLS identity needs it"
  (cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${identity}")
else
  (cd "${repository_root}" && zig build install)
fi
[ -x "${client}" ] || fail "the client was not built at ${client}"
readonly content_crc32="$(pattern_crc32 "${content_len}")"
readonly large_crc32="$(pattern_crc32 "${large_len}")"

for peer in "${peers[@]}"; do
  case "${peer}" in
    go)
      command -v go >/dev/null 2>&1 || fail "go is not installed"
      run_go
      ;;
    h2o)
      command -v docker >/dev/null 2>&1 || fail "docker is not installed"
      docker image inspect "${image}" >/dev/null 2>&1 ||
        docker build -q -t "${image}" "${peer_directory}" >/dev/null
      run_h2o
      ;;
    *) fail "unknown peer: ${peer}" ;;
  esac
done
modes="cleartext"
[ -z "${checkout}" ] || modes="cleartext and TLS"
echo "h11_interop.sh: every exchange ended as planned over h11, in ${modes}, against: ${peers[*]}"
