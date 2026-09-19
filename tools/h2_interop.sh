#!/usr/bin/env bash
# The client half of the interop check of docs/design.md §8 step 5: run colibri's test-only h2
# client (§9) against other implementations' servers and require every exchange to end the way
# the plan says. Cleartext, with prior knowledge (RFC 9113 §3.3): the h2 octets are the ones a
# TLS connection carries, and TLS joins when a provider can sit under a loop that never blocks.
#
# The peers are Go's net/http, run with `go run`, and Debian's nghttpd and h2o, run in a
# container built from tools/h2_interop/Dockerfile. None is installed by this repository: the run
# needs `go`, `docker` and `python3` on the path, and it names the versions it met.
#
# Usage: tools/h2_interop.sh [go] [nghttpd] [h2o]      (no argument runs all three)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly client="${repository_root}/zig-out/bin/h2-client"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The image is tagged with a checksum of what it is built from, so a run builds it only when one
# of those files changed, and CI can keep it between runs under the same name.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" | shasum -a 256 | cut -c1-16)"
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
  report="$("${client}" --port "${port}" "$@" 2>&1)" || { echo "${report}"; fail "the client exited non-zero"; }
  echo "${report}"
  local many
  many="$("${client}" --port "${port}" --connections 64 "$@" 2>&1 | tail -1)" || fail "64 connections: ${many}"
  echo "${many}"
  [ "${many}" = "h2-client: connections=64 succeeded=64 failed=0" ] || fail "64 connections did not all succeed"
}

# expect <path> <text>: the report's line for <path> carries <text>.
expect() {
  local line
  line="$(grep -E " (GET|POST) $1 " <<<"${report}" || true)"
  [[ "${line}" == *"$2"* ]] || fail "the exchange for $1 does not carry: $2"
}

run_go() {
  echo "h2_interop.sh: $(go version)"
  # Built first and run as itself: `go run` starts the server as a child that outlives a kill.
  (cd "${peer_directory}" && go build -o "${scratch}/go_server" go_server.go)
  "${scratch}/go_server" "${go_port}" &
  background_pid=$!
  wait_for_port "${go_port}"
  run_client "${go_port}" --get / --get /large --post /echo "${content_len}" \
    --get /interim --get /trailers --get /missing
  expect / "status=200 interim=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=ended"
  # The echo returns what was sent, octet for octet, while it is still being sent.
  expect /echo "sent=${content_len} sent_crc32=${content_crc32} received=${content_len} received_crc32=${content_crc32} outcome=ended"
  # RFC 9113 §8.1: an interim response, then the final one.
  expect /interim "status=200 interim=1"
  expect /trailers "status=200 interim=0 sent=0 sent_crc32=0x00000000 received=8"
  expect /missing "status=404"
  stop_peer
}

start_container() {
  container="colibri-h2-interop-peer-$1"
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker run -d --rm --name "${container}" -p "127.0.0.1:$2:8080" "${image}" "${@:3}" >/dev/null
  wait_for_port "$2"
}

run_nghttpd() {
  echo "h2_interop.sh: $(docker run --rm "${image}" nghttpd --version)"
  start_container nghttpd "${nghttpd_port}" nghttpd --no-tls -d /www 8080
  run_client "${nghttpd_port}" --get / --get /large --post /index.html "${content_len}" --get /missing
  expect / "status=200 interim=0 sent=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=ended"
  # nghttpd answers a POST with the file, after it has read the content whole.
  expect /index.html "status=200 interim=0 sent=${content_len} sent_crc32=${content_crc32} received=8"
  expect /missing "status=404"
  stop_peer
}

run_h2o() {
  echo "h2_interop.sh: $(docker run --rm "${image}" h2o --version | head -1)"
  start_container h2o "${h2o_port}" h2o -c /etc/h2o/colibri.conf
  run_client "${h2o_port}" --get / --get /large --post /index.html "${content_len}" --get /missing
  expect / "status=200 interim=0 sent=0"
  expect /large "received=${large_len} received_crc32=${large_crc32} outcome=ended"
  # h2o's file handler refuses the method, and still reads the content whole (RFC 9110 §15.5.6).
  expect /index.html "status=405 interim=0 sent=${content_len} sent_crc32=${content_crc32}"
  expect /missing "status=404"
  stop_peer
}

peers=("$@")
[ "${#peers[@]}" -gt 0 ] || peers=(go nghttpd h2o)

command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"
echo "h2_interop.sh: building the test-only client"
(cd "${repository_root}" && zig build install)
[ -x "${client}" ] || fail "the client was not built at ${client}"
readonly content_crc32="$(pattern_crc32 "${content_len}")"
readonly large_crc32="$(pattern_crc32 "${large_len}")"

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
echo "h2_interop.sh: every exchange ended as planned against: ${peers[*]}"
