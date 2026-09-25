#!/usr/bin/env bash
# The server half of the interop check of docs/design.md §8 step 5: run other implementations' h2
# clients against colibri's test-only h2 server (§9) and require every request to end with 200 and
# the body the server always sends. Cleartext, with prior knowledge (RFC 9113 §3.3), and with
# --tls also over TLS 1.3 (§3.2), through chapulin's record-mode server built from the checkout.
#
# The peers are Go's net/http client, built with `go build`, and Debian's curl and nghttp, run in
# the container tools/h2_interop/Dockerfile builds. None is installed by this repository: the run
# needs `go` and `docker` on the path, and it names the versions it met. Over TLS the server
# serves the identity tools/h2_interop/tls_identity.go mints. curl and Go check its chain against
# the root and refuse one that fails; nghttp prints a warning and goes on.
#
# Usage: tools/h2_server_interop.sh [--tls <chapulin-checkout>] [curl] [nghttp] [go]
#        (no peer runs all three)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly server="${repository_root}/zig-out/bin/h2-server"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The same image tools/h2_interop.sh builds, tagged by a checksum of what it is built from.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" "${peer_directory}/h2o_tls.conf" | shasum -a 256 | cut -c1-16)"
readonly port=18481
# Requests each client sends at once on one connection, fewer than the 100 concurrent streams RFC
# 9113 §6.5.2 recommends a peer allow at least.
readonly requests=64
# Octets of request content: past the 65,535-octet window a stream starts with (RFC 9113 §6.9.2),
# so an upload finishes only if the server sends WINDOW_UPDATE frames.
readonly content_len=300000
# What the server answers every request with (src/testing/constants.zig), without its final
# newline, and the octets it takes with it.
readonly body="colibri"
readonly body_len=$((${#body} + 1))
# Seconds to wait for the server to listen before the run gives it up.
readonly listen_wait_seconds=30

fail() {
  echo "h2_server_interop.sh: $*" >&2
  [ ! -f "${scratch}/server.log" ] || tail -5 "${scratch}/server.log" >&2
  exit 1
}

readonly scratch="$(mktemp -d)"
readonly identity_directory="${scratch}/tls"
readonly identity="${identity_directory}/colibri"
server_pid=""
stop_server() {
  [ -z "${server_pid}" ] || { kill "${server_pid}" 2>/dev/null || true; wait "${server_pid}" 2>/dev/null || true; server_pid=""; }
}
trap 'stop_server; rm -rf "${scratch}"' EXIT

# Where a container finds the server: Docker Desktop forwards host.docker.internal to the host's
# loopback, and on Linux the container shares the host's network.
if [ "$(uname)" = Darwin ]; then
  readonly container_host=host.docker.internal
  docker_network=()
else
  readonly container_host=127.0.0.1
  docker_network=(--network host)
fi

# start_server [--tls <identity-prefix>]: starts colibri's server in the mode the arguments name.
start_server() {
  stop_server
  "${server}" --port "${port}" "$@" >"${scratch}/server.log" 2>&1 &
  server_pid=$!
  for _ in $(seq "${listen_wait_seconds}"); do
    nc -z 127.0.0.1 "${port}" 2>/dev/null && return 0
    sleep 1
  done
  fail "the server did not listen on port ${port} within ${listen_wait_seconds} seconds"
}

in_container() {
  docker run --rm ${docker_network[@]+"${docker_network[@]}"} -v "${identity_directory}:/identity:ro" \
    "${image}" "$@"
}

# in_both_modes <plan>: runs the plan against the cleartext server, then against the TLS one when
# --tls was given. The plan reads ${mode}.
in_both_modes() {
  mode=cleartext
  start_server
  "$1"
  if [ -n "${checkout}" ]; then
    mode=tls
    echo "h2_server_interop.sh: over TLS"
    start_server --tls "${identity}"
    "$1"
  fi
  stop_server
}

# Over TLS curl multiplexes every GET onto one connection (RFC 9113 §5), asks for the name the
# certificate carries, and connects to the host the container finds the server at. In cleartext
# each GET gets its own connection, all at once: curl 7.88.1 cannot reuse a prior-knowledge
# connection, and its second request on one fails with "Error in the HTTP2 framing layer" against
# Go's server as it does against colibri's.
plan_curl() {
  local base arguments=()
  if [ "${mode}" = tls ]; then
    base="https://localhost:${port}"
    arguments=(--http2 --cacert /identity/colibri.chain.pem --connect-to "localhost:${port}:${container_host}:${port}")
  else
    base="http://${container_host}:${port}"
    arguments=(--http2-prior-knowledge)
  fi
  local quoted
  quoted="$(printf '%q ' "${arguments[@]}")"
  local gets
  if [ "${mode}" = tls ]; then
    local transfers=()
    for i in $(seq "${requests}"); do transfers+=(-o /dev/null "${base}/get/${i}"); done
    gets="curl -s ${quoted} --parallel --parallel-max ${requests} -w '%{http_code} %{http_version}\n' ${transfers[*]}"
  else
    gets="for i in \$(seq ${requests}); do curl -s ${quoted} -o /dev/null -w '%{http_code} %{http_version}\n' ${base}/get/\$i & done; wait"
  fi
  local answered
  answered="$(in_container sh -c "${gets}")" || fail "curl ${mode}: the GETs failed"
  [ "$(grep -c '^200 2$' <<<"${answered}")" -eq "${requests}" ] ||
    fail "curl ${mode}: not every GET ended with 200 over h2: $(sort <<<"${answered}" | uniq -c | tr '\n' ' ')"
  local posted
  posted="$(in_container sh -c "head -c ${content_len} /dev/urandom >/tmp/content &&
    curl -s ${quoted} --data-binary @/tmp/content -w ' %{http_code} %{http_version}' ${base}/post")" ||
    fail "curl ${mode}: the POST failed"
  [ "${posted}" = "${body}"$'\n'" 200 2" ] || fail "curl ${mode}: the POST got: ${posted}"
  echo "h2_server_interop.sh: curl ${mode}: ${requests} GETs and a ${content_len}-octet POST ended with 200"
}

# nghttp sends every request of a run at once on one connection. Over TLS it connects to the
# host the container finds the server at, and warns that the certificate names another.
plan_nghttp() {
  local base="http://${container_host}:${port}"
  [ "${mode}" = cleartext ] || base="https://${container_host}:${port}"
  local statistics
  statistics="$(in_container sh -c "head -c ${content_len} /dev/urandom >/tmp/content &&
    nghttp -s -m ${requests} ${base}/get && nghttp -s -d /tmp/content ${base}/post")" ||
    fail "nghttp ${mode}: the run failed"
  # nghttp writes each body, then a statistics line for each response: its timings, then the
  # status, the size and the path.
  local answered bodies
  answered="$(grep -cE "[[:space:]]200[[:space:]]+${body_len}[[:space:]]+/(get|post)$" <<<"${statistics}" || true)"
  bodies="$(grep -cx "${body}" <<<"${statistics}" || true)"
  [ "${answered}" -eq $((requests + 1)) ] && [ "${bodies}" -eq $((requests + 1)) ] ||
    fail "nghttp ${mode}: ${answered} of $((requests + 1)) requests ended with 200, ${bodies} with the body"
  echo "h2_server_interop.sh: nghttp ${mode}: ${requests} GETs and a ${content_len}-octet POST ended with 200"
}

plan_go() {
  local arguments=()
  [ "${mode}" = cleartext ] || arguments=("${identity}")
  local report
  report="$("${scratch}/go_client" "127.0.0.1:${port}" ${arguments[@]+"${arguments[@]}"} 2>&1)" ||
    { echo "${report}"; fail "go ${mode}: the client exited non-zero"; }
  echo "h2_server_interop.sh: go ${mode}: ${report#go_client: }"
}

checkout=""
if [ "${1:-}" = "--tls" ]; then
  [ -n "${2:-}" ] || fail "--tls needs a chapulin checkout"
  checkout="$(cd "$2" && pwd)"
  shift 2
fi
peers=("$@")
[ "${#peers[@]}" -gt 0 ] || peers=(curl nghttp go)

command -v go >/dev/null 2>&1 || fail "go is not installed"
echo "h2_server_interop.sh: building the test-only server"
mkdir -p "${identity_directory}"
if [ -n "${checkout}" ]; then
  (cd "${repository_root}" && zig build install -Dchapulin-server="${checkout}")
  (cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${identity}")
else
  (cd "${repository_root}" && zig build install)
fi
[ -x "${server}" ] || fail "the server was not built at ${server}"

for peer in "${peers[@]}"; do
  case "${peer}" in
    curl | nghttp)
      command -v docker >/dev/null 2>&1 || fail "docker is not installed"
      docker image inspect "${image}" >/dev/null 2>&1 ||
        docker build -q -t "${image}" "${peer_directory}" >/dev/null
      if [ "${peer}" = curl ]; then
        echo "h2_server_interop.sh: $(in_container curl --version | head -1)"
      else
        echo "h2_server_interop.sh: $(in_container nghttp --version)"
      fi
      in_both_modes "plan_${peer}"
      ;;
    go)
      echo "h2_server_interop.sh: $(go version)"
      (cd "${peer_directory}" && go build -o "${scratch}/go_client" go_client.go)
      in_both_modes plan_go
      ;;
    *) fail "unknown peer: ${peer}" ;;
  esac
done
modes="cleartext"
[ -z "${checkout}" ] || modes="cleartext and TLS"
echo "h2_server_interop.sh: every request ended with 200, in ${modes}, from: ${peers[*]}"
