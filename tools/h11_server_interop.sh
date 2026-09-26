#!/usr/bin/env bash
# The server half of the h11 interop check of docs/design.md §8 step 15d: run other
# implementations' HTTP/1.1 clients against colibri's test-only server (§9) and require every
# request to end with 200 and the body the server always sends, over HTTP/1.1. Cleartext with
# `--h11`, and with --tls also over TLS 1.3 through chapulin's record-mode server built from the
# checkout, where the server offers "h2" and "http/1.1" and the client's offer decides.
#
# The peers are Go's net/http client, built with `go build`, and Debian's curl, run in the
# container tools/h2_interop/Dockerfile builds, the same peers tools/h2_server_interop.sh runs.
# Over TLS, Go offers ALPN "http/1.1" alone, and curl runs twice: offering "http/1.1" alone, and
# offering no ALPN at all, which the server takes as h11 (decision 88).
#
# Usage: tools/h11_server_interop.sh [--tls <chapulin-checkout>] [curl] [go]
#        (no peer runs both)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly server="${repository_root}/zig-out/bin/http-server"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The image tools/h2_interop.sh builds, tagged by a checksum of what it is built from.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" "${peer_directory}/h2o_tls.conf" | shasum -a 256 | cut -c1-16)"
readonly port=18581
# Requests each client sends, curl on one keep-alive connection one after another and Go all at
# once over as many connections as it opens.
readonly requests=64
# Octets of request content. curl asks for a 100 (Continue) before sending it (RFC 9110 §10.1.1).
readonly content_len=300000
# What the server answers every request with (src/testing/constants.zig), without its final
# newline.
readonly body="colibri"
# Seconds to wait for the server to listen before the run gives it up.
readonly listen_wait_seconds=30

fail() {
  echo "h11_server_interop.sh: $*" >&2
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

# start_server <arguments...>: starts colibri's server in the mode the arguments name.
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

# in_both_modes <plan>: runs the plan against the cleartext h11 server, then against the TLS one,
# which offers both protocols, when --tls was given. The plan reads ${mode}.
in_both_modes() {
  mode=cleartext
  start_server --h11
  "$1"
  if [ -n "${checkout}" ]; then
    mode=tls
    echo "h11_server_interop.sh: over TLS"
    start_server --tls "${identity}"
    "$1"
  fi
  stop_server
}

# curl_run <label> <curl arguments...>: every GET on one keep-alive connection, one after another,
# then a POST, each of which must end with 200 over HTTP/1.1 and carry the body.
curl_run() {
  local label="$1"
  shift
  local base="http://${container_host}:${port}"
  local arguments=("$@")
  if [ "${mode}" = tls ]; then
    base="https://localhost:${port}"
    arguments+=(--cacert /identity/colibri.chain.pem --connect-to "localhost:${port}:${container_host}:${port}")
  fi
  local quoted urls=""
  quoted="$(printf '%q ' "${arguments[@]}")"
  for i in $(seq "${requests}"); do urls+=" ${base}/get/${i}"; done
  local answered
  answered="$(in_container sh -c "curl -s ${quoted} -w '%{http_code} %{http_version} %{num_connects}\n' ${urls}")" ||
    fail "curl ${label}: the GETs failed"
  [ "$(grep -c "^${body}\$" <<<"${answered}")" -eq "${requests}" ] ||
    fail "curl ${label}: not every GET carried the body"
  [ "$(grep -cE '^200 1\.1 [01]$' <<<"${answered}")" -eq "${requests}" ] ||
    fail "curl ${label}: not every GET ended with 200 over HTTP/1.1: $(grep -vx "${body}" <<<"${answered}" | sort | uniq -c | tr '\n' ' ')"
  # RFC 9112 §9.3: one connection carried them all, so curl connected once.
  [ "$(grep -c ' 1$' <<<"${answered}")" -eq 1 ] || fail "curl ${label}: the GETs did not share one connection"
  local posted
  posted="$(in_container sh -c "head -c ${content_len} /dev/urandom >/tmp/content &&
    curl -s ${quoted} --data-binary @/tmp/content -w ' %{http_code} %{http_version}' ${base}/post")" ||
    fail "curl ${label}: the POST failed"
  [ "${posted}" = "${body}"$'\n'" 200 1.1" ] || fail "curl ${label}: the POST got: ${posted}"
  echo "h11_server_interop.sh: curl ${label}: ${requests} GETs on one connection and a ${content_len}-octet POST ended with 200"
}

plan_curl() {
  curl_run "${mode}" --http1.1
  # RFC 9846 §4.2.2: a client that offers no ALPN gets no selection, which the server takes as
  # h11 (decision 88).
  [ "${mode}" = cleartext ] || curl_run "${mode}, no ALPN" --http1.1 --no-alpn
}

plan_go() {
  local arguments=()
  [ "${mode}" = cleartext ] || arguments=("${identity}")
  local report
  report="$("${scratch}/go_client" -h11 "127.0.0.1:${port}" ${arguments[@]+"${arguments[@]}"} 2>&1)" ||
    { echo "${report}"; fail "go ${mode}: the client exited non-zero"; }
  echo "h11_server_interop.sh: go ${mode}: ${report#go_client: }"
}

checkout=""
if [ "${1:-}" = "--tls" ]; then
  [ -n "${2:-}" ] || fail "--tls needs a chapulin checkout"
  checkout="$(cd "$2" && pwd)"
  shift 2
fi
peers=("$@")
[ "${#peers[@]}" -gt 0 ] || peers=(curl go)

command -v go >/dev/null 2>&1 || fail "go is not installed"
echo "h11_server_interop.sh: building the test-only server"
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
    curl)
      command -v docker >/dev/null 2>&1 || fail "docker is not installed"
      docker image inspect "${image}" >/dev/null 2>&1 ||
        docker build -q -t "${image}" "${peer_directory}" >/dev/null
      echo "h11_server_interop.sh: $(in_container curl --version | head -1)"
      in_both_modes plan_curl
      ;;
    go)
      echo "h11_server_interop.sh: $(go version)"
      (cd "${peer_directory}" && go build -o "${scratch}/go_client" go_client.go)
      in_both_modes plan_go
      ;;
    *) fail "unknown peer: ${peer}" ;;
  esac
done
modes="cleartext"
[ -z "${checkout}" ] || modes="cleartext and TLS"
echo "h11_server_interop.sh: every request ended with 200 over h11, in ${modes}, from: ${peers[*]}"
