#!/usr/bin/env bash
# The server half of the h11 interop check of docs/design.md §8 step 15d: run other
# implementations' HTTP/1.1 clients against colibri's test-only server (§9) and require every
# request to end with 200 and the body the server always sends, over HTTP/1.1. Cleartext with
# `--h11`, and with --tls also over TLS 1.3 through chapulin's record-mode server, where the server
# offers "h2" and "http/1.1" and the client's offer decides.
#
# The peers are Go's net/http client, built with `go build`, and Debian's curl, run in the
# container tools/h2_interop/Dockerfile builds, the same peers tools/h2_server_interop.sh runs.
# Over TLS, Go offers ALPN "http/1.1" alone, and curl runs twice: offering "http/1.1" alone, and
# offering no ALPN at all, which the server takes as h11 (decision 88). With --tls a Go client
# that offers "http/1.1" and sends a record that does not authenticate after the handshake must
# read bad_record_mac.
#
# Usage: tools/h11_server_interop.sh [--tls] [curl] [go]
#        (no peer runs both)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly server="${repository_root}/zig-out/bin/http-server"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The image tools/h2_interop.sh builds, tagged by a checksum of what it is built from.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" "${peer_directory}/h2o_tls.conf" | shasum -a 256 | cut -c1-16)"
readonly port=18581
# The UDP port the server advertises h3 on (design §8 step 17b). No h3 server listens there: the
# check reads the advertisement alone.
readonly h3_port=8443
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
  start_server --h11 --h3-port "${h3_port}"
  "$1"
  if [ -n "${tls}" ]; then
    mode=tls
    echo "h11_server_interop.sh: over TLS"
    start_server --tls "${identity}" --h3-port "${h3_port}"
    "$1"
  fi
  stop_server
}

# RFC 9846 §5.2: a record that does not authenticate ends the connection with a bad_record_mac
# alert. forged_record.go's client sends one once the handshake is complete, over http/1.1, and
# reads what the server answers.
forge_record() {
  (cd "${peer_directory}" && go build -o "${scratch}/forged_record" forged_record.go)
  start_server --tls "${identity}"
  local report
  report="$("${scratch}/forged_record" client "${port}" "${identity}" http/1.1 2>&1)" ||
    { echo "${report}"; fail "the forged record's client did not complete its handshake"; }
  grep -q "remote error: tls: bad record MAC" <<<"${report}" ||
    { echo "${report}"; fail "the server did not answer a forged record with bad_record_mac"; }
  stop_server
  echo "h11_server_interop.sh: a forged record ends with the server's alert: ${report##*remote error: tls: }"
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
  alt_svc_run
}

# RFC 7838 §3: over TLS each final response carries an Alt-Svc line naming h3 on `h3_port`, which
# curl prints among the response's fields, and in cleartext none does (RFC 9114 §3.1.2).
alt_svc_run() {
  local url="http://${container_host}:${port}/get"
  local arguments=(--http1.1)
  if [ "${mode}" = tls ]; then
    url="https://localhost:${port}/get"
    arguments+=(--cacert /identity/colibri.chain.pem --connect-to "localhost:${port}:${container_host}:${port}")
  fi
  local head advertised
  head="$(in_container curl -s -o /dev/null -D - "${arguments[@]}" "${url}")" || fail "curl ${mode}: the Alt-Svc GET failed"
  advertised="$(grep -ci '^alt-svc:' <<<"${head}" || true)"
  if [ "${mode}" = tls ]; then
    [ "${advertised}" -eq 1 ] && grep -qi "^alt-svc: h3=\":${h3_port}\"; ma=86400" <<<"${head}" ||
      fail "curl tls: no Alt-Svc line named h3 on port ${h3_port}: ${head}"
    echo "h11_server_interop.sh: curl tls: the response advertised h3 on port ${h3_port}"
  else
    [ "${advertised}" -eq 0 ] || fail "curl cleartext: the response advertised h3: ${head}"
  fi
}

plan_go() {
  local arguments=()
  [ "${mode}" = cleartext ] || arguments=("${identity}")
  local report
  report="$("${scratch}/go_client" -h11 "127.0.0.1:${port}" ${arguments[@]+"${arguments[@]}"} 2>&1)" ||
    { echo "${report}"; fail "go ${mode}: the client exited non-zero"; }
  echo "h11_server_interop.sh: go ${mode}: ${report#go_client: }"
}

# coded_round <plan>: runs the plan against the server in its --coded mode, in cleartext and, with
# --tls, over TLS (decision 101). The plan reads ${mode}.
coded_round() {
  mode=cleartext
  start_server --h11 --coded
  "$1"
  if [ -n "${tls}" ]; then
    mode=tls
    start_server --coded --tls "${identity}"
    "$1"
  fi
  stop_server
}

# Decision 101: curl with --compressed offers gzip and deflate, and the server answers in gzip, its
# first coding, which curl decodes to the body.
plan_curl_coded() {
  local base arguments=(--http1.1)
  base="http://${container_host}:${port}"
  if [ "${mode}" = tls ]; then
    base="https://localhost:${port}"
    arguments=(--http1.1 --cacert /identity/colibri.chain.pem --connect-to "localhost:${port}:${container_host}:${port}")
  fi
  local answered
  answered="$(in_container curl -s "${arguments[@]}" --compressed -D - "${base}/get")" ||
    fail "curl ${mode}, coded: the GET failed"
  grep -qi '^content-encoding: gzip' <<<"${answered}" || fail "curl ${mode}, coded: the answer was not gzip: ${answered}"
  [ "$(tail -1 <<<"${answered}")" = "${body}" ] || fail "curl ${mode}, coded: the body did not decode: ${answered}"
  echo "h11_server_interop.sh: curl ${mode}: a GET with --compressed got gzip, which decoded to the body"
}

# Decision 101: Go's transport asks for gzip itself, and decodes each coded answer.
plan_go_coded() {
  local arguments=()
  [ "${mode}" = cleartext ] || arguments=("${identity}")
  local report
  report="$("${scratch}/go_client" -h11 -coded "127.0.0.1:${port}" ${arguments[@]+"${arguments[@]}"} 2>&1)" ||
    { echo "${report}"; fail "go ${mode}, coded: the client exited non-zero"; }
  echo "h11_server_interop.sh: go ${mode}, coded: ${report#go_client: }"
}

tls=""
if [ "${1:-}" = "--tls" ]; then
  tls="yes"
  shift
fi
peers=("$@")
[ "${#peers[@]}" -gt 0 ] || peers=(curl go)

command -v go >/dev/null 2>&1 || fail "go is not installed"
echo "h11_server_interop.sh: building the test-only server"
mkdir -p "${identity_directory}"
if [ -n "${tls}" ]; then
  (cd "${repository_root}" && zig build install)
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
      coded_round plan_curl_coded
      ;;
    go)
      echo "h11_server_interop.sh: $(go version)"
      (cd "${peer_directory}" && go build -o "${scratch}/go_client" go_client.go)
      in_both_modes plan_go
      coded_round plan_go_coded
      ;;
    *) fail "unknown peer: ${peer}" ;;
  esac
done
[ -z "${tls}" ] || forge_record
modes="cleartext"
[ -z "${tls}" ] || modes="cleartext and TLS"
echo "h11_server_interop.sh: every request ended with 200 over h11, in ${modes}, from: ${peers[*]}"
