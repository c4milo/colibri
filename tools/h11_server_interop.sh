#!/usr/bin/env bash
# The server half of the h11 interop check of docs/design.md §8 step 15d: run other
# implementations' HTTP/1.1 clients against colibri's test-only server (§9) and require every
# request to end with 200 and the body the server always sends, over HTTP/1.1. In cleartext the
# server names no version and reads h11 from each client's first octets (decision 117), and with
# --tls also over TLS 1.3 through chapulin's record-mode server, where the server offers "h2" and
# "http/1.1" and the client's offer decides.
#
# The peers are Go's net/http client, built with `go build`, and Debian's curl, run in the
# container tools/h2_interop/Dockerfile builds, the same peers tools/h2_server_interop.sh runs.
# Over TLS, Go offers ALPN "http/1.1" alone, and curl runs twice: offering "http/1.1" alone, and
# offering no ALPN at all, which the server takes as h11 (decision 88). With --tls a Go client
# that offers "http/1.1" and sends a record that does not authenticate after the handshake must
# read bad_record_mac.
#
# curl also posts to a route of the server's --routes github mode that answers 405 at the head
# (decision 160): a body under 256 KiB, which the server reads and discards, so the next request
# shares the connection, and a body of 1 MiB, which gets the staged close of RFC 9112 §9.6. curl
# must read each 405, and no reset. A python3 client on this host then keeps writing a body past
# the bound while it reads. It must read the whole 405 and the end of the data with no reset, a
# write after that must be acknowledged, and a later write must fail. It needs python3.
#
# Usage: tools/h11_server_interop.sh [--tls] [curl] [go]
#        (no peer runs both)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly server="${repository_root}/zig-out/bin/http-server"
readonly peer_directory="${repository_root}/tools/h2_interop"
# The image tools/h2_interop.sh builds, tagged by a checksum of what it is built from.
readonly image="colibri-h2-interop:$(cat "${peer_directory}/Dockerfile" "${peer_directory}/h2o.conf" "${peer_directory}/h2o_tls.conf" "${peer_directory}/Caddyfile" "${peer_directory}/Caddyfile_tls" | shasum -a 256 | cut -c1-16)"
readonly listening_port="${repository_root}/tools/listening_port.sh"
# The port the server now running listens on, which the kernel chose
# (https://github.com/c4milo/colibri/issues/94).
port=""
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
  "${server}" --port 0 "$@" >"${scratch}/server.log" 2>&1 &
  server_pid=$!
  # The server prints its port once every worker's listener is bound.
  port="$("${listening_port}" "${scratch}/server.log" "${listen_wait_seconds}")"
}

in_container() {
  docker run --rm ${docker_network[@]+"${docker_network[@]}"} -v "${identity_directory}:/identity:ro" \
    "${image}" "$@"
}

# in_both_modes <plan>: runs the plan against the cleartext server, then against the TLS one, which
# offers both protocols, when --tls was given. The plan reads ${mode}.
in_both_modes() {
  mode=cleartext
  start_server --h3-port "${h3_port}"
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

# Decision 160: a POST to /emojis, a GET route, gets 405 before its body is read. curl writes the
# body while it waits, so a server that closed at once could reset the connection (RFC 9112 §9.6).
readonly early_url_path=/emojis
readonly early_small_len=10240
readonly early_large_len=1048576
early_run() {
  local base="http://${container_host}:${port}"
  local arguments=(--http1.1 -H "Expect:")
  if [ "${mode}" = tls ]; then
    base="https://localhost:${port}"
    arguments+=(--cacert /identity/colibri.chain.pem --connect-to "localhost:${port}:${container_host}:${port}")
  fi
  local quoted answered
  quoted="$(printf '%q ' "${arguments[@]}")"
  # Under the bound: two POSTs on one connection, so curl connects once.
  answered="$(in_container sh -c "head -c ${early_small_len} /dev/urandom >/tmp/small &&
    curl -s ${quoted} --data-binary @/tmp/small -o /dev/null -w '%{http_code} %{num_connects}\n' \
      ${base}${early_url_path} ${base}${early_url_path}")" ||
    fail "curl ${mode}: a POST under the bound failed: ${answered:-}"
  [ "${answered}" = $'405 1\n405 0' ] || fail "curl ${mode}: the POSTs under the bound got: ${answered}"
  # Past the bound: the 405 arrives whole, and then the server closes in stages.
  answered="$(in_container sh -c "head -c ${early_large_len} /dev/urandom >/tmp/large &&
    curl -s ${quoted} --data-binary @/tmp/large -o /dev/null -w '%{http_code}' ${base}${early_url_path}")" ||
    fail "curl ${mode}: the POST past the bound failed: ${answered:-}"
  [ "${answered}" = 405 ] || fail "curl ${mode}: the POST past the bound got: ${answered}"
  echo "h11_server_interop.sh: curl ${mode}: a ${early_small_len}-octet POST kept its connection, and a ${early_large_len}-octet one read its 405"
}

# RFC 9112 §9.6: a client on this host declares 4 MiB, keeps writing 1 MiB of it, and reads while
# it writes. A server that closed at once would reset the connection, and the reset can erase the
# 405 that the client has not read. The client requires these, in order:
#  1. It reads the whole 405 and then the end of the server's data, with no reset.
#  2. Its writer sends the 1 MiB, and a further octet sent on the same socket is acknowledged. A
#     socket that the server closed fully answers with a reset, so a full close fails here.
#  3. A later write fails: the server closed fully at the client's close or at its bound of 1 s.
# A pass is decided by these events alone, never by a clock. One case needs a clock: when step 2
# fails after the server's own bound of 1 s passed since the half-close, the server closed fully
# by its bound, as it must, and the client was too slow, as a loaded host can make it. That case
# runs again, at most attempts_max times in all. A step 2 that fails before the bound is a full
# close, and fails the check at once. Each wait has a bound of 30 s so that a broken server cannot
# hang the check.
early_reset_run() {
  python3 - "${port}" "${early_url_path}" <<'PYTHON' || fail "a client that kept writing past the bound did not see the half-close"
import socket
import sys
import threading
import time

port, path = int(sys.argv[1]), sys.argv[2]
declared = 4 * 1024 * 1024
written = 1024 * 1024
# A bound on each wait, so that a broken server cannot hang the check. No step expects to come
# near it.
wait_s = 30
# The server's half_close_ns (server.constants.limits), and the share of it after which a failed
# step 2 can come from the server's own bound and not from a full close.
half_close_s = 1.0
too_late_s = 0.8 * half_close_s
attempts_max = 3
# The octets of the send buffer that the peer has not acknowledged: SIOCOUTQ on Linux, which
# termios names TIOCOUTQ, and SO_NWRITE (0x1024 in <sys/socket.h>) on macOS.
if sys.platform == "darwin":
    def unacknowledged(connection):
        return connection.getsockopt(socket.SOL_SOCKET, 0x1024)
else:
    import fcntl
    import struct
    import termios

    def unacknowledged(connection):
        queued = fcntl.ioctl(connection.fileno(), termios.TIOCOUTQ, struct.pack("i", 0))
        return struct.unpack("i", queued)[0]


class TooLate(Exception):
    """Step 2 failed after the server's bound passed: the client was too slow, not the server."""


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def step_two_failed(message, half_closed_at):
    if time.monotonic() - half_closed_at >= too_late_s:
        raise TooLate(message)
    fail(message)


def attempt():
    connection = socket.create_connection(("127.0.0.1", port))
    connection.settimeout(wait_s)
    connection.sendall(f"POST {path} HTTP/1.1\r\nHost: h\r\nContent-Length: {declared}\r\n\r\n".encode())
    writer_errors = []

    def write_body():
        part = b"x" * 65536
        try:
            for _ in range(written // len(part)):
                connection.sendall(part)
        except OSError as error:
            writer_errors.append(error)

    writer = threading.Thread(target=write_body, daemon=True)
    writer.start()
    # Step 1: the 405 and then the end of the data, from the half-close.
    received = b""
    try:
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            received += chunk
    except ConnectionResetError:
        fail(f"reset after {len(received)} octets")
    half_closed_at = time.monotonic()
    if not received.startswith(b"HTTP/1.1 405 ") or not received.endswith(b"\r\n\r\n"):
        fail(f"read {received!r}")
    # Step 2: the server still reads after its half-close.
    writer.join(wait_s)
    if writer.is_alive():
        fail("the server did not read the body after its half-close")
    if writer_errors:
        step_two_failed(f"the body's writes failed: {writer_errors[0]!r}, a full close in place of the half-close", half_closed_at)
    try:
        connection.sendall(b"x")
        for _ in range(wait_s * 1000):
            if unacknowledged(connection) == 0:
                break
            time.sleep(0.001)
    except OSError as error:
        step_two_failed(f"a write after the half-close failed: {error!r}, a full close in place of the half-close", half_closed_at)
    error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if error != 0 or unacknowledged(connection) != 0:
        step_two_failed(f"the server did not acknowledge a write after its half-close (error {error})", half_closed_at)
    # Step 3: the server closes fully, so a later write fails.
    for _ in range(wait_s * 20):
        try:
            connection.send(b"x")
        except (BrokenPipeError, ConnectionResetError):
            return
        time.sleep(0.05)
    fail(f"the server did not close within {wait_s} s")


for number in range(1, attempts_max + 1):
    try:
        attempt()
        sys.exit(0)
    except TooLate as late:
        print(f"attempt {number}: {late}, after the server's bound of {half_close_s} s: the client was too slow", file=sys.stderr)
fail(f"the client was too slow in each of {attempts_max} attempts")
PYTHON
  echo "h11_server_interop.sh: a client that kept writing past the bound read the whole 405, the half-close, and the close"
}

# early_round: runs early_run against the server in its --routes github mode, in cleartext and,
# with --tls, over TLS, and early_reset_run in cleartext.
early_round() {
  mode=cleartext
  start_server --routes github
  early_run
  early_reset_run
  if [ -n "${tls}" ]; then
    mode=tls
    start_server --routes github --tls "${identity}"
    early_run
  fi
  stop_server
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
  start_server --coded
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
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"
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
      early_round
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
