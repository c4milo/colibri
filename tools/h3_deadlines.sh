#!/usr/bin/env bash
#
# Decision 110's deadlines on design §9's test-only h3 server, over UDP on 127.0.0.1 and on its
# loop's clock (design §8 step 20c), with aioquic as the slow peer. Four peers the server must end
# at the default limits:
#   1. a peer that completes the handshake and sends a PING every second, and no request, gets a
#      GOAWAY at the first-request deadline, 10 s, and then a close with H3_NO_ERROR;
#   2. a peer that sends half of a request's head gets a 408 on that stream at the head deadline,
#      10 s after the stream opened, and its connection serves a later request;
#   3. a peer that sends a head and three octets of its body gets a 408 when the body's first
#      window ends, the grace period and a window after the head, 20 s;
#   4. a peer that asks for a large file and acknowledges nothing of the response is closed with
#      H3_EXCESSIVE_LOAD when the first window ends, 20 s after its request.
# Each must end within a second after its instant and not before it. tools/deadlines.sh checks
# the same limits over TCP.
#
# It needs python3 and a Go toolchain for the identity. aioquic is pinned and installed once into
# the cached virtual environment tools/quic_aioquic.sh uses. It is not part of `zig build test`.
#
#   tools/h3_deadlines.sh
#
# The server binds port 0, and the run reads the port the kernel chose from its log, so two runs
# on one machine do not collide (https://github.com/c4milo/colibri/issues/94).
set -euo pipefail

readonly hostname="localhost"
readonly aioquic_version="1.3.0"
readonly venv="${XDG_CACHE_HOME:-$HOME/.cache}/colibri/aioquic-${aioquic_version}"

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

echo "h3_deadlines: building the endpoint and the peer"
zig build
go run tools/h2_interop/tls_identity.go "$scratch/identity"
if [ ! -x "$venv/bin/python" ]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q "aioquic==${aioquic_version}"
fi
export HQ_PEER_SCRATCH="$scratch"

mkdir -p "$scratch/www"
head -c 1000 /dev/urandom >"$scratch/www/small"
head -c 3000000 /dev/urandom >"$scratch/www/large"

# `errors`: the fourth peer ends its connection on a connection error, which the server expects.
./zig-out/bin/quic-udp server 127.0.0.1 0 "$scratch/identity" "$scratch/www" errors h3 \
  >"$scratch/colibri.log" 2>&1 &
server_pid=$!
port="$(tools/listening_port.sh "$scratch/colibri.log")"

if ! "$venv/bin/python" tools/quic_interop/slow_peer.py 127.0.0.1 "$port" "$scratch/identity" \
  "$hostname"; then
  echo "h3_deadlines: a peer was not ended as decision 110 says; colibri's server said:" >&2
  cat "$scratch/colibri.log" >&2
  exit 1
fi
if ! kill -0 "$server_pid" 2>/dev/null; then
  echo "h3_deadlines: colibri's server did not outlive its peers:" >&2
  cat "$scratch/colibri.log" >&2
  exit 1
fi
echo "h3_deadlines: ok"
