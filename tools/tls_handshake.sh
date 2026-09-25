#!/usr/bin/env bash
#
# One TLS 1.3 handshake between colibri's chapulin-backed client and a Go server, which is the
# first half of design §8 step 5's check. It says whether the two complete a handshake and agree
# on ALPN, which RFC 9113 §3.1 makes the thing h2 over TLS rests on.
#
# It needs a Go toolchain and a chapulin checkout built for the client role. It is not part of
# `zig build test`, which runs without either.
#
#   tools/tls_handshake.sh <chapulin-checkout> [port]
#
# The server mints its own CA and a leaf signed by it, writes the CA's Subject Name and
# SubjectPublicKeyInfo, and serves the chain. colibri pins that one root.
set -euo pipefail

readonly checkout="${1:?usage: tls_handshake.sh <chapulin-checkout> [port]}"
readonly port="${2:-44443}"
readonly hostname="localhost"

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

echo "tls_handshake: building the peer and the check"
go build -o "$scratch/tls_server" tools/h2_interop/tls_server.go
zig build -Dchapulin-client="$checkout"

"$scratch/tls_server" "$port" "$scratch/ca" > "$scratch/server.log" 2>&1 &
server_pid=$!

# The peer prints "ready" once both anchor files are written and the listener is open, so the
# client never races either.
for _ in $(seq 1 100); do
  grep -q ready "$scratch/server.log" 2>/dev/null && break
  sleep 0.1
done
if ! grep -q ready "$scratch/server.log" 2>/dev/null; then
  echo "tls_handshake: the peer did not start" >&2
  cat "$scratch/server.log" >&2
  exit 1
fi

# The clock is the caller's: no source file under src/ may read one (CLAUDE.md non-negotiable 3),
# and a webpki chain is valid only at a time.
if ! ./zig-out/bin/tls-handshake "$port" "$scratch/ca" "$hostname" "$(date +%s)" 2>&1 \
  | tee "$scratch/client.log"; then
  echo "tls_handshake: the handshake failed; the peer said:" >&2
  tail -5 "$scratch/server.log" >&2
  exit 1
fi

# RFC 9846 §7.5: both ends of one session export one value for one label and context. The peer
# prints its value while the client is still finishing, so it is written by the time this reads.
client_exporter="$(sed -n 's/^tls-handshake: exporter //p' "$scratch/client.log")"
server_exporter="$(sed -n 's/^exporter //p' "$scratch/server.log")"
if [ -z "$client_exporter" ] || [ "$client_exporter" != "$server_exporter" ]; then
  echo "tls_handshake: the exporters differ: colibri ${client_exporter:-none}," \
    "the peer ${server_exporter:-none}" >&2
  exit 1
fi

# RFC 9846 §4.7.1: Go's server sends a NewSessionTicket before its SETTINGS, and the client must
# open it and stay live (https://github.com/c4milo/colibri/issues/62).
if ! grep -q "records ok, [1-9][0-9]* carried no data" "$scratch/client.log"; then
  echo "tls_handshake: no record without data reached the client's record phase" >&2
  exit 1
fi

echo "tls_handshake: ok"
