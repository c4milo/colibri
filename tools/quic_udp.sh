#!/usr/bin/env bash
#
# A colibri hq-interop client fetches files from a colibri hq-interop server over real UDP on
# 127.0.0.1, both over chapulin's QUIC mode and Rotor's loop. Part of design §8 step 9e. Each
# file must arrive octet for octet, and a client with `resumption` must resume its first
# connection's session on its second (RFC 9846 §2.2).
#
# It needs a Go toolchain, for the identity, and a chapulin checkout whose QUIC object was built
# with `make RAND=drbg TRUST=webpki TRANSPORT=quic ROLE=both KEYLOG=on lib` and copied to
# bin/chapulin-quic.o. It is not part of `zig build test`.
#
#   tools/quic_udp.sh <chapulin-checkout> [port]
#
# SSLKEYLOGFILE, when set, receives both endpoints' traffic secrets.
set -euo pipefail

readonly checkout="${1:?usage: quic_udp.sh <chapulin-checkout> [port]}"
readonly port="${2:-44555}"
readonly hostname="localhost"

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

echo "quic_udp: building the endpoint"
zig build -Dchapulin-quic="$checkout"
go run tools/h2_interop/tls_identity.go "$scratch/identity"

# Three files: one smaller than a packet, one of many packets, and one past the receive pool,
# which only arrives if the client's reads give the server credit (RFC 9000 §4.1).
mkdir -p "$scratch/www" "$scratch/downloads"
head -c 1000 /dev/urandom >"$scratch/www/small"
head -c 100000 /dev/urandom >"$scratch/www/medium"
head -c 3000000 /dev/urandom >"$scratch/www/large"

# Starts a server with the options given, and waits for it to listen. With `once` it exits when
# its first connection ends.
start_server() {
  ./zig-out/bin/quic-udp server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" "$@" \
    >"$scratch/server.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 100); do
    grep -q listening "$scratch/server.log" 2>/dev/null && break
    sleep 0.1
  done
  if ! grep -q listening "$scratch/server.log"; then
    echo "quic_udp: the server did not start" >&2
    cat "$scratch/server.log" >&2
    exit 1
  fi
}

client() {
  ./zig-out/bin/quic-udp client 127.0.0.1 "$port" "$scratch/identity" "$hostname" "$(date +%s)" \
    "$scratch/downloads" "$@"
}

start_server once
if ! client /small /medium /large; then
  echo "quic_udp: the client failed; the server said:" >&2
  cat "$scratch/server.log" >&2
  exit 1
fi
# The client's CONNECTION_CLOSE ends the server's connection at once (RFC 9000 §10.2.2). A server
# still running after a few seconds never received it, and would sit out its idle timeout.
for _ in $(seq 1 50); do
  kill -0 "$server_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$server_pid" 2>/dev/null; then
  echo "quic_udp: the server never saw the client's close" >&2
  exit 1
fi
wait "$server_pid" || {
  echo "quic_udp: the server failed:" >&2
  cat "$scratch/server.log" >&2
  exit 1
}
server_pid=""
cat "$scratch/server.log"

for file in small medium large; do
  if ! cmp -s "$scratch/www/$file" "$scratch/downloads/$file"; then
    echo "quic_udp: $file arrived different from what the server holds" >&2
    exit 1
  fi
done
# A path the server does not hold is answered by resetting its stream, which the client reports.
start_server once
if client /small /missing >"$scratch/missing.log" 2>&1; then
  echo "quic_udp: the client fetched a file the server does not hold" >&2
  exit 1
fi
if ! grep -q StreamReset "$scratch/missing.log"; then
  echo "quic_udp: a missing file did not reset its stream:" >&2
  cat "$scratch/missing.log" >&2
  exit 1
fi
kill "$server_pid" 2>/dev/null || true
server_pid=""
# A server given the time issues a ticket, and the client's second connection presents it.
# chapulin fails a handshake whose ticket the server declines, so a second connection that
# fetches its file resumed.
rm -f "$scratch/downloads/small" "$scratch/downloads/medium"
start_server "seconds=$(date +%s)"
if ! client resumption /small /medium >"$scratch/resumption.log" 2>&1; then
  echo "quic_udp: the resuming client failed:" >&2
  cat "$scratch/resumption.log" "$scratch/server.log" >&2
  exit 1
fi
kill "$server_pid" 2>/dev/null || true
server_pid=""
cat "$scratch/resumption.log"
grep -q "resumed the first" "$scratch/resumption.log" || {
  echo "quic_udp: the client did not resume" >&2
  exit 1
}
# The first connection fetches one file and the second the other.
grep -q "fetched 2 of 2 files, 101000 octets" "$scratch/resumption.log" || {
  echo "quic_udp: the two connections did not split the files between them" >&2
  exit 1
}
for file in small medium; do
  if ! cmp -s "$scratch/www/$file" "$scratch/downloads/$file"; then
    echo "quic_udp: $file arrived different from what the server holds on resumption" >&2
    exit 1
  fi
done
echo "quic_udp: ok"
