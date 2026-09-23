#!/usr/bin/env bash
#
# One TLS 1.3 handshake in which colibri is the server, which is the second half of design §8
# step 5's check. It says whether chapulin's server behind colibri's `tls.Provider` completes a
# handshake with Go's crypto/tls client, whether the two agree on ALPN (RFC 9113 §3.1), and
# whether the record phase works from the server side: one record each way, then the client's
# close_notify read as the end of its data rather than as a failure (RFC 9846 §6.1).
#
# It needs a Go toolchain and a chapulin checkout built for the server role. It is not part of
# `zig build test`, which runs without either.
#
#   tools/tls_accept.sh <chapulin-checkout> [port]
#
# The run mints its own CA and a leaf signed by it, hands colibri the leaf, the root and the
# signing key, and has the client pin that one root.
set -euo pipefail

readonly checkout="${1:?usage: tls_accept.sh <chapulin-checkout> [port]}"
readonly port="${2:-44444}"
readonly hostname="localhost"

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

echo "tls_accept: building the check and the peer"
zig build -Dchapulin-server="$checkout"
go build -o "$scratch/tls_client" tools/h2_interop/tls_client.go

# The identity colibri serves: the leaf, the root that signed it, and the P-256 scalar and point
# chapulin's ecdsa_p256 slot takes. All raw DER or raw octets, never PEM.
go run tools/h2_interop/tls_identity.go "$scratch/identity"

./zig-out/bin/tls-accept "$port" "$scratch/identity" > "$scratch/server.log" 2>&1 &
server_pid=$!

# The check prints "ready" once the listener is open, so the client never races it.
for _ in $(seq 1 100); do
  grep -q ready "$scratch/server.log" 2>/dev/null && break
  sleep 0.1
done
if ! grep -q ready "$scratch/server.log" 2>/dev/null; then
  echo "tls_accept: colibri's server did not start" >&2
  cat "$scratch/server.log" >&2
  exit 1
fi

if ! "$scratch/tls_client" "$port" "$scratch/identity" "$hostname" | tee "$scratch/client.log"; then
  echo "tls_accept: the client failed; colibri's server said:" >&2
  cat "$scratch/server.log" >&2
  exit 1
fi

# The server half must also have finished: it owes the echo and the clean close.
wait "$server_pid" || {
  echo "tls_accept: colibri's server failed:" >&2
  cat "$scratch/server.log" >&2
  exit 1
}
server_pid=""
cat "$scratch/server.log"

# RFC 9846 §7.5: both ends of one session export one value for one label and context.
client_exporter="$(sed -n 's/^tls_client: exporter //p' "$scratch/client.log")"
server_exporter="$(sed -n 's/^tls-accept: exporter //p' "$scratch/server.log")"
if [ -z "$server_exporter" ] || [ "$server_exporter" != "$client_exporter" ]; then
  echo "tls_accept: the exporters differ: colibri ${server_exporter:-none}," \
    "the peer ${client_exporter:-none}" >&2
  exit 1
fi

echo "tls_accept: ok"
