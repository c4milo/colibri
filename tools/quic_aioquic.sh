#!/usr/bin/env bash
#
# colibri's hq-interop endpoint against aioquic's, in both directions, over UDP on 127.0.0.1.
# Part of design §8 step 9e. It is the first check in which colibri's QUIC connection, and
# chapulin's QUIC mode beneath it, meet another implementation: a shared misreading of an RFC
# passes the loopback and tools/quic_udp.sh, and fails here.
#
# It needs python3, a Go toolchain for the identity, and a chapulin checkout whose QUIC object
# was built with `make RAND=drbg TRUST=webpki TRANSPORT=quic ROLE=both KEYLOG=on lib` and copied
# to bin/chapulin-quic.o. aioquic is pinned and installed once into a cached virtual environment.
# It is not part of `zig build test`.
#
#   tools/quic_aioquic.sh <chapulin-checkout> [port]
#
# SSLKEYLOGFILE, when set, receives both endpoints' traffic secrets.
set -euo pipefail

readonly checkout="${1:?usage: quic_aioquic.sh <chapulin-checkout> [port]}"
readonly port="${2:-44655}"
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

echo "quic_aioquic: building the endpoint and the peer"
zig build -Dchapulin-quic="$checkout"
go run tools/h2_interop/tls_identity.go "$scratch/identity"
if [ ! -x "$venv/bin/python" ]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q "aioquic==${aioquic_version}"
fi
peer=("$venv/bin/python" tools/quic_interop/hq_peer.py)
export HQ_PEER_SCRATCH="$scratch"

mkdir -p "$scratch/www" "$scratch/from_aioquic" "$scratch/from_colibri"
head -c 1000 /dev/urandom >"$scratch/www/small"
head -c 100000 /dev/urandom >"$scratch/www/medium"
head -c 3000000 /dev/urandom >"$scratch/www/large"
readonly files=(small medium large)

# Waits for a server's log to say it listens, and fails the run when it does not.
await_listening() {
  local log="$1"
  for _ in $(seq 1 100); do
    grep -q listening "$log" 2>/dev/null && return
    sleep 0.1
  done
  echo "quic_aioquic: the server did not start:" >&2
  cat "$log" >&2
  exit 1
}

compare() {
  local into="$1" direction="$2"
  for file in "${files[@]}"; do
    if ! cmp -s "$scratch/www/$file" "$into/$file"; then
      echo "quic_aioquic: $direction: $file arrived different from what the server holds" >&2
      exit 1
    fi
  done
  echo "quic_aioquic: $direction: every file arrived octet for octet"
}

# colibri's client against aioquic's server.
"${peer[@]}" server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" >"$scratch/aioquic.log" 2>&1 &
server_pid=$!
await_listening "$scratch/aioquic.log"
if ! ./zig-out/bin/quic-udp client 127.0.0.1 "$port" "$scratch/identity" "$hostname" "$(date +%s)" \
  "$scratch/from_aioquic" /small /medium /large; then
  echo "quic_aioquic: colibri's client failed; aioquic's server said:" >&2
  cat "$scratch/aioquic.log" >&2
  exit 1
fi
kill "$server_pid" 2>/dev/null || true
server_pid=""
compare "$scratch/from_aioquic" "colibri client, aioquic server"

# aioquic's client against colibri's server, which exits once its connection ends.
./zig-out/bin/quic-udp server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" once \
  >"$scratch/colibri.log" 2>&1 &
server_pid=$!
await_listening "$scratch/colibri.log"
if ! "${peer[@]}" client 127.0.0.1 "$port" "$scratch/identity" "$hostname" "$scratch/from_colibri" \
  /small /medium /large; then
  echo "quic_aioquic: aioquic's client failed; colibri's server said:" >&2
  cat "$scratch/colibri.log" >&2
  exit 1
fi
# aioquic's CONNECTION_CLOSE ends colibri's connection (RFC 9000 §10.2.2).
for _ in $(seq 1 50); do
  kill -0 "$server_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$server_pid" 2>/dev/null; then
  echo "quic_aioquic: colibri's server never saw aioquic's close" >&2
  exit 1
fi
if ! wait "$server_pid"; then
  echo "quic_aioquic: colibri's server failed:" >&2
  cat "$scratch/colibri.log" >&2
  exit 1
fi
server_pid=""
compare "$scratch/from_colibri" "aioquic client, colibri server"
echo "quic_aioquic: ok, aioquic ${aioquic_version}"
