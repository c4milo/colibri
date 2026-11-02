#!/usr/bin/env bash
#
# OpenSSL's s_client against colibri's servers, over TCP and over QUIC, for the CNSA 2.0 key
# exchange (https://github.com/c4milo/colibri/issues/115). Each server selects ML-KEM-1024
# (0x0202) whenever the client lists it, and the client's older groups still work:
# - a client that sends an ML-KEM-1024 key share gets ML-KEM-1024 in one ServerHello;
# - a client that lists ML-KEM-1024 but sends only an X25519MLKEM768 share gets a
#   HelloRetryRequest that selects ML-KEM-1024 (RFC 9846 §4.1.4), and then ML-KEM-1024;
# - a client that lists X25519MLKEM768 alone, or x25519 alone, gets that group.
#
# It needs an OpenSSL that offers MLKEM1024 and speaks QUIC, 3.5 or newer, named by OPENSSL or
# found on the path, and a Go toolchain for the identity. It is not part of `zig build test`.
#
#   tools/tls_openssl.sh
#
# Each server binds port 0, and the run reads the port the kernel chose from its log
# (https://github.com/c4milo/colibri/issues/94).
set -euo pipefail

readonly hostname="localhost"
readonly openssl="${OPENSSL:-openssl}"
# Seconds a client may take before the run counts it as hung.
readonly client_seconds=10

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

if ! "$openssl" list -kem-algorithms 2>/dev/null | grep -q "ML-KEM-1024"; then
  echo "tls_openssl: $("$openssl" version 2>&1) offers no ML-KEM-1024; it needs OpenSSL 3.5 or newer" >&2
  exit 1
fi
echo "tls_openssl: $("$openssl" version)"

echo "tls_openssl: building the servers"
zig build
go run tools/h2_interop/tls_identity.go "$scratch/identity"
mkdir -p "$scratch/www"

# Prints the ServerHellos of an s_client -trace log, one line each: "hello <n> 0x<group>", with
# the NamedGroup's code point in hex. A HelloRetryRequest is a ServerHello too, so a retry prints
# two lines.
server_hellos() {
  awk '
    /^Received TLS Record/ { received = 1; next }
    /^Sent TLS Record/ { received = 0; next }
    received && /^    ServerHello,/ { hello += 1; wanted = 1; next }
    wanted && /NamedGroup:/ {
      code = $NF
      gsub(/[()]/, "", code)
      printf "hello %d 0x%04x\n", hello, code
      wanted = 0
    }
  ' "$1"
}

# expect <log> <want>: requires the ServerHellos of the log to be the lines of <want>.
expect() {
  local got
  got="$(server_hellos "$1")"
  if [ "$got" != "$2" ]; then
    echo "tls_openssl: $3: the server answered" >&2
    echo "${got:-no ServerHello}" >&2
    echo "tls_openssl: and not" >&2
    echo "$2" >&2
    tail -20 "$1" >&2
    exit 1
  fi
  echo "tls_openssl: $3: $(echo "$got" | awk '{ print $3 }' | paste -sd, -)"
}

# The groups each client lists, in its order, and the ServerHellos it must read. The first group
# is the one the client sends a key share for.
# ML-KEM-1024 is 0x0202, X25519MLKEM768 0x11ec, and x25519 0x001d.
readonly cases=(
  "MLKEM1024|hello 1 0x0202"
  "X25519MLKEM768:MLKEM1024|hello 1 0x0202"$'\n'"hello 2 0x0202"
  "X25519MLKEM768|hello 1 0x11ec"
  "x25519|hello 1 0x001d"
)

# Over TCP: tls-accept serves one connection, echoes one record, and requires the client's
# close_notify (RFC 9846 §6.1). It prints the group it selected too.
tcp_case() {
  local groups="$1" want="$2"
  ./zig-out/bin/tls-accept 0 "$scratch/identity" >"$scratch/tcp_server.log" 2>&1 &
  server_pid=$!
  local port
  port="$(tools/listening_port.sh "$scratch/tcp_server.log")"
  (printf ping; sleep 1) | timeout "$client_seconds" "$openssl" s_client -connect "127.0.0.1:$port" \
    -servername "$hostname" -alpn h2 -groups "$groups" -no_ign_eof -trace \
    >"$scratch/tcp_client.log" 2>&1 || true
  if ! wait "$server_pid"; then
    echo "tls_openssl: tcp $groups: colibri's server failed:" >&2
    cat "$scratch/tcp_server.log" >&2
    exit 1
  fi
  server_pid=""
  expect "$scratch/tcp_client.log" "$want" "tcp $groups"
}

# Over QUIC: the UDP server serves hq-interop. The client closes once its handshake completes.
quic_case() {
  local groups="$1" want="$2" port="$3"
  timeout "$client_seconds" "$openssl" s_client -quic -connect "127.0.0.1:$port" \
    -servername "$hostname" -alpn hq-interop -groups "$groups" -trace \
    </dev/null >"$scratch/quic_client.log" 2>&1 || true
  expect "$scratch/quic_client.log" "$want" "quic $groups"
}

for entry in "${cases[@]}"; do
  tcp_case "${entry%%|*}" "${entry#*|}"
done

./zig-out/bin/quic-udp server 127.0.0.1 0 "$scratch/identity" "$scratch/www" \
  >"$scratch/quic_server.log" 2>&1 &
server_pid=$!
quic_port="$(tools/listening_port.sh "$scratch/quic_server.log")"
for entry in "${cases[@]}"; do
  quic_case "${entry%%|*}" "${entry#*|}" "$quic_port"
done

echo "tls_openssl: ok"
