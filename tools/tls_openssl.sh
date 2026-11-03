#!/usr/bin/env bash
#
# OpenSSL's s_client against colibri's servers, over TCP and over QUIC, for CNSA 2.0
# (https://github.com/c4milo/colibri/issues/115, design §8 step 33). Each server holds the Go
# tool's P-256 identity and the RSA and ML-DSA-87 ones of src/testing/testdata/ (decision 147), and
# chooses
# CNSA 2.0's algorithms first when the client offers them:
# - ML-KEM-1024 (0x0202) whenever the client lists it. A client that sends only an
#   X25519MLKEM768 share gets a HelloRetryRequest that selects ML-KEM-1024 (RFC 9846 §4.2.4).
# - TLS_AES_256_GCM_SHA384 (0x1302) when the client lists it, even after TLS_AES_128_GCM_SHA256.
# - mldsa87 (0x0906, draft-ietf-tls-mldsa-05 §3) when the client lists it.
# - ecdsa_secp256r1_sha256 before rsa_pss_rsae_sha256, in whatever order the client lists them.
# A client that lists only older algorithms still gets them: X25519MLKEM768 (0x11ec), x25519
# (0x001d), ecdsa_secp256r1_sha256 (0x0403) and rsa_pss_rsae_sha256 (0x0804).
#
# It needs an OpenSSL that offers ML-KEM-1024 and ML-DSA-87 and speaks QUIC, 3.5 or newer, named by
# OPENSSL or found on the path, and a Go toolchain for the P-256 identity. It is not part of `zig
# build test`.
#
#   tools/tls_openssl.sh
#
# Each server binds port 0, and the run reads the port the kernel chose from its log
# (https://github.com/c4milo/colibri/issues/94).
set -euo pipefail

readonly hostname="localhost"
readonly openssl="${OPENSSL:-openssl}"
readonly rsa="src/testing/testdata/identity.rsa"
readonly mldsa87="src/testing/testdata/identity.mldsa87"
# Seconds a client may take before the run counts it as hung.
readonly client_seconds=10

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

if ! "$openssl" list -kem-algorithms 2>/dev/null | grep -q "ML-KEM-1024" ||
  ! "$openssl" list -signature-algorithms 2>/dev/null | grep -q "ML-DSA-87"; then
  echo "tls_openssl: $("$openssl" version 2>&1) lacks ML-KEM-1024 or ML-DSA-87; it needs OpenSSL 3.5 or newer" >&2
  exit 1
fi
echo "tls_openssl: $("$openssl" version)"

echo "tls_openssl: building the servers"
zig build
go run tools/h2_interop/tls_identity.go "$scratch/identity"
mkdir -p "$scratch/www"

# Prints what the server chose, from an s_client -trace log, on one line: the group of each
# ServerHello, a HelloRetryRequest first when there is one, then the suite, then the signature
# scheme of the CertificateVerify. Each is a code point in hex, as "groups=0x0202 suite=0x1302
# signature=0x0906".
chosen() {
  awk '
    /^Received TLS Record/ { received = 1; next }
    /^Sent TLS Record/ { received = 0; next }
    received && /^    ServerHello,/ { hello = 1; next }
    hello && /cipher_suite \{/ {
      octets = $2 $3
      gsub(/[{},]|0x/, "", octets)
      suite = "0x" tolower(octets)
    }
    hello && /NamedGroup:/ {
      code = $NF
      gsub(/[()]/, "", code)
      groups = groups (groups == "" ? "" : ",") sprintf("0x%04x", code)
      hello = 0
    }
    received && /^    CertificateVerify,/ { verify = 1; next }
    verify && /Signature Algorithm:/ {
      code = $NF
      gsub(/[()]/, "", code)
      signature = code
      verify = 0
    }
    END { printf "groups=%s suite=%s signature=%s\n", groups, suite, signature }
  ' "$1"
}

# expect <log> <want> <name>: requires what the server chose to be <want>.
expect() {
  local got
  got="$(chosen "$1")"
  if [ "$got" != "$2" ]; then
    echo "tls_openssl: $3: the server chose $got, and not $2" >&2
    tail -20 "$1" >&2
    exit 1
  fi
  echo "tls_openssl: $3: $got"
}

# Each case: the client's s_client options, then what the server must choose. The first group a
# client lists is the one it sends a key share for. A case that names no group, suite or
# signature scheme keeps OpenSSL's own list.
readonly cases=(
  "-groups MLKEM1024|groups=0x0202 suite=0x1302 signature=0x0906"
  "-groups X25519MLKEM768:MLKEM1024|groups=0x0202,0x0202 suite=0x1302 signature=0x0906"
  "-groups X25519MLKEM768|groups=0x11ec suite=0x1302 signature=0x0906"
  "-groups x25519|groups=0x001d suite=0x1302 signature=0x0906"
  "-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384|groups=0x11ec suite=0x1302 signature=0x0906"
  "-ciphersuites TLS_AES_128_GCM_SHA256|groups=0x11ec suite=0x1301 signature=0x0906"
  "-sigalgs ecdsa_secp256r1_sha256:mldsa87|groups=0x11ec suite=0x1302 signature=0x0906"
  "-sigalgs ecdsa_secp256r1_sha256|groups=0x11ec suite=0x1302 signature=0x0403"
  "-sigalgs rsa_pss_rsae_sha256|groups=0x11ec suite=0x1302 signature=0x0804"
  "-sigalgs rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256|groups=0x11ec suite=0x1302 signature=0x0403"
)

# Over TCP: tls-accept serves one connection, echoes one record, and requires the client's
# close_notify (RFC 9846 §6.1).
tcp_case() {
  local options="$1" want="$2"
  ./zig-out/bin/tls-accept 0 "$scratch/identity" "rsa=$rsa" "mldsa87=$mldsa87" >"$scratch/tcp_server.log" 2>&1 &
  server_pid=$!
  local port
  port="$(tools/listening_port.sh "$scratch/tcp_server.log")"
  # shellcheck disable=SC2086 # each case's options are several words
  (printf ping; sleep 1) | timeout "$client_seconds" "$openssl" s_client -connect "127.0.0.1:$port" \
    -servername "$hostname" -alpn h2 -no_ign_eof -trace $options \
    >"$scratch/tcp_client.log" 2>&1 || true
  if ! wait "$server_pid"; then
    echo "tls_openssl: tcp $options: colibri's server failed:" >&2
    cat "$scratch/tcp_server.log" >&2
    exit 1
  fi
  server_pid=""
  expect "$scratch/tcp_client.log" "$want" "tcp $options"
}

# Over QUIC: the UDP server serves hq-interop. The client closes once its handshake completes.
quic_case() {
  local options="$1" want="$2" port="$3"
  # shellcheck disable=SC2086 # each case's options are several words
  timeout "$client_seconds" "$openssl" s_client -quic -connect "127.0.0.1:$port" \
    -servername "$hostname" -alpn hq-interop -trace $options \
    </dev/null >"$scratch/quic_client.log" 2>&1 || true
  expect "$scratch/quic_client.log" "$want" "quic $options"
}

for entry in "${cases[@]}"; do
  tcp_case "${entry%%|*}" "${entry#*|}"
done

./zig-out/bin/quic-udp server 127.0.0.1 0 "$scratch/identity" "$scratch/www" "rsa=$rsa" "mldsa87=$mldsa87" \
  >"$scratch/quic_server.log" 2>&1 &
server_pid=$!
quic_port="$(tools/listening_port.sh "$scratch/quic_server.log")"
for entry in "${cases[@]}"; do
  quic_case "${entry%%|*}" "${entry#*|}" "$quic_port"
done

echo "tls_openssl: ok"
