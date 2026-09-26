#!/usr/bin/env bash
#
# One QUIC handshake and one stream between a colibri client and a colibri server, both over
# chapulin's QUIC mode, in one process. Part of design §8 step 9e. It says whether colibri's
# connection drives a real TLS 1.3 handshake through `tls.QuicProvider` and protects real packets
# through `crypto.Suite`.
#
# It needs a Go toolchain, for the identity. chapulin comes from the package build.zig.zon pins
# (design §8 step 16a).
#
# It is not part of `zig build test`.
#
#   tools/quic_loopback.sh
#
# SSLKEYLOGFILE, when set, receives the run's traffic secrets in the NSS key log format.
set -euo pipefail

readonly hostname="localhost"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

echo "quic_loopback: building the check"
zig build

# The identity the server presents: the leaf, the root that signed it, and the P-256 scalar and
# point chapulin's ecdsa_p256 slot takes. The client pins the root.
go run tools/h2_interop/tls_identity.go "$scratch/identity"

./zig-out/bin/quic-loopback "$scratch/identity" "$hostname" "$(date +%s)" ${SSLKEYLOGFILE:+"$SSLKEYLOGFILE"}
echo "quic_loopback: ok"
