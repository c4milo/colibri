#!/usr/bin/env bash
#
# The h3spec check of docs/design.md §8 step 12: the pinned suite against design §9's h3 server,
# every case accounted for. h3spec is fetched once, checked against the SHA-256 pinned below, and
# cached; the release publishes no checksums, so the pins were taken from the files themselves.
#
# It needs a Go toolchain for the identity and a chapulin checkout whose QUIC object was built as
# tools/quic_udp.sh says. The server runs with `errors`, because h3spec breaks a rule on purpose
# on every connection it opens. It is not part of `zig build test`.
#
# h3spec's client offers AES-GCM and AES-CCM suites alone, and chapulin's QUIC mode protects
# packets with ChaCha20-Poly1305 alone, so today every handshake fails with handshake_failure and
# no case passes (design §8 step 12). The check runs once chapulin's QUIC mode offers AES-GCM.
#
#   tools/h3spec.sh <chapulin-checkout> [port]
set -euo pipefail

readonly checkout="${1:?usage: h3spec.sh <chapulin-checkout> [port]}"
readonly port="${2:-44833}"
readonly h3spec_version="v0.1.13"
readonly cache="${XDG_CACHE_HOME:-$HOME/.cache}/colibri/h3spec-${h3spec_version}"
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "h3spec.sh: $*" >&2
  exit 1
}

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)
    asset="h3spec-mac-arm64"
    digest="850ee3317b767db1e5e41cf3b9f034a74feabf52672744920ba41f330b710253"
    ;;
  Linux-x86_64)
    asset="h3spec-linux-x86_64"
    digest="b5f8eddd968cb195d1e3e7698d33fa141d6b2ad56153089d89928ac0fdee28bf"
    ;;
  *) fail "h3spec ${h3spec_version} publishes no binary for $(uname -s) $(uname -m)" ;;
esac
readonly h3spec="${cache}/${asset}"

if [ ! -x "$h3spec" ]; then
  mkdir -p "$cache"
  curl -fsSL -o "$h3spec.part" \
    "https://github.com/kazu-yamamoto/h3spec/releases/download/${h3spec_version}/${asset}"
  mv "$h3spec.part" "$h3spec"
  chmod +x "$h3spec"
fi
found="$(shasum -a 256 "$h3spec" | awk '{print $1}')"
[ "$found" = "$digest" ] || fail "$h3spec has SHA-256 $found, not the pinned $digest"

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

cd "$repository_root"
echo "h3spec.sh: building the endpoint"
zig build -Dchapulin-quic="$checkout"
go run tools/h2_interop/tls_identity.go "$scratch/identity"
mkdir -p "$scratch/www"
./zig-out/bin/quic-udp server 127.0.0.1 "$port" "$scratch/identity" "$scratch/www" errors \
  >"$scratch/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 100); do
  grep -q listening "$scratch/server.log" 2>/dev/null && break
  sleep 0.1
done
grep -q listening "$scratch/server.log" || fail "the server did not start: $(cat "$scratch/server.log")"

echo "h3spec.sh: running h3spec ${h3spec_version} against 127.0.0.1:${port}"
status=0
"$h3spec" 127.0.0.1 "$port" --no-validate >"$scratch/report" 2>&1 || status=$?
sed -n '/^QUIC servers/,/^Failures:/p' "$scratch/report"
grep -E "examples, [0-9]+ failure" "$scratch/report" || true
if grep -q handshake_failure "$scratch/server.log"; then
  echo "h3spec.sh: handshakes failed: h3spec offers AES suites alone, and chapulin's QUIC mode ChaCha20-Poly1305 alone" >&2
fi
[ "$status" -eq 0 ] || fail "h3spec reported failures"
echo "h3spec.sh: ok, every case passed"
