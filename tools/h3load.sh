#!/usr/bin/env bash
#
# h2load --h3 against design §9's h3 server (design §8 step 12): every request must succeed with a
# 2xx over ALPN h3. It checks, and measures nothing: decision 32 publishes numbers from Linux
# alone, through bench/.
#
# h2load comes from tools/h3load/Dockerfile, which builds it with HTTP/3 from pinned release tags,
# because Debian's h2load has none. It needs Docker, a Go toolchain for the identity, and a
# chapulin checkout whose QUIC object was built as tools/quic_udp.sh says. It is not part of
# `zig build test`.
#
#   tools/h3load.sh <chapulin-checkout> [requests] [port]
set -euo pipefail

readonly checkout="${1:?usage: h3load.sh <chapulin-checkout> [requests] [port]}"
readonly requests="${2:-1000}"
readonly port="${3:-44823}"
readonly image="colibri-h3load:latest"
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly clients=10
readonly streams_per_client=10

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

fail() {
  echo "h3load.sh: $*" >&2
  exit 1
}

cd "$repository_root"
echo "h3load.sh: building the endpoint and h2load"
zig build -Dchapulin-quic="$checkout"
docker image inspect "$image" >/dev/null 2>&1 || docker build -q -t "$image" tools/h3load >/dev/null
go run tools/h2_interop/tls_identity.go "$scratch/identity"
mkdir -p "$scratch/www"

# A container reaches the host through host networking on Linux. Docker Desktop has none by
# default, so there the server listens on every address and the container names the host.
docker_network=()
target="127.0.0.1"
bind="127.0.0.1"
if [ "$(uname)" = Darwin ]; then
  bind="0.0.0.0"
  target='$(getent ahostsv4 host.docker.internal | awk "NR == 1 { print \$1 }")'
else
  docker_network=(--network host)
fi

./zig-out/bin/quic-udp server "$bind" "$port" "$scratch/identity" "$scratch/www" >"$scratch/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 100); do
  grep -q listening "$scratch/server.log" 2>/dev/null && break
  sleep 0.1
done
grep -q listening "$scratch/server.log" || fail "the server did not start: $(cat "$scratch/server.log")"

docker run --rm "${docker_network[@]}" "$image" sh -c \
  "h2load --alpn-list=h3 -n $requests -c $clients -m $streams_per_client https://$target:$port/" \
  >"$scratch/h2load.log" 2>&1 || true
grep -E "Application protocol|finished in|requests:|status codes:" "$scratch/h2load.log" || true

grep -q "Application protocol: h3" "$scratch/h2load.log" || fail "h2load did not negotiate h3"
grep -q "requests: $requests total, $requests started, $requests done, $requests succeeded, 0 failed" \
  "$scratch/h2load.log" || fail "not every request succeeded; the server said: $(cat "$scratch/server.log")"
grep -q "status codes: $requests 2xx" "$scratch/h2load.log" || fail "not every response was a 2xx"
echo "h3load.sh: ok, $requests requests over h3"
