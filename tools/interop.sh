#!/usr/bin/env bash
#
# Runs colibri's endpoint in the QUIC Interop Runner against other implementations, as a server
# and as a client. Design §8 step 9e's piece 11 and design §9's interop check.
#
#   tools/interop.sh [peers] [tests]
#
# peers and tests are the runner's comma-separated names; the defaults are below. It needs Docker
# with docker compose, python3, and tshark from Wireshark 4.5.0 or newer, which the runner reads
# packet captures with. The runner is cloned at a pinned commit into a cache directory, with its
# requirements in a virtual environment there, and colibri is registered in that clone's
# implementations_quic.json. The clone carries two patches, quic_interop/count_handshakes.patch
# (decision 99) and quic_interop/rebind_challenges.patch (decision 106). Test cases the endpoint
# does not build exit 127 and show as unsupported. Every qlog file colibri's endpoint wrote must
# pass tools/qlog_check.py (design §8 step 18c). It is not part of `zig build test`, and it takes
# minutes.
set -euo pipefail

readonly peers="${1:-quic-go}"
readonly tests="${2:-handshake,transfer,chacha20,multiplexing,handshakeloss,transferloss,retry,keyupdate,amplificationlimit,ipv6,ecn,longrtt,blackhole,rebind-port,rebind-addr,resumption,http3}"
readonly runner_commit="740c05a10b61d65e8abd3ad38d60898004d335d9"
readonly runner="${XDG_CACHE_HOME:-$HOME/.cache}/colibri/quic-interop-runner-${runner_commit}"
readonly image="colibri-qns:latest"
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for tool in docker python3 tshark; do
  command -v "$tool" >/dev/null || { echo "interop: $tool is not installed" >&2; exit 1; }
done

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# The image builds from colibri's working tree, fetched packages included, so it runs exactly what
# this machine has. The packages come first, so zig-pkg/ holds chapulin's.
echo "interop: building $image"
(cd "$repository_root" && zig build --fetch=all)
mkdir -p "$scratch/context/colibri"
rsync -a --exclude .zig-cache --exclude zig-out --exclude .git "$repository_root/" "$scratch/context/colibri/"
cp "$repository_root"/tools/quic_interop/{Dockerfile,run_endpoint.sh,qns_identity.py} "$scratch/context/"
docker build -q -t "$image" "$scratch/context" >/dev/null

if [ ! -d "$runner" ]; then
  git clone -q https://github.com/quic-interop/quic-interop-runner "$runner"
  git -C "$runner" checkout -q "$runner_commit"
fi
# Decision 99: count the client's connection attempts as handshakes, until
# https://github.com/quic-interop/quic-interop-runner/pull/509 is merged. The patch goes on the
# pinned testcase.py, so a clone that carries an earlier patch takes the current one, and a pinned
# file the patch no longer applies to stops the run.
readonly count_patch="$repository_root/tools/quic_interop/count_handshakes.patch"
git -C "$runner" checkout -q "$runner_commit" -- testcase.py
git -C "$runner" apply "$count_patch"
# Decision 106: a rebinding test's new path passes once the client answers any PATH_CHALLENGE sent
# on it, until https://github.com/quic-interop/quic-interop-runner/pull/511 is merged. The patch
# goes on the pinned testcases_quic.py, as the one above goes on testcase.py.
readonly rebind_patch="$repository_root/tools/quic_interop/rebind_challenges.patch"
git -C "$runner" checkout -q "$runner_commit" -- testcases_quic.py
git -C "$runner" apply "$rebind_patch"
if [ ! -x "$runner/venv/bin/python" ]; then
  python3 -m venv "$runner/venv"
  "$runner/venv/bin/pip" install -q -r "$runner/requirements.txt"
fi
python3 - "$runner/implementations_quic.json" "$image" <<'PY'
import json, sys
path, image = sys.argv[1], sys.argv[2]
implementations = json.load(open(path))
implementations["colibri"] = {"image": image, "url": "https://github.com/c4milo/colibri", "role": "both"}
json.dump(implementations, open(path, "w"), indent=2)
PY

cd "$runner"
status=0
echo "interop: colibri as the server"
venv/bin/python "$repository_root/tools/quic_interop/run_runner.py" -s colibri -c "colibri,$peers" -t "$tests" -l "$scratch/logs-server" \
  -m >"$scratch/server.md" || status=1
echo "interop: colibri as the client"
venv/bin/python "$repository_root/tools/quic_interop/run_runner.py" -s "$peers" -c colibri -t "$tests" -l "$scratch/logs-client" \
  -m >"$scratch/client.md" || status=1
cat "$scratch/server.md" "$scratch/client.md"
# Design §8 step 18c: the runner keeps each test case's logs, and colibri's side of each holds the
# qlog files of its connections (main schema §12.1). A connection the runner stopped mid-way ends
# its file early, so the check asks for well-formed records and not for each connection's close.
qlog_directories=0
qlog_failures=0
for directory in "$scratch"/logs-*/colibri_*/*/server/qlog "$scratch"/logs-*/*_colibri/*/client/qlog; do
  [ -d "$directory" ] || continue
  qlog_directories=$((qlog_directories + 1))
  python3 "$repository_root/tools/qlog_check.py" "$directory" >/dev/null || {
    echo "interop: $directory failed tools/qlog_check.py" >&2
    qlog_failures=$((qlog_failures + 1))
    status=1
  }
done
echo "interop: $qlog_directories test cases left colibri's qlog files, and $qlog_failures failed tools/qlog_check.py"
if [ "$status" -ne 0 ] && [ -n "${INTEROP_LOGS:-}" ]; then
  mkdir -p "$INTEROP_LOGS"
  cp -R "$scratch/logs-server" "$scratch/logs-client" "$INTEROP_LOGS"/
  echo "interop: logs copied to $INTEROP_LOGS"
fi
exit "$status"
