#!/usr/bin/env bash
# Trace validation of spec/tla/h2_connection against colibri's server and client connections
# (https://github.com/c4milo/colibri/issues/79). The simulator's TCP trace run has a
# `client.Connection` and a `server.Connection` act out a seed's plan over h2, the client's first
# flight carrying its preface, its SETTINGS and requests the server reads in one delivery, and logs
# the model's state after each action. TLC then checks every seed's log is a behavior of the model
# (spec/tla/h2_connection/H2ConnectionTrace.tla), as tools/h2_trace.sh does for h2's own.
#
# It writes `sim --tcp-trace-write`'s modules into a scratch directory beside copies of the two
# model files, and runs `zig build tla` over their configurations. It needs Java, as
# `zig build tla` does, and it is not part of `zig build test`.
#
#   tools/tcp_trace.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly model="${repository_root}/spec/tla/h2_connection"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

cd "${repository_root}"
command -v java >/dev/null 2>&1 || { echo "tcp_trace.sh: java is not installed" >&2; exit 1; }
zig build sim -- --tcp-trace-write "${scratch}"
cp "${model}/H2Connection.tla" "${model}/H2ConnectionTrace.tla" "${scratch}/"
report="${scratch}/report.txt"
status=0
zig build tla -- "${scratch}"/TcpTraceSeed*.cfg >"${report}" 2>&1 || status=$?
followed="$(grep -c "violated, as expected" "${report}" || true)"
total="$(ls "${scratch}"/TcpTraceSeed*.cfg | wc -l | tr -d ' ')"
if [ "${status}" -ne 0 ]; then
  grep -E "error: \[tla\]" "${report}" >&2 || tail -20 "${report}" >&2
  echo "tcp_trace.sh: ${followed} of ${total} traces are behaviors of the model" >&2
  exit 1
fi
echo "tcp_trace.sh: ${followed} of ${total} traces are behaviors of the model"
