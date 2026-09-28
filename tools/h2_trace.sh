#!/usr/bin/env bash
# Trace validation of spec/tla/h2_connection against colibri
# (https://github.com/c4milo/colibri/issues/75). The simulator's h2 trace run acts out a seed's
# plan with colibri's h2 client and server and logs the model's state after each step; TLC then
# checks every seed's log is a behavior of the model (spec/tla/h2_connection/H2ConnectionTrace.tla).
#
# It writes `sim --h2-trace-write`'s modules into a scratch directory beside copies of the two
# model files, and runs `zig build tla` over their configurations. It needs Java, as
# `zig build tla` does, and it is not part of `zig build test`.
#
#   tools/h2_trace.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly model="${repository_root}/spec/tla/h2_connection"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

cd "${repository_root}"
command -v java >/dev/null 2>&1 || { echo "h2_trace.sh: java is not installed" >&2; exit 1; }
zig build sim -- --h2-trace-write "${scratch}"
cp "${model}/H2Connection.tla" "${model}/H2ConnectionTrace.tla" "${scratch}/"
report="${scratch}/report.txt"
status=0
zig build tla -- "${scratch}"/H2TraceSeed*.cfg >"${report}" 2>&1 || status=$?
followed="$(grep -c "violated, as expected" "${report}" || true)"
total="$(ls "${scratch}"/H2TraceSeed*.cfg | wc -l | tr -d ' ')"
if [ "${status}" -ne 0 ]; then
  grep -E "error: \[tla\]" "${report}" >&2 || tail -20 "${report}" >&2
  echo "h2_trace.sh: ${followed} of ${total} traces are behaviors of the model" >&2
  exit 1
fi
echo "h2_trace.sh: ${followed} of ${total} traces are behaviors of the model"
