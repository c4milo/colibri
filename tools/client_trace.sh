#!/usr/bin/env bash
# Trace validation of spec/tla/client_exchanges against colibri (decision 105). The simulator's
# client trace run has a `client.Origin` carry each seed's exchanges over QUIC and TCP, and logs
# the model's state after each instant; TLC then checks every seed's log is a behavior of the
# model (spec/tla/client_exchanges/ClientExchangesTrace.tla).
#
# It writes `sim --client-trace-write`'s modules into a scratch directory beside copies of the two
# model files, and runs `zig build tla` over their configurations. It needs Java, as
# `zig build tla` does, and it is not part of `zig build test`.
#
#   tools/client_trace.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly model="${repository_root}/spec/tla/client_exchanges"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

cd "${repository_root}"
command -v java >/dev/null 2>&1 || { echo "client_trace.sh: java is not installed" >&2; exit 1; }
zig build sim -- --client-trace-write "${scratch}"
cp "${model}/ClientExchanges.tla" "${model}/ClientExchangesTrace.tla" "${scratch}/"
report="${scratch}/report.txt"
status=0
zig build tla -- "${scratch}"/ClientTraceSeed*.cfg >"${report}" 2>&1 || status=$?
followed="$(grep -c "violated, as expected" "${report}" || true)"
total="$(ls "${scratch}"/ClientTraceSeed*.cfg | wc -l | tr -d ' ')"
if [ "${status}" -ne 0 ]; then
  grep -E "error: \[tla\]" "${report}" >&2 || tail -20 "${report}" >&2
  echo "client_trace.sh: ${followed} of ${total} traces are behaviors of the model" >&2
  exit 1
fi
echo "client_trace.sh: ${followed} of ${total} traces are behaviors of the model"
