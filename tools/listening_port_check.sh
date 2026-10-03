#!/usr/bin/env bash
# The check of tools/listening_port.sh, which every check script waits for its peers with
# (docs/decisions.md entry 114). The helper must print the port of a log written after it
# starts, and must fail, showing what the log holds, for a log that never comes and for one
# that names no port. `tools/ci.sh` runs it.
#
# Usage: tools/listening_port_check.sh
set -euo pipefail

readonly helper="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/listening_port.sh"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
# The port the late log names, and how long the helper may wait for it.
readonly port_named=43210
readonly late_wait_seconds=5

fail() {
  echo "listening_port_check.sh: $*" >&2
  exit 1
}

# A script starts its peer in the background, and the peer's shell creates the log after the
# script has gone on. Two runs at once found the helper failing on that log before it existed.
(
  sleep 0.5
  echo "peer: listening on port ${port_named}, and more" >"${scratch}/late.log"
) &
port="$("${helper}" "${scratch}/late.log" "${late_wait_seconds}")" || fail "a log written late was refused"
[ "${port}" = "${port_named}" ] || fail "a log written late gave port ${port}"
wait

# A peer that never starts, and one that prints no port, each end the wait with a failure.
if "${helper}" "${scratch}/never.log" 1 2>/dev/null; then
  fail "a log that never came gave a port"
fi
echo "peer: failed to bind" >"${scratch}/silent.log"
if said="$("${helper}" "${scratch}/silent.log" 1 2>&1)"; then
  fail "a log that names no port gave one"
fi
[[ "${said}" == *"failed to bind"* ]] || fail "the failure does not show what the log holds"
echo "listening_port_check.sh: ok"
