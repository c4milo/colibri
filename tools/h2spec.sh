#!/usr/bin/env bash
# The h2spec check of docs/design.md §8 steps 4 and 5: run the pinned suite against the test-only
# h2 server of §9 and require every case to pass but the ones named below. It runs in cleartext
# with prior knowledge, and, given a chapulin checkout, over TLS as well (`h2spec -t -k`), through
# the server's record-mode chapulin (https://github.com/c4milo/colibri/issues/20). The TLS run also
# needs a Go toolchain, which mints the identity the server presents.
#
# h2spec is not installed by this repository. On macOS: brew install h2spec. Elsewhere, take the
# release named by h2spec_version from https://github.com/summerwind/h2spec.
#
# Usage: tools/h2spec.sh [port] [chapulin-checkout]
set -euo pipefail

readonly h2spec_version="2.6.0"
readonly port="${1:-18443}"
readonly checkout="${2:-}"
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly server="${repository_root}/zig-out/bin/http-server"

# The cases colibri does not pass, and why. Each one tests a rule RFC 7540 §5.3.1 stated and
# RFC 9113 dropped with the rest of the priority scheme: §5.3.2 deprecates the signalling and §6.3
# keeps only two rules, a stream identifier of 0 and no PRIORITY inside a field block, both of
# which colibri enforces. colibri reads RFC 9113 and never RFC 7540 (CLAUDE.md), and decision 18
# parses the priority fields without acting on them, so a stream that depends on itself is a
# signal colibri ignores rather than an error it reports. The owner ruled this on 2026-09-18:
# docs/decisions.md entry 41.
readonly skipped_cases=(
  "Sends HEADERS frame that depends on itself"
  "Sends PRIORITY frame that depend on itself"
)

fail() {
  echo "h2spec.sh: $*" >&2
  exit 1
}

command -v h2spec >/dev/null 2>&1 || fail "h2spec is not installed; see the header of this script"

installed_version="$(h2spec --version 2>&1 | head -1 | awk '{print $2}')"
[ "${installed_version}" = "${h2spec_version}" ] ||
  fail "h2spec ${installed_version} is installed; this check is pinned to ${h2spec_version}"

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "${server_pid}" ] && kill "${server_pid}" 2>/dev/null || true
  rm -rf "${scratch}"
}
trap cleanup EXIT

echo "h2spec.sh: building the test-only server"
if [ -n "${checkout}" ]; then
  (cd "${repository_root}" && zig build install -Dchapulin-server="${checkout}")
else
  (cd "${repository_root}" && zig build install)
fi
[ -x "${server}" ] || fail "the server was not built at ${server}"

# Runs the suite once against a server started with the given arguments, and checks the report.
# The first argument names the run; the h2spec flags follow the server's arguments after "--".
run_suite() {
  local label="$1"
  shift
  local server_arguments=()
  while [ "$1" != "--" ]; do
    server_arguments+=("$1")
    shift
  done
  shift
  "${server}" --port "${port}" "${server_arguments[@]}" &
  server_pid=$!
  # Wait one second for the listener to start accepting connections before the first case connects.
  sleep 1
  kill -0 "${server_pid}" 2>/dev/null || fail "the ${label} server exited before the suite started"

  local report="${scratch}/${label}.txt"
  echo "h2spec.sh: running h2spec ${h2spec_version} against 127.0.0.1:${port} (${label})"
  h2spec "$@" -h 127.0.0.1 -p "${port}" generic hpack http2 >"${report}" 2>&1 || true
  kill "${server_pid}" 2>/dev/null || true
  wait "${server_pid}" 2>/dev/null || true
  server_pid=""
  tail -4 "${report}"

  local failed passed
  failed="$(grep -Eo '[0-9]+ failed' "${report}" | awk '{ total += $1 } END { print total + 0 }')"
  passed="$(grep -Eo '[0-9]+ passed' "${report}" | awk '{ total += $1 } END { print total + 0 }')"

  for skipped in "${skipped_cases[@]}"; do
    grep -qF "${skipped}" "${report}" || fail "the case named as skipped did not run (${label}): ${skipped}"
  done

  if [ "${failed}" -ne "${#skipped_cases[@]}" ]; then
    sed -n '/^Failures:/,$p' "${report}"
    fail "${failed} cases failed (${label}); ${#skipped_cases[@]} are named in this script as skipped"
  fi

  echo "h2spec.sh: ${label}: ${passed} passed, ${failed} skipped by name:"
  for skipped in "${skipped_cases[@]}"; do
    echo "h2spec.sh:   ${skipped} (RFC 7540 §5.3.1, dropped by RFC 9113 §5.3.2)"
  done
}

run_suite cleartext --

if [ -n "${checkout}" ]; then
  command -v go >/dev/null 2>&1 || fail "the TLS run needs a Go toolchain to mint the identity"
  # The identity the server presents: the leaf, the root that signed it, and the P-256 scalar and
  # point chapulin's ecdsa_p256 slot takes. -k tells h2spec not to verify it.
  (cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${scratch}/identity" >/dev/null)
  run_suite tls --tls "${scratch}/identity" -- -t -k
fi
