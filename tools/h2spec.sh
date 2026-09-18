#!/usr/bin/env bash
# The h2spec check of docs/design.md §8 step 4: run the pinned suite against the test-only
# cleartext h2 server of §9 and require every case to pass but the ones named below.
#
# h2spec is not installed by this repository. On macOS: brew install h2spec. Elsewhere, take the
# release named by h2spec_version from https://github.com/summerwind/h2spec.
#
# Usage: tools/h2spec.sh [port]
set -euo pipefail

readonly h2spec_version="2.6.0"
readonly port="${1:-18443}"
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly server="${repository_root}/zig-out/bin/h2-server"

# The cases colibri does not pass, and why. Each one tests a rule RFC 7540 §5.3.1 stated and
# RFC 9113 dropped with the rest of the priority scheme: §5.3.2 deprecates the signalling and §6.3
# keeps only two rules, a stream identifier of 0 and no PRIORITY inside a field block, both of
# which colibri enforces. colibri reads RFC 9113 and never RFC 7540 (CLAUDE.md), and decision 18
# parses the priority fields without acting on them, so a stream that depends on itself is a
# signal colibri ignores rather than an error it reports.
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

echo "h2spec.sh: building the test-only server"
(cd "${repository_root}" && zig build install)
[ -x "${server}" ] || fail "the server was not built at ${server}"

"${server}" --port "${port}" &
readonly server_pid=$!
trap 'kill "${server_pid}" 2>/dev/null || true' EXIT

# Wait one second for the listener to start accepting connections before the first case connects.
sleep 1
kill -0 "${server_pid}" 2>/dev/null || fail "the server exited before the suite started"

readonly report="$(mktemp)"
trap 'kill "${server_pid}" 2>/dev/null || true; rm -f "${report}"' EXIT
echo "h2spec.sh: running h2spec ${h2spec_version} against 127.0.0.1:${port}"
h2spec -h 127.0.0.1 -p "${port}" generic hpack http2 >"${report}" 2>&1 || true
tail -4 "${report}"

failed="$(grep -Eo '[0-9]+ failed' "${report}" | awk '{ total += $1 } END { print total + 0 }')"
passed="$(grep -Eo '[0-9]+ passed' "${report}" | awk '{ total += $1 } END { print total + 0 }')"

for skipped in "${skipped_cases[@]}"; do
  grep -qF "${skipped}" "${report}" || fail "the case named as skipped did not run: ${skipped}"
done

if [ "${failed}" -ne "${#skipped_cases[@]}" ]; then
  sed -n '/^Failures:/,$p' "${report}"
  fail "${failed} cases failed; ${#skipped_cases[@]} are named in this script as skipped"
fi

echo "h2spec.sh: ${passed} passed, ${failed} skipped by name:"
for skipped in "${skipped_cases[@]}"; do
  echo "h2spec.sh:   ${skipped} (RFC 7540 §5.3.1, dropped by RFC 9113 §5.3.2)"
done
