#!/usr/bin/env bash
# The h2spec check of docs/design.md §8 steps 4 and 5: run the pinned suite against the test-only
# h2 server of §9 and require every case to pass but the ones named below. It runs in cleartext
# twice: against the server with `--h2`, which speaks h2 alone with prior knowledge, and against
# the server naming no version, which reads h2's connection preface from each connection's first
# octets (decision 117). With --tls it runs over TLS as well (`h2spec -t -k`), through the server's
# record-mode chapulin (https://github.com/c4milo/colibri/issues/20). The TLS run also needs a Go
# toolchain, which mints the identity the server presents.
#
# h2spec is not installed by this repository. On macOS: brew install h2spec. Elsewhere, take the
# release named by h2spec_version from https://github.com/summerwind/h2spec.
#
# The server binds port 0 and the run reads the port the kernel chose from its log, so two runs
# on one machine do not collide (https://github.com/c4milo/colibri/issues/94).
#
# Usage: tools/h2spec.sh [--tls]
set -euo pipefail

readonly h2spec_version="2.6.0"
readonly tls="${1:-}"
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly server="${repository_root}/zig-out/bin/http-server"
readonly listening_port="${repository_root}/tools/listening_port.sh"

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
readonly skipped_reason="RFC 7540 §5.3.1, dropped by RFC 9113 §5.3.2"

# The case the server naming no version does not pass in cleartext, and why. It sends octets that
# are not the connection preface, and RFC 9113 §3.3 has a server that speaks both versions tell an
# h2 connection by its preface, so the server reads them as h11, which answers 400. RFC 9113 §3.4
# lets a server omit the GOAWAY, "since an invalid preface indicates that the peer is not using
# HTTP/2". The run with `--h2`, and the run over TLS, where ALPN chose h2, must pass it.
readonly preface_case="Sends invalid connection preface"
readonly preface_reason="RFC 9113 §3.3: a server speaking both reads what is not the preface as h11"

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

{ [ -z "${tls}" ] || [ "${tls}" = "--tls" ]; } && [ "$#" -le 1 ] || fail "usage: tools/h2spec.sh [--tls]"
echo "h2spec.sh: building the test-only server"
(cd "${repository_root}" && zig build install)
[ -x "${server}" ] || fail "the server was not built at ${server}"

# Runs the suite once against a server started with the given arguments, and checks the report.
# The first argument names the run, and the second says whether the preface case is expected to
# fail in it; the h2spec flags follow the server's arguments after "--".
run_suite() {
  local label="$1" preface_fails="$2"
  shift 2
  local server_arguments=()
  while [ "$1" != "--" ]; do
    server_arguments+=("$1")
    shift
  done
  shift
  "${server}" --port 0 ${server_arguments[@]+"${server_arguments[@]}"} 2>"${scratch}/${label}.server.log" &
  server_pid=$!
  # The server prints its port once every worker's listener is bound.
  local port
  port="$("${listening_port}" "${scratch}/${label}.server.log")" ||
    fail "the ${label} server did not listen"

  local report="${scratch}/${label}.txt"
  echo "h2spec.sh: running h2spec ${h2spec_version} against 127.0.0.1:${port} (${label})"
  # The release binary of h2spec 2.6.0, which CI installs, is built with Go 1.12, whose TLS client
  # offers TLS 1.3 only when GODEBUG sets tls13=1. chapulin speaks TLS 1.3 alone, so without it the
  # server refuses the handshake and every TLS case ends in EOF. A later Go ignores the setting.
  GODEBUG=tls13=1 h2spec "$@" -h 127.0.0.1 -p "${port}" generic hpack http2 >"${report}" 2>&1 || true
  kill "${server_pid}" 2>/dev/null || true
  wait "${server_pid}" 2>/dev/null || true
  server_pid=""
  tail -4 "${report}"

  local failed passed
  failed="$(grep -Eo '[0-9]+ failed' "${report}" | awk '{ total += $1 } END { print total + 0 }')"
  passed="$(grep -Eo '[0-9]+ passed' "${report}" | awk '{ total += $1 } END { print total + 0 }')"

  # The cases expected to fail in this run, each with its reason.
  local expected=("${skipped_cases[@]}") reasons=()
  for _ in "${skipped_cases[@]}"; do reasons+=("${skipped_reason}"); done
  if [ "${preface_fails}" = yes ]; then
    expected+=("${preface_case}")
    reasons+=("${preface_reason}")
  fi
  # h2spec lists each failed case under "Failures:", so a name found there failed.
  local failures
  failures="$(sed -n '/^Failures:/,$p' "${report}")"
  for skipped in "${expected[@]}"; do
    grep -qF "${skipped}" <<<"${failures}" || fail "the case named as skipped did not fail (${label}): ${skipped}"
  done

  if [ "${failed}" -ne "${#expected[@]}" ]; then
    echo "${failures}"
    fail "${failed} cases failed (${label}); ${#expected[@]} are named in this script as skipped"
  fi

  echo "h2spec.sh: ${label}: ${passed} passed, ${failed} skipped by name:"
  local index
  for index in "${!expected[@]}"; do
    echo "h2spec.sh:   ${expected[${index}]} (${reasons[${index}]})"
  done
}

run_suite cleartext-h2 no --h2 --
run_suite cleartext yes --

if [ -n "${tls}" ]; then
  command -v go >/dev/null 2>&1 || fail "the TLS run needs a Go toolchain to mint the identity"
  # The identity the server presents: the leaf, the root that signed it, and the P-256 scalar and
  # point chapulin's ecdsa_p256 slot takes. -k tells h2spec not to verify it.
  (cd "${repository_root}" && go run tools/h2_interop/tls_identity.go "${scratch}/identity" >/dev/null)
  run_suite tls no --tls "${scratch}/identity" -- -t -k
fi
