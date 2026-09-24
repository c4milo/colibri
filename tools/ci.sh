#!/usr/bin/env bash
# Every check of this repository in one run, with a report: what .github/workflows/main.yml runs
# on each push to main (docs/decisions.md entry 46), and what a person runs by hand to get the
# same answer. It runs every section even after one fails, so the report is whole, and exits
# non-zero when any section failed.
#
# The report separates two kinds of number. The counted costs and the simulator's checksums are
# exact: a change in one is a change in the code. The h2load throughput is indicative: a hosted
# runner pins no core and fixes no governor, which decision 33 requires of a published number, so
# it shows a large regression and proves nothing about a small one.
#
# Usage: tools/ci.sh [report.md]
set -uo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly report="${1:-${repository_root}/ci-report.md}"
readonly scratch="$(mktemp -d)"
readonly h2load_port=18470
# The two TLS checks of design §8 step 5 need a chapulin checkout built for both roles, which a
# hosted runner does not have. They run for a person and are stated as skipped otherwise, which
# is what CLAUDE.md asks of a check CI cannot run.
readonly chapulin="${CHAPULIN:-${repository_root}/../chapulin}"
readonly h2load_runs=5
readonly h2load_requests=200000
readonly h2load_clients=32
readonly h2load_streams=10
trap 'kill "${server_pid:-}" 2>/dev/null; rm -rf "${scratch}"' EXIT
cd "${repository_root}"

failed_sections=()

# section <title> <command...>: runs the command, keeps its output, and writes the verdict.
section() {
  local title="$1"
  shift
  local log="${scratch}/section.log"
  echo "ci.sh: ${title}"
  if "$@" >"${log}" 2>&1; then
    echo "| ${title} | passed |" >>"${scratch}/verdicts"
  else
    echo "| ${title} | **failed** |" >>"${scratch}/verdicts"
    failed_sections+=("${title}")
    { echo; echo "### Failed: ${title}"; echo; echo '```text'; tail -40 "${log}"; echo '```'; } >>"${scratch}/failures"
  fi
  cp "${log}" "${scratch}/last.log"
}

fenced() {
  echo '```text'
  cat
  echo '```'
}

machine() {
  echo "- Commit: \`$(git rev-parse HEAD)\`"
  echo "- Host: \`$(uname -srm)\`"
  if command -v lscpu >/dev/null 2>&1; then
    echo "- CPU: $(lscpu | sed -n 's/^Model name: *//p' | head -1), $(nproc) cores"
  else
    echo "- CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
  fi
  echo "- Zig: $(zig version)"
}

simulator_checks() {
  local mode
  for mode in "" "-Drelease"; do
    for check in chunk connection tls qpack qpack-input; do
      zig build sim ${mode} -- "--${check}-check" 2>&1 | grep -E "^${check}:" || return 1
    done >"${scratch}/sim${mode}.txt"
  done
  # Non-negotiable 5: one seed replays byte-identically across build modes.
  diff "${scratch}/sim.txt" "${scratch}/sim-Drelease.txt" || return 1
  # The QUIC checks have no command line yet: their digests are pinned in their tests, so
  # passing in both modes is the same comparison the checks above make.
  zig build test-sim-run-quic && zig build test-sim-run-quic -Drelease
}

# One h2load run's requests per second, from the line "finished in 1.2s, 81234.56 req/s, ...".
# A run in which any request failed prints nothing, which fails the section.
h2load_once() {
  local output
  output="$(h2load -n "${h2load_requests}" -c "${h2load_clients}" -m "${h2load_streams}" \
    "http://127.0.0.1:${h2load_port}/" 2>&1)"
  grep -q "${h2load_requests} succeeded, 0 failed, 0 errored, 0 timeout" <<<"${output}" || return 1
  sed -n 's/^finished in .*, \([0-9.]*\) req\/s.*/\1/p' <<<"${output}"
}

throughput() {
  zig build install -Drelease || return 1
  zig-out/bin/h2-server --port "${h2load_port}" &
  server_pid=$!
  sleep 1
  h2load_once >/dev/null # Warmup, discarded (decision 33).
  for _ in $(seq "${h2load_runs}"); do h2load_once; done | sort -n >"${scratch}/rates"
  kill "${server_pid}" 2>/dev/null
  [ "$(wc -l <"${scratch}/rates")" -eq "${h2load_runs}" ] || return 1
  echo "h2load -n ${h2load_requests} -c ${h2load_clients} -m ${h2load_streams}, ${h2load_runs} runs after one warmup, requests per second:"
  echo "median $(sed -n "$(((h2load_runs + 1) / 2))p" "${scratch}/rates"), lowest $(head -1 "${scratch}/rates"), highest $(tail -1 "${scratch}/rates")"
}

: >"${scratch}/verdicts"
: >"${scratch}/failures"

section "Format" zig fmt --check build.zig build src tools
section "Lint and tests" zig build test --summary all
tests_line="$(grep -E "Build Summary" "${scratch}/last.log" | tail -1)"
section "Simulator checks, Debug and ReleaseSafe" simulator_checks
section "h2spec" tools/h2spec.sh
h2spec_lines="$(grep -E "^h2spec.sh: [0-9]+ passed" "${scratch}/last.log")"
section "Interop, client direction" tools/h2_interop.sh
interop_lines="$(grep -E "^h2_interop.sh: (go version|nghttpd|h2o version|every exchange)|^h2-client:" "${scratch}/last.log")"
if [ -f "${chapulin}/bin/chapulin-client.o" ] && [ -f "${chapulin}/bin/chapulin-server.o" ]; then
  section "TLS handshake, colibri as client" tools/tls_handshake.sh "${chapulin}"
  tls_lines="$(grep -E "^tls-handshake:" "${scratch}/last.log")"
  section "TLS handshake, colibri as server" tools/tls_accept.sh "${chapulin}"
  tls_lines="${tls_lines}"$'\n'"$(grep -E "^tls-accept: complete|^tls-accept: records|^tls_client:" "${scratch}/last.log")"
else
  tls_lines="No chapulin checkout with both role objects at ${chapulin}, so this run made no TLS handshake."
fi
# Design §8 step 9e's QUIC loopback: a colibri client and server over chapulin's QUIC object.
if [ -f "${chapulin}/bin/chapulin-quic.o" ]; then
  section "QUIC handshake, colibri to colibri over chapulin" tools/quic_loopback.sh "${chapulin}"
  quic_lines="$(grep -E "^quic-loopback:" "${scratch}/last.log")"
  section "hq-interop over UDP, colibri to colibri over chapulin" tools/quic_udp.sh "${chapulin}"
  quic_lines="${quic_lines}"$'\n'"$(grep -E "^quic-udp: (fetched|served)" "${scratch}/last.log")"
  section "hq-interop over UDP, colibri against aioquic" tools/quic_aioquic.sh "${chapulin}"
  quic_lines="${quic_lines}"$'\n'"$(grep -E "^quic_aioquic: " "${scratch}/last.log")"
else
  quic_lines="No chapulin checkout with a QUIC object at ${chapulin}, so this run made no QUIC handshake."
fi
# Design §8 step 11: the QIF tools of design §9 against ls-qpack, through pylsqpack.
if command -v python3 >/dev/null 2>&1; then
  section "QIF interop, colibri against ls-qpack" tools/qif_interop.sh
  qif_lines="$(grep -E "^qif_interop: ok" "${scratch}/last.log")"
else
  qif_lines="No python3 on PATH, so this run made no QIF interop."
fi
# Decision 67: the TLA+ specifications of spec/tla/, model-checked by TLC through pepegrillo.
if command -v java >/dev/null 2>&1; then
  section "TLA+ models" zig build tla
  tla_lines="$(grep -E "\[tla\]" "${scratch}/last.log")"
else
  tla_lines="No Java runtime on PATH, so this run checked no TLA+ model."
fi
# Decision 77: the Lean proofs of spec/lean/, and the vectors the Zig tests read from them.
if command -v lake >/dev/null 2>&1 || [ -x "${HOME}/.elan/bin/lake" ]; then
  section "Lean proofs" zig build lean
  lean_lines="Every proof in spec/lean/ built, and the vector files match the proved definitions."
else
  lean_lines="No lake on PATH or in ~/.elan/bin, so this run built no Lean proof."
fi
if command -v h2load >/dev/null 2>&1; then
  section "Throughput, indicative" throughput
  throughput_lines="$(tail -2 "${scratch}/last.log")"
else
  throughput_lines="h2load is not installed, so this run measured nothing."
fi

{
  echo "# colibri checks"
  echo
  machine
  echo
  echo "| Section | Verdict |"
  echo "|---|---|"
  cat "${scratch}/verdicts"
  echo
  echo "## Exact numbers"
  echo
  echo "A change in any of these is a change in the code."
  echo
  echo "${tests_line}" | fenced
  echo
  echo "Simulator censuses, identical in Debug and ReleaseSafe:"
  echo
  {
    cat "${scratch}/sim.txt"
    # The QUIC checks' censuses are the ones their tests pin, read from the source.
    awk -F'[ =;]+' '/^pub const census_[a-z0-9]+_expected/ { sub(/census_/, "", $3); sub(/_expected:/, "", $3); gsub(/_/, "", $5); field[$3] = $5 }
      END { printf "packet: packets=%s octets=%s crc32=%s\n", field["packets"], field["octets"], field["crc32"] }' src/sim/packet_check.zig
    awk -F'[ =;]+' '/^pub const census_[a-z0-9]+_expected/ { sub(/census_/, "", $3); sub(/_expected:/, "", $3); gsub(/_/, "", $5); field[$3] = $5 }
      END { printf "network: sent=%s delivered=%s crc32=%s\n", field["sent"], field["delivered"], field["crc32"] }' src/sim/network_check.zig
  } | fenced
  echo
  echo "Counted cost of one request (\`src/sim/cost_check.zig\`):"
  echo
  awk '/^pub const [a-z_]+: Cost = /,/^};/' src/sim/cost_check.zig | fenced
  echo
  echo "## Conformance and interop"
  echo
  { echo "${h2spec_lines}"; echo "${interop_lines}"; } | fenced
  echo
  echo "## TLS, both directions"
  echo
  echo "Design §8 step 5's two checks: colibri's chapulin-backed client against a Go server, and"
  echo "colibri's chapulin-backed server against a Go client (docs/decisions.md entry 10)."
  echo
  echo "${tls_lines}" | fenced
  echo
  echo "## QUIC over chapulin"
  echo
  echo "Design §8 step 9e's loopback check: a colibri client and a colibri server, each over one"
  echo "session of chapulin's \`TRANSPORT=quic ROLE=both\` object, finish a handshake and one stream."
  echo
  echo "${quic_lines}" | fenced
  echo
  echo "## QIF interop"
  echo
  echo "colibri's QIF tools and ls-qpack decode each other's files over the qpackers/qifs inputs"
  echo "(docs/design.md §8 step 11)."
  echo
  echo "${qif_lines}" | fenced
  echo
  echo "## TLA+ models"
  echo
  echo "Each configuration of spec/tla/ states whether TLC must find its properties holding or"
  echo "violated (docs/decisions.md entry 67)."
  echo
  echo "${tla_lines}" | fenced
  echo
  echo "## Lean proofs"
  echo
  echo "spec/lean/ built by lake, and the vector files of src/qpack/ checked against the proved"
  echo "definitions (docs/decisions.md entry 77)."
  echo
  echo "${lean_lines}" | fenced
  echo
  echo "## Throughput, indicative"
  echo
  echo "From a machine that pins no core and fixes no governor, so it shows a large regression"
  echo "and proves nothing about a small one (docs/decisions.md entries 33 and 47)."
  echo
  echo "${throughput_lines}" | fenced
  cat "${scratch}/failures"
} >"${report}"

echo "ci.sh: report written to ${report}"
if [ "${#failed_sections[@]}" -gt 0 ]; then
  echo "ci.sh: failed: ${failed_sections[*]}" >&2
  exit 1
fi
