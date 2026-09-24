#!/usr/bin/env bash
# Model-checks every TLA+ specification in tools/tla/ with TLC (decision 67).
#
# Each configuration tools/tla/<Module>_<case>.cfg checks tools/tla/<Module>.tla, and its first
# line states what TLC must find: "\* expect: holds" or "\* expect: violated". A configuration
# that expects a violation shows the property can fail, so one that holds is not holding
# vacuously, which is what a mutation shows for a Zig test.
#
# TLC is tla2tools.jar from the tlaplus release pinned below, downloaded once into a cache and
# checked against its SHA-256 before every run. It needs a Java runtime, 11 or newer.
#
# Usage: tools/tla.sh [configuration...]
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly tla_version="1.7.4"
readonly tla_sha256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
readonly tla_url="https://github.com/tlaplus/tlaplus/releases/download/v${tla_version}/tla2tools.jar"
readonly cache="${XDG_CACHE_HOME:-${HOME}/.cache}/colibri"
readonly jar="${cache}/tla2tools-${tla_version}.jar"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

command -v java >/dev/null || { echo "tla: no java on PATH; TLC needs a Java runtime" >&2; exit 2; }

if [ ! -f "${jar}" ]; then
  mkdir -p "${cache}"
  curl -fsSL -o "${jar}.part" "${tla_url}"
  mv "${jar}.part" "${jar}"
fi
if [ "$(shasum -a 256 "${jar}" | cut -d' ' -f1)" != "${tla_sha256}" ]; then
  echo "tla: ${jar} does not match its pinned SHA-256; remove it and run again" >&2
  exit 1
fi

cd "${repository_root}/tools/tla"
if [ "$#" -gt 0 ]; then configurations=("$@"); else configurations=(*_*.cfg); fi

failed=0
for configuration in "${configurations[@]}"; do
  configuration="$(basename "${configuration}")"
  module="${configuration%%_*}"
  expected="$(sed -n '1s/^\\\* expect: //p' "${configuration}")"
  case "${expected}" in
    holds | violated) ;;
    *) echo "tla: ${configuration} states no expectation on its first line" >&2; exit 2 ;;
  esac
  log="${scratch}/${configuration}.log"
  status=0
  java -XX:+UseParallelGC -cp "${jar}" tlc2.TLC -config "${configuration}" \
    -metadir "${scratch}/${configuration}.states" -workers auto "${module}.tla" >"${log}" 2>&1 || status=$?
  # TLC's exit codes: 0 when nothing is violated, 12 for an invariant, 13 for a temporal property.
  # Any other code is TLC failing to check, which is never what a configuration expects.
  case "${status}" in
    0) found=holds ;;
    12 | 13) found=violated ;;
    *) found="error ${status}" ;;
  esac
  states="$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "${log}" | tail -1)"
  if [ "${found}" = "${expected}" ]; then
    echo "tla: ${configuration}: ${found}, as expected (${states:-?} distinct states)"
  else
    echo "tla: ${configuration}: expected ${expected}, found ${found}" >&2
    tail -30 "${log}" >&2
    failed=1
  fi
done
exit "${failed}"
