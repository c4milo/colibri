#!/usr/bin/env bash
#
# The instructions of one `match` (design §8 step 21e, decision 122 as amended on 2026-10-14).
# It builds bench/routes/run_time.zig in ReleaseSafe for Linux on the host's architecture, from
# a copy of bench/routes/ in the .zig-cache of a tree. Then it runs the probe under callgrind in
# a container that bench/routes/valgrind.Dockerfile builds. For each count k of literal edges and
# each path, it prints k, the path, and the instructions of one match: callgrind's count for
# <count> matches less its count for none, divided by <count>, then the remainder.
#
#   bench/routes/run_time.sh [--tree <tree>] [count]
#
# The tree is this checkout unless --tree names another. The count is 100000 by default. It
# needs Zig and Docker. Its numbers are a laptop's and are never published (decision 32).
set -euo pipefail

readonly here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "${1:-}" = "inside" ]; then
  # In the container: inside <probe> <count>.
  probe="$2"
  count="$3"
  instructions() {
    valgrind --tool=callgrind --callgrind-out-file=/dev/null "$@" 2>&1 |
      sed -n 's/.*Collected : \([0-9]*\).*/\1/p'
  }
  for k in 1 2 4 8 16 64 256; do
    none="$(instructions "${probe}" "${k}" first 0)"
    for position in first middle last miss; do
      all="$(instructions "${probe}" "${k}" "${position}" "${count}")"
      echo "${k} ${position} $(((all - none) / count)) $(((all - none) % count))"
    done
  done
  exit 0
fi

tree="$(cd "${here}/../.." && pwd)"
if [ "${1:-}" = "--tree" ]; then
  tree="$(cd "$2" && pwd)"
  shift 2
fi
count="${1:-100000}"
case "$(uname -m)" in
  arm64 | aarch64) arch=aarch64 ;;
  x86_64 | amd64) arch=x86_64 ;;
  *) echo "run_time.sh: no Linux target for $(uname -m)" >&2; exit 1 ;;
esac

readonly probe="${tree}/.zig-cache/bench-routes"
mkdir -p "${probe}"
cp "${here}"/*.zig "${here}/build.zig.zon" "${here}/run_time.sh" "${probe}/"
(cd "${probe}" && zig build probe -Dtarget="${arch}-linux")
readonly image=colibri-bench-routes-valgrind
docker build --quiet -t "${image}" -f "${here}/valgrind.Dockerfile" "${here}" >/dev/null
docker run --rm -v "${probe}:/probe" "${image}" /probe/run_time.sh inside /probe/zig-out/bin/probe "${count}"
