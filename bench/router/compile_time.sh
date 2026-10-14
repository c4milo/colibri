#!/usr/bin/env bash
#
# The compile time of the router's tables (design §8 step 21e, decision 122 as amended on
# 2026-10-14). It copies bench/router/ into the .zig-cache of a tree and builds once to fill the
# cache. Then it compiles each table twice, each time with a new stamp, which makes the compiler
# build the table again. Each line gives the table, the round, the exit status of `zig build
# compile`, its wall time from `/usr/bin/time -p`, and the load average after it.
#
#   bench/router/compile_time.sh [--tree <tree>] [table...]
#
# The tree is this checkout unless --tree names another, such as an export of an older commit.
# The tables are the names of `Table` in bench/router/build.zig, each one by default. It runs on
# macOS and on Linux. Its numbers order changes on one machine and are never published
# (decision 32).
set -euo pipefail

readonly here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tree="$(cd "${here}/../.." && pwd)"
if [ "${1:-}" = "--tree" ]; then
  tree="$(cd "$2" && pwd)"
  shift 2
fi
tables=("$@")
if [ ${#tables[@]} -eq 0 ]; then
  tables=(one literals_256_parameter literals_512_parameter literals_512_literal router_test_256
    resources_50 mixed_338 named_256)
fi

# The copy sits two levels below the tree, where build.zig.zon's path names the tree. Zig
# writes the packages it fetches into the copy, and the lint rules do not read `.zig-cache`.
readonly probe="${tree}/.zig-cache/bench-router"
mkdir -p "${probe}"
cp "${here}"/*.zig "${here}/build.zig.zon" "${probe}/"
cd "${probe}"

load() {
  if [ -r /proc/loadavg ]; then cut -d ' ' -f 1-3 /proc/loadavg; else sysctl -n vm.loadavg; fi
}

zig build compile -Dtable=one -Dstamp=0 >warm.log 2>&1 || {
  echo "compile_time.sh: the first build failed:" >&2
  tail -20 warm.log >&2
  exit 1
}
stamp="$(date +%s)000"
failed=0
for table in "${tables[@]}"; do
  for round in 1 2; do
    stamp=$((stamp + 1))
    log="${table}_${round}.log"
    rc=0
    /usr/bin/time -p zig build compile -Dtable="${table}" -Dstamp="${stamp}" >"${log}" 2>&1 || rc=$?
    seconds="$(sed -n 's/^real *//p' "${log}" | tail -1)"
    echo "${table} round ${round} rc=${rc} ${seconds} s load $(load)"
    if [ "${rc}" -ne 0 ]; then failed=1; fi
  done
done
exit "${failed}"
