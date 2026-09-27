#!/usr/bin/env bash
#
# Builds and runs tools/consumer/, a project that depends on colibri as a package, the way README.md
# tells a project to: colibri's working tree is packed as a tarball, `zig fetch --save` adds it to
# a scratch copy of the consumer, and `zig build run` builds and runs it. It shows that the twelve
# modules are exported under their names (decision 86), that the `.release` option exists, and
# that a dependent fetches none of colibri's tooling. It then builds a program that links `tls`
# and defines no `ch_assert_fail`, chapulin's one hook, which must fail to link and name it (design
# §8 step 16). No program defines `ch_rand_bytes`: each session draws from the source its `start`
# takes (decision 94 as amended).
#
#   tools/consumer_check.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

# The package is what build.zig.zon's `paths` names, as those files are on disk now.
mkdir -p "${scratch}/colibri"
(cd "${repository_root}" && cp -R build.zig build.zig.zon build src "${scratch}/colibri/")
# The files sit at the tarball's root, where Zig looks for build.zig.zon.
tar -czf "${scratch}/colibri.tar.gz" -C "${scratch}/colibri" build.zig build.zig.zon build src

cp -R "${repository_root}/tools/consumer" "${scratch}/consumer"
cd "${scratch}/consumer"
zig fetch --save=colibri "${scratch}/colibri.tar.gz" >/dev/null
zig build run 2>&1 | tee "${scratch}/run.log"
grep -q "^consumer: h11, h2 and tls link and run as a dependency$" "${scratch}/run.log"
if zig build without-assert >"${scratch}/without-assert.log" 2>&1; then
  echo "consumer_check.sh: a program with no ch_assert_fail linked" >&2
  exit 1
fi
if ! grep -q "ch_assert_fail" "${scratch}/without-assert.log"; then
  echo "consumer_check.sh: the link failed without naming ch_assert_fail:" >&2
  tail -20 "${scratch}/without-assert.log" >&2
  exit 1
fi
echo "consumer_check.sh: a program with no ch_assert_fail does not link, and the linker names it"
echo "consumer_check.sh: a project that depends on colibri builds and runs"
