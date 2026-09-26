#!/usr/bin/env bash
#
# Builds and runs tools/consumer/, a project that depends on colibri as a package, the way README.md
# tells a project to: colibri's working tree is packed as a tarball, `zig fetch --save` adds it to
# a scratch copy of the consumer, and `zig build run` builds and runs it. It shows that the eleven
# modules are exported under their names (decision 86), that the `.release` option exists, and
# that a dependent fetches none of colibri's tooling.
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
grep -q "^consumer: h11 and h2 link and run as a dependency$" "${scratch}/run.log"
echo "consumer_check.sh: a project that depends on colibri builds and runs"
