#!/usr/bin/env bash
# Counts the lines of each library module that its tests run, with pepegrillo's coverage tool
# under kcov 43 (tools/line_coverage.zig). It prints one line for each module and one for the
# total:
#
#   src/core: note: [coverage] 91.2% of 1204 lines
#   zig-out/coverage: note: [coverage] total 88.4% of 30200 lines
#
# kcov runs on Linux alone. A host with kcov 43 runs `zig build line-coverage` itself. Another
# Linux host runs it in an ubuntu:26.04 container, which packages kcov 43, with this host's Zig, the
# tree and the global cache. kcov needs ptrace and the personality call there. The container runs
# as root, so it gives each file it wrote back to the user that runs the script. tools/ci.sh runs
# this check on Linux.
#
# Usage: tools/line_coverage_check.sh
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The release that tools/line_coverage.zig pins through pepegrillo's tool.
readonly kcov_release=43
readonly image=ubuntu:26.04
cd "${repository_root}"

if kcov --version 2>/dev/null | grep -q "^kcov ${kcov_release}"; then
  exec zig build line-coverage
fi
if [ "$(uname -s)" != Linux ]; then
  echo "line_coverage_check.sh: kcov runs on Linux alone; run this check on Linux" >&2
  exit 2
fi
readonly zig_directory="$(dirname "$(readlink -f "$(command -v zig)")")"
readonly global_cache="${ZIG_GLOBAL_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/zig}"
mkdir -p "${global_cache}"
# The container's arguments: the Zig directory, the global cache and the owner of the files.
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "${repository_root}:${repository_root}" -w "${repository_root}" \
  -v "${zig_directory}:${zig_directory}:ro" -v "${global_cache}:${global_cache}" \
  -e ZIG_GLOBAL_CACHE_DIR="${global_cache}" -e DEBIAN_FRONTEND=noninteractive \
  "${image}" sh -c '
    apt-get update -qq && apt-get install -y -qq --no-install-recommends kcov >/dev/null || exit 2
    PATH="$0:${PATH}" zig build line-coverage
    status=$?
    find .zig-cache zig-out "$1" -uid 0 -exec chown "$2" {} + 2>/dev/null
    exit "${status}"
  ' "${zig_directory}" "${global_cache}" "$(id -u):$(id -g)"
