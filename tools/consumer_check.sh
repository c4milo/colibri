#!/usr/bin/env bash
#
# Builds and runs tools/consumer/, a project that depends on colibri as a package, the way README.md
# tells a project to: colibri's working tree is packed as a tarball, `zig fetch --save` adds it to
# a scratch copy of the consumer, and `zig build run` builds and runs it. It shows that the
# package exports the one module `colibri`, whose root names each library module (decision 170),
# that the `.release` option exists, and that a dependent fetches none of colibri's tooling. It
# requires that the package exports no library module under its own name: a build that asks for
# `h2` must stop. It then builds a program that runs `colibri.tls`
# and defines no `ch_assert_fail`, chapulin's one hook, which must fail to link and name it (design
# §8 step 16). No program defines `ch_rand_bytes`: each session draws from the source its `start`
# takes (decision 94 as amended).
#
# tools/consumer/ uses the `.private` kind of the `colibri` module, so it passes `.rotor = true`
# and its build fetches Rotor. The script then builds tools/consumer_hosted/, a second project,
# which uses `colibri.h11` and the `.hosted` kind alone and passes no such option (decision
# 159, design §8 step 44j). It builds it with a global cache that starts empty, and requires that:
# - `zig build --fetch` and `zig build run` fetch stdx, and no Rotor, no pepegrillo and no qifs,
#   the three packages that colibri's build.zig.zon marks lazy;
# - `zig build run` fetches chapulin, which stdx's build.zig.zon marks lazy and asks for when
#   colibri passes `.crypto = true` (decision 174). `zig build --fetch` fetches no lazy package, so
#   the check of chapulin waits for the run;
# - a program of that project that names `.private` does not compile, and the compiler prints
#   colibri's message for `colibri.Server` and for `colibri.Client`.
# Zig 0.16 keeps each package as `<hash>.tar.gz` under the global cache's `p/`, and unpacked under
# the project's `zig-pkg/`. The script reads both.
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
# Decision 97 as amended on 2026-09-30: a program depends on stdx itself for `platform`, at the
# commit colibri pins, so it shares colibri's stdx.
stdx_url="$(grep -o 'git+https://github.com/c4milo/stdx#[0-9a-f]*' "${repository_root}/build.zig.zon")"
zig fetch --save=stdx "${stdx_url}" >/dev/null
zig build run 2>&1 | tee "${scratch}/run.log"
grep -q "^consumer: h11, h2, tls, gzip, server, client and colibri link and run as a dependency$" "${scratch}/run.log"
# Decision 170: the package exports `colibri` alone, so it has no module named `h2`, and none
# named `gzip`, which is stdx's. Zig's build stops and names the module it did not find.
for named in h2 gzip; do
  if zig build run "-Dnamed-module=${named}" >"${scratch}/named-module.log" 2>&1; then
    echo "consumer_check.sh: colibri's package exports a module named ${named}" >&2
    exit 1
  fi
  if ! grep -q "unable to find module '${named}'" "${scratch}/named-module.log"; then
    echo "consumer_check.sh: the build that asks for ${named} failed for another reason:" >&2
    tail -20 "${scratch}/named-module.log" >&2
    exit 1
  fi
done
echo "consumer_check.sh: the package exports colibri alone, and no module named h2 or gzip"
if ! zig build without-assert >"${scratch}/without-assert.log" 2>&1; then
  echo "consumer_check.sh: a program that declares no chapulin hook did not link:" >&2
  tail -20 "${scratch}/without-assert.log" >&2
  exit 1
fi
if ! nm zig-out/bin/without-assert | grep -E " T _?ch_assert_fail$" >/dev/null; then
  echo "consumer_check.sh: the program does not define ch_assert_fail from chapulin's module" >&2
  exit 1
fi
echo "consumer_check.sh: a program that declares no chapulin hook links, with chapulin's ch_assert_fail"
# The control of the Rotor check below: this project passes `.rotor = true`, so Rotor's package is
# among the ones Zig unpacked for it, under the name the check looks for.
if ! ls zig-pkg | grep -q '^rotor-'; then
  echo "consumer_check.sh: a project that passes .rotor = true unpacked no rotor-* package:" >&2
  ls zig-pkg >&2
  exit 1
fi
echo "consumer_check.sh: a project that depends on colibri builds and runs"

# Decision 159: the second project, with a global cache that starts empty.
readonly private_message='colibri: .private runs on Rotor; pass .rotor = true to b.dependency("colibri", ...)'
readonly global_cache="${scratch}/global-cache"
mkdir "${global_cache}"

# The hash of each package that colibri's build.zig.zon marks lazy: Rotor, pepegrillo and qifs.
lazy_hashes="$(awk '/\.hash = /{ gsub(/[",]/, "", $3); hash = $3 } /\.lazy = true/{ print hash }' "${repository_root}/build.zig.zon")"

# Fails when the empty cache or the project's zig-pkg/ holds Rotor, by its name, or a package
# that colibri marks lazy, by its hash. When $2 is `chapulin`, it fails too when neither holds
# chapulin, which a build of this project must fetch. $1 names the command that just ran.
require_no_lazy_package() {
  local packages
  packages="$(ls "${global_cache}/p" zig-pkg 2>/dev/null | sed 's/\.tar\.gz$//')"
  if [[ "${2:-}" == chapulin ]] && ! grep -q '^chapulin-' <<<"${packages}"; then
    echo "consumer_check.sh: after $1, the listing of fetched packages holds no chapulin-*:" >&2
    echo "${packages}" >&2
    exit 1
  fi
  if grep -E '^rotor-' <<<"${packages}" >&2 || grep -Fx "${lazy_hashes}" <<<"${packages}" >&2; then
    echo "consumer_check.sh: after $1, a project that passes no .rotor option fetched the package above" >&2
    exit 1
  fi
}

cp -R "${repository_root}/tools/consumer_hosted" "${scratch}/consumer_hosted"
cd "${scratch}/consumer_hosted"
zig fetch --global-cache-dir "${global_cache}" --save=colibri "${scratch}/colibri.tar.gz" >/dev/null
zig fetch --global-cache-dir "${global_cache}" --save=stdx "${stdx_url}" >/dev/null
zig build --fetch --global-cache-dir "${global_cache}"
require_no_lazy_package "zig build --fetch"
zig build run --global-cache-dir "${global_cache}" 2>&1 | tee "${scratch}/hosted-run.log"
grep -q "^consumer_hosted: h11 and colibri's .hosted kind link and run with no Rotor$" "${scratch}/hosted-run.log"
require_no_lazy_package "zig build run" chapulin
if zig build private --global-cache-dir "${global_cache}" >"${scratch}/private.log" 2>&1; then
  echo "consumer_check.sh: a program that names .private compiled in a build with no Rotor" >&2
  exit 1
fi
# One message for `colibri.Server` and one for `colibri.Client`.
if [[ "$(grep -cF "error: ${private_message}" "${scratch}/private.log")" != 2 ]]; then
  echo "consumer_check.sh: the compile failed without colibri's message for each of the two types:" >&2
  grep -F "error:" "${scratch}/private.log" | cut -c1-300 >&2
  exit 1
fi
require_no_lazy_package "zig build private"
echo "consumer_check.sh: a program that names .private with no Rotor does not compile, and the compiler prints colibri's message"
echo "consumer_check.sh: a project of the protocol modules and .hosted alone builds, runs and fetches no Rotor"
