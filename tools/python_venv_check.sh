#!/usr/bin/env bash
# The check of tools/python_venv.sh, which keeps the check scripts' cached Python virtual
# environments whole. The helper must make an environment that is absent and keep one that
# imports its module. It must make again whole an environment whose bin/python is a link to
# nothing, and one whose package is gone. It must not remove a directory that holds no
# pyvenv.cfg. It must fail when the new environment does not import the module, also when the
# current directory holds it. The check reads no package index. `tools/ci.sh` runs it.
#
# Usage: tools/python_venv_check.sh
set -euo pipefail

readonly helper="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/python_venv.sh"
readonly scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
readonly venv="${scratch}/venv"
# Every environment `python3 -m venv` makes holds pip, so these arguments install nothing and read
# no index, and `import pip` fails once the package is gone.
readonly install=(--no-index pip)

fail() {
  echo "python_venv_check.sh: $*" >&2
  exit 1
}

# Runs the helper on ${venv} for the module pip, and requires the environment to import pip after.
make_venv() {
  "${helper}" "${venv}" pip "${install[@]}" >/dev/null || fail "$1 was refused"
  "${venv}/bin/python" -I -c 'import pip' || fail "$1 does not import pip after the helper"
}

make_venv "an absent environment"

touch "${venv}/kept"
make_venv "an environment that works"
[ -e "${venv}/kept" ] || fail "an environment that works was made again"

# What the Python upgrade of 2026-10-20 left: bin/python a link to an interpreter that is gone.
rm "${venv}/bin/python"
ln -s python3.0 "${venv}/bin/python"
make_venv "an environment whose bin/python links to nothing"
[ ! -e "${venv}/kept" ] ||
  fail "an environment whose bin/python links to nothing was not made whole"

touch "${venv}/kept"
packages=("${venv}"/lib/python3*/site-packages/pip)
[ -d "${packages[0]}" ] || fail "the environment holds no pip package at ${packages[0]}"
rm -rf "${packages[@]}"
make_venv "an environment whose package is gone"
[ ! -e "${venv}/kept" ] || fail "an environment whose package is gone was not made whole"

mkdir "${scratch}/other"
touch "${scratch}/other/file"
if "${helper}" "${scratch}/other" pip "${install[@]}" >/dev/null 2>&1; then
  fail "a directory that holds no pyvenv.cfg was accepted"
fi
[ -e "${scratch}/other/file" ] || fail "a directory that holds no pyvenv.cfg was removed"

# The current directory and PYTHONPATH hold the module, and the new environment does not.
mkdir "${scratch}/outside"
touch "${scratch}/outside/colibri_outside_module.py"
if (cd "${scratch}/outside" && PYTHONPATH="${scratch}/outside" "${helper}" "${scratch}/absent" \
  colibri_outside_module "${install[@]}") >/dev/null 2>&1; then
  fail "a module from outside the new environment was accepted"
fi
echo "python_venv_check.sh: ok"
