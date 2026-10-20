#!/usr/bin/env bash
# Makes <directory> a Python virtual environment whose Python imports <module>. A check script
# calls it before it runs a peer from an environment in the cache. When the environment's Python
# imports the module, the helper changes nothing. When it does not, the helper removes the
# directory, makes a new environment there, and installs what the pip arguments name. On
# 2026-10-20 a Python upgrade left bin/python a link to an interpreter that was gone, and
# `python3 -m venv` over the old directory kept that link.
#
# The helper removes only a directory that holds pyvenv.cfg, the file `python3 -m venv` writes.
# It fails when the new environment does not import the module either.
#
# Usage: tools/python_venv.sh <directory> <module> <pip install argument>...
set -euo pipefail

readonly usage="usage: tools/python_venv.sh <directory> <module> <pip install argument>..."
readonly directory="${1:?${usage}}"
readonly module="${2:?${usage}}"
shift 2
if [ "$#" -eq 0 ]; then
  echo "${usage}" >&2
  exit 2
fi

# Whether the environment's Python imports the module. With -I, neither the current directory nor
# PYTHONPATH is on the import path, so the module must come from the environment.
imports_module() {
  "${directory}/bin/python" -I -c 'import importlib, sys; importlib.import_module(sys.argv[1])' \
    "${module}" >/dev/null 2>&1
}

if imports_module; then
  exit 0
fi
if [ -e "${directory}" ] && [ ! -f "${directory}/pyvenv.cfg" ]; then
  echo "python_venv.sh: ${directory} holds no pyvenv.cfg, so it is not a virtual environment," \
    "and the helper did not remove it" >&2
  exit 1
fi
echo "python_venv.sh: the Python of ${directory} does not import ${module}; making it again"
rm -rf "${directory}"
python3 -m venv "${directory}"
"${directory}/bin/pip" install -q "$@"
if ! imports_module; then
  echo "python_venv.sh: the new environment in ${directory} does not import ${module}" >&2
  exit 1
fi
