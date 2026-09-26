#!/usr/bin/env bash
# The HTTP Garden check of docs/design.md §8 step 15d (decision 88): colibri's test-only server, in
# its echo mode, as one origin among the Garden's others, fed every request stream of
# tools/http_garden/driver.py. The report names each stream whose parse by colibri differs from
# another origin's. A difference is judged against RFC 9112 before it counts as colibri's defect,
# so the run fails only when a stream went uncompared, never on a difference.
#
# The Garden (https://github.com/narfindustries/http-garden, GPL-3.0) is cloned at a pinned commit
# into a cache and run as it is, with colibri's image and service added to the clone. Nothing of
# it is linked into colibri, and colibri's files here import none of its code. It needs Linux: its
# tools reach each container by its address on the Docker network, which Docker Desktop does not
# route to a macOS host. It also needs Docker with compose, python3 and uv, and tens of GB of disk
# for the origins' images, which it builds from source.
#
# Usage: tools/http_garden.sh [origin...]
#        (no origin compares colibri with every origin the Garden carries)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly garden_repository=https://github.com/narfindustries/http-garden
readonly garden_commit=b417e806c1b15e8ea0b9312f81a91fbdcbc7a83e
readonly garden="${XDG_CACHE_HOME:-${HOME}/.cache}/colibri/http-garden-${garden_commit:0:8}"
readonly driver="${repository_root}/tools/http_garden/driver.py"
# Seconds the origins get to start listening once their containers are up.
readonly start_wait_seconds=30

fail() {
  echo "http_garden.sh: $*" >&2
  exit 1
}

[ "$(uname)" = Linux ] || fail "the Garden needs Linux: its tools reach containers by their Docker network address"
for tool in docker python3 uv git; do
  command -v "${tool}" >/dev/null 2>&1 || fail "${tool} is not installed"
done

# The Garden at the pinned commit, with nothing left of an earlier run.
if [ ! -d "${garden}/.git" ]; then
  git clone -q "${garden_repository}" "${garden}"
fi
git -C "${garden}" fetch -q origin "${garden_commit}" 2>/dev/null || true
git -C "${garden}" checkout -q --force "${garden_commit}"
git -C "${garden}" clean -q -fdx

# colibri's image, built from its committed tree, and its service and quirks. colibri matches every
# default quirk: it requires Host, keeps connections alive and changes no field, so its entry is
# empty.
cp -R "${repository_root}/tools/http_garden/colibri" "${garden}/images/colibri"
git -C "${repository_root}" archive --format=tar HEAD >"${garden}/images/colibri/colibri.tar"
cat >>"${garden}/docker-compose.yml" <<'SERVICE'
  colibri:
    build:
      context: ./images/colibri
    x-props:
      role: origin
SERVICE
echo "colibri:" >>"${garden}/quirks.yml"

origins=("$@")
if [ "${#origins[@]}" -eq 0 ]; then
  mapfile -t origins < <(cd "${garden}" && uv run python3 -c '
import yaml
services = yaml.safe_load(open("docker-compose.yml"))["services"]
print("\n".join(name for name, service in services.items()
                if service.get("x-props", {}).get("role") == "origin" and name != "colibri"))')
fi
[ "${#origins[@]}" -gt 0 ] || fail "no origin to compare colibri with"
echo "http_garden.sh: the Garden at ${garden_commit:0:8}, colibri at $(git -C "${repository_root}" rev-parse --short HEAD), ${#origins[@]} origins: ${origins[*]}"

cleanup() {
  (cd "${garden}" && docker compose down --remove-orphans >/dev/null 2>&1) || true
}
trap cleanup EXIT

# The build is what takes time and disk, so both are reported beside the comparison. The images are
# built one at a time, which a runner with a few cores and 16 GB of memory can hold. The Garden's
# own base image and colibri's must build. An origin's image that does not, because a download it
# names has moved since the pinned commit, is reported and left out of the comparison.
build_started="$(date +%s)"
(cd "${garden}" && ./garden.sh build_seq colibri) || fail "colibri's image did not build"
built=()
unbuilt=()
for origin in "${origins[@]}"; do
  if (cd "${garden}" && docker compose build "${origin}"); then
    built+=("${origin}")
  else
    unbuilt+=("${origin}")
  fi
done
echo "http_garden.sh: built colibri and ${#built[@]} of ${#origins[@]} origins in $(($(date +%s) - build_started)) seconds"
[ "${#unbuilt[@]}" -eq 0 ] || echo "http_garden.sh: unbuilt=${#unbuilt[@]}: ${unbuilt[*]}"
[ "${#built[@]}" -gt 0 ] || fail "no origin's image built"
docker system df

(cd "${garden}" && docker compose up -d colibri "${built[@]}")
sleep "${start_wait_seconds}"

readonly scratch="$(mktemp -d)"
python3 "${driver}" commands "${built[@]}" >"${scratch}/commands"
(cd "${garden}" && uv run ./tools/repl.py) <"${scratch}/commands" >"${scratch}/output" 2>&1 ||
  fail "the Garden's REPL exited non-zero: $(tail -5 "${scratch}/output")"
python3 "${driver}" report "${built[@]}" <"${scratch}/output" ||
  fail "not every stream was compared: $(grep -iE "error|exception|traceback" "${scratch}/output" | head -5)"
rm -rf "${scratch}"
