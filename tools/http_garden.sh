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
# With GARDEN_REGISTRY set to an image repository, such as ghcr.io/c4milo/colibri-http-garden, the
# Garden's base image and each origin's are pulled from it when they are there, tagged
# `<service>-<Garden commit>`, and built only when they are not; with GARDEN_PUSH=1 too, each image
# built is pushed there for the next run. colibri's image is always built from the commit under
# test, and never pushed. A pull or a push that fails is reported, and the run goes on.
#
# With GARDEN_REPL_OUTPUT set to a path, the REPL's whole output is copied there, so a run whose
# report is wrong can be read afterwards.
#
# Usage: tools/http_garden.sh [origin...]
#        (no origin compares colibri with every origin the Garden carries)
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly garden_repository=https://github.com/narfindustries/http-garden
readonly garden_commit=b417e806c1b15e8ea0b9312f81a91fbdcbc7a83e
readonly garden="${XDG_CACHE_HOME:-${HOME}/.cache}/colibri/http-garden-${garden_commit:0:8}"
readonly driver="${repository_root}/tools/http_garden/driver.py"
# Seconds the origins get to accept a connection once their containers are up, and again after one
# is restarted.
readonly start_wait_seconds=60
# The Garden's tools find each container on the Docker network `http-garden_default`, a name they
# hold fixed. Compose names the network after its project, so every compose command here runs as
# the project `http-garden`, whatever the cache directory is called.
export COMPOSE_PROJECT_NAME=http-garden

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

# The registry's tag for a service's image, and the name compose gives the image it builds: its
# project, then the service.
registry_tag() {
  echo "${GARDEN_REGISTRY}:$1-${garden_commit:0:8}"
}
local_image() {
  echo "${COMPOSE_PROJECT_NAME}-$1"
}

# pull <local-image> <service>: takes the service's image from the registry when it is there.
pull() {
  [ -n "${GARDEN_REGISTRY:-}" ] || return 1
  docker pull -q "$(registry_tag "$2")" >/dev/null 2>&1 || return 1
  docker tag "$(registry_tag "$2")" "$1"
}

# push <local-image> <service>: keeps an image this run built for the next one.
push() {
  [ -n "${GARDEN_REGISTRY:-}" ] && [ "${GARDEN_PUSH:-}" = 1 ] || return 0
  docker tag "$1" "$(registry_tag "$2")"
  docker push -q "$(registry_tag "$2")" >/dev/null 2>&1 || echo "http_garden.sh: could not push ${2}'s image"
}

# The package's first image is a tiny one, so the package exists, linked to colibri's repository by
# its source label, before any large push: a new package is private, and a private one's small
# free storage may refuse the others until its owner makes it public.
if [ -n "${GARDEN_REGISTRY:-}" ] && [ "${GARDEN_PUSH:-}" = 1 ]; then
  marker="$(mktemp -d)"
  echo "${garden_commit}" >"${marker}/garden-commit"
  printf 'FROM scratch\nCOPY garden-commit /\nLABEL org.opencontainers.image.source=https://github.com/c4milo/colibri\n' >"${marker}/Dockerfile"
  docker build -q -t "$(registry_tag marker)" "${marker}" >/dev/null
  docker push -q "$(registry_tag marker)" >/dev/null 2>&1 || echo "http_garden.sh: could not push the marker image"
  rm -rf "${marker}"
fi

# The build is what takes time and disk, so both are reported beside the comparison. The images are
# built one at a time, which a runner with a few cores and 16 GB of memory can hold. The Garden's
# own base image and colibri's must build. An origin's image that does not, because a download it
# names has moved since the pinned commit, is reported and left out of the comparison.
build_started="$(date +%s)"
if pull http-garden-soil:latest soil; then
  echo "http_garden.sh: pulled the Garden's base image"
else
  (cd "${garden}" && docker pull -q debian:trixie-slim && docker build -q -t http-garden-soil ./images/http-garden-soil) ||
    fail "the Garden's base image did not build"
  push http-garden-soil:latest soil
fi
(cd "${garden}" && docker compose build colibri) || fail "colibri's image did not build"
ready=()
pulled=()
unbuilt=()
for origin in "${origins[@]}"; do
  if pull "$(local_image "${origin}")" "${origin}"; then
    pulled+=("${origin}")
    ready+=("${origin}")
  elif (cd "${garden}" && docker compose build "${origin}"); then
    push "$(local_image "${origin}")" "${origin}"
    ready+=("${origin}")
  else
    unbuilt+=("${origin}")
  fi
done
echo "http_garden.sh: ${#ready[@]} of ${#origins[@]} origins ready, ${#pulled[@]} pulled, in $(($(date +%s) - build_started)) seconds"
[ "${#unbuilt[@]}" -eq 0 ] || echo "http_garden.sh: unbuilt=${#unbuilt[@]}: ${unbuilt[*]}"
[ "${#ready[@]}" -gt 0 ] || fail "no origin's image is ready"
docker system df

# The named services that accept a TCP connection on their port within `start_wait_seconds`, one
# a line. The port is the Garden's: its `port` property, or 443 for TLS and 80 otherwise.
reachable() {
  (cd "${garden}" && uv run python3 - "${start_wait_seconds}" "$@") <<'PYTHON'
import socket
import sys
import time

import docker
import yaml

network_name = "http-garden_default"
services = yaml.safe_load(open("docker-compose.yml"))["services"]
addresses = {
    container.labels["com.docker.compose.service"]: container.attrs["NetworkSettings"]["Networks"][network_name]["IPAddress"]
    for container in docker.from_env().networks.get(network_name).containers
}
waiting = list(sys.argv[2:])
deadline = time.monotonic() + float(sys.argv[1])
while waiting and time.monotonic() < deadline:
    for name in list(waiting):
        properties = services[name].get("x-props", {})
        port = properties.get("port", 443 if properties.get("requires-tls") else 80)
        try:
            socket.create_connection((addresses[name], port), timeout=1).close()
        except (KeyError, OSError):
            continue
        print(name)
        waiting.remove(name)
    time.sleep(1)
PYTHON
}

# Whether the first argument is one of the rest.
among() {
  local wanted="$1"
  shift
  local name
  for name in "$@"; do
    [ "${name}" = "${wanted}" ] && return 0
  done
  return 1
}

# The named services whose containers are not running, one a line.
stopped() {
  local running
  running="$(cd "${garden}" && docker compose ps --status running --services)"
  local name
  for name in "$@"; do
    grep -qx "${name}" <<<"${running}" || echo "${name}"
  done
}

(cd "${garden}" && docker compose up -d colibri "${ready[@]}")
mapfile -t live < <(reachable colibri "${ready[@]}")
among colibri "${live[@]}" || fail "colibri's server accepted no connection"
compared=()
unreachable=()
for origin in "${ready[@]}"; do
  if among "${origin}" "${live[@]}"; then compared+=("${origin}"); else unreachable+=("${origin}"); fi
done
if [ "${#unreachable[@]}" -gt 0 ]; then
  echo "http_garden.sh: unreachable=${#unreachable[@]}: ${unreachable[*]}"
  (cd "${garden}" && docker compose logs --tail 5 "${unreachable[@]}") || true
fi
[ "${#compared[@]}" -gt 0 ] || fail "no origin accepted a connection"
echo "http_garden.sh: comparing colibri with ${#compared[@]} origins"

readonly scratch="$(mktemp -d)"
: >"${scratch}/output"

# run_case <case> <origin>...: one case through a REPL of its own, whose output joins the rest.
run_case() {
  local name="$1"
  shift
  python3 "${driver}" case "${name}" "$@" >"${scratch}/case"
  (cd "${garden}" && uv run ./tools/repl.py) <"${scratch}/case" >>"${scratch}/output" 2>"${scratch}/error"
}

# The REPL stops at the first server it cannot reach, so each case runs in its own. A case that
# brings a server down is reported with that server's last lines, the server is restarted, and
# the case runs once more without it. colibri's own server is never left out.
while IFS= read -r name <&3; do
  run_case "${name}" "${compared[@]}" && continue
  mapfile -t down < <(stopped colibri "${compared[@]}")
  echo "http_garden.sh: ${name}: the REPL failed ($(tail -1 "${scratch}/error")); down: ${down[*]:-none}"
  if [ "${#down[@]}" -gt 0 ]; then
    (cd "${garden}" && docker compose logs --tail 5 "${down[@]}" && docker compose up -d "${down[@]}") || true
    reachable "${down[@]}" >/dev/null
  fi
  without=()
  for origin in "${compared[@]}"; do
    among "${origin}" "${down[@]}" || without+=("${origin}")
  done
  run_case "${name}" "${without[@]}" ||
    echo "http_garden.sh: ${name}: the REPL failed again ($(tail -1 "${scratch}/error"))"
done 3< <(python3 "${driver}" names)

[ -z "${GARDEN_REPL_OUTPUT:-}" ] || cp "${scratch}/output" "${GARDEN_REPL_OUTPUT}"
if ! python3 "${driver}" report <"${scratch}/output"; then
  # What the REPL printed for the first case that went uncompared.
  first="$(python3 "${driver}" uncompared <"${scratch}/output" | head -1)"
  echo "http_garden.sh: the REPL's output for ${first}:"
  grep -a -A 40 "\[b'${first}'\]" "${scratch}/output" | cut -c 1-200 | head -60
  fail "not every stream was compared"
fi
rm -rf "${scratch}"
