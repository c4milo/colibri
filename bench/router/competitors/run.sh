#!/usr/bin/env bash
#
# The router benchmark: colibri's `match` against other routers, over the GitHub API's 203 routes
# of github_routes.txt (go-http-routing-benchmark's list, BSD-3-Clause, Julien Schmidt). Each
# router registers the routes, then matches every route's path a number of rounds, and prints the
# nanoseconds of one match. All run on Linux in containers on this machine. Where callgrind can
# count it, the script also prints the instructions of one match. The owner ruled the scope on
# 2026-10-26; its numbers are a laptop's and are never published (decision 32).
#
#   bench/router/competitors/run.sh [rounds]
#
# It needs Zig 0.16 for colibri, Zig 0.17 for http.zig (BENCH_ZIG_HTTPZ, or Homebrew's zig), and
# Docker. zap's router matches exact paths and h2o's matches prefixes, so neither can route these
# patterns, and neither runs here.
set -euo pipefail

readonly here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly tree="$(cd "${here}/../../.." && pwd)"
readonly rounds="${1:-20000}"
readonly callgrind_rounds=200
case "$(uname -m)" in
  arm64 | aarch64) arch=aarch64; platform=linux/arm64 ;;
  x86_64 | amd64) arch=x86_64; platform=linux/amd64 ;;
  *) echo "run.sh: no Linux target for $(uname -m)" >&2; exit 1 ;;
esac
readonly work="${tree}/.zig-cache/bench-router-competitors"
mkdir -p "${work}/bin"
readonly routes="${here}/github_routes.txt"

readonly go_image="golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437"
readonly rust_image="rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f"
readonly node_image="node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205"
readonly valgrind_image=colibri-bench-router-valgrind
readonly zig17="${BENCH_ZIG_HTTPZ:-/opt/homebrew/Cellar/zig/0.17.0/bin/zig}"

# colibri, from a copy three levels below the tree: ReleaseSafe, the one mode colibri offers, and
# ReleaseFast, which only this benchmark builds, to show what the assertions cost.
rm -rf "${work}/colibri" && mkdir -p "${work}/colibri"
cp "${here}"/colibri/* "${here}/../hook.zig" "${routes}" "${work}/colibri/"
for mode in safe fast; do
  (cd "${work}/colibri" && zig build -Dtarget="${arch}-linux" -Dfast=$([ "${mode}" = fast ] && echo true || echo false) --prefix "${work}/colibri/${mode}")
  cp "${work}/colibri/${mode}/bin/router-bench" "${work}/bin/colibri-${mode}"
done

# http.zig, with Zig 0.17.
rm -rf "${work}/httpz" && mkdir -p "${work}/httpz"
cp "${here}"/httpz/* "${work}/httpz/"
(cd "${work}/httpz" && "${zig17}" build -Dtarget="${arch}-linux" --prefix "${work}/httpz/out")
cp "${work}/httpz/out/bin/router-bench" "${work}/bin/httpz"

# Rust and Go, built in their images. Each writes its binary into the work directory.
rm -rf "${work}/rust" "${work}/go" && cp -R "${here}/rust" "${here}/go" "${work}/"
docker run --rm --platform "${platform}" -v "${work}/rust:/src" -w /src "${rust_image}" \
  sh -c 'cargo build --release --locked -q && cp target/release/router-bench /src/router-bench'
cp "${work}/rust/router-bench" "${work}/bin/rust"
docker run --rm --platform "${platform}" -v "${work}/go:/src" -w /src -e CGO_ENABLED=0 "${go_image}" \
  go build -o /src/router-bench .
cp "${work}/go/router-bench" "${work}/bin/go"
docker build --quiet -t "${valgrind_image}" -f "${here}/../valgrind.Dockerfile" "${here}/.." >/dev/null

cp "${routes}" "${work}/bin/github_routes.txt"
run() {
  docker run --rm --platform "${platform}" -v "${work}/bin:/bin-bench" "${valgrind_image}" "$@"
}
instructions() {
  # The instructions of one match: callgrind's count for `callgrind_rounds` rounds less its count
  # for none, divided by the matches.
  local none all
  none="$(run sh -c "valgrind --tool=callgrind --callgrind-out-file=/dev/null $* 0 2>&1 | sed -n 's/.*Collected : \([0-9]*\).*/\1/p'")"
  all="$(run sh -c "valgrind --tool=callgrind --callgrind-out-file=/dev/null $* ${callgrind_rounds} 2>&1 | sed -n 's/.*Collected : \([0-9]*\).*/\1/p'")"
  echo $(((all - none) / (callgrind_rounds * 203)))
}

echo "router ns_per_match instructions_per_match"
for name in colibri-safe colibri-fast; do
  echo "${name} $(run /bin-bench/${name} "${rounds}" | sed -n 's/.*ns_per_match=//p') $(instructions /bin-bench/${name})"
done
echo "httpz $(run sh -c "/bin-bench/httpz /bin-bench/github_routes.txt ${rounds} 2>&1" | sed -n 's/.*ns_per_match=//p') $(instructions /bin-bench/httpz /bin-bench/github_routes.txt)"
for router in matchit actix; do
  # actix tries each pattern with a regular expression, so it runs fewer rounds.
  router_rounds="${rounds}"
  [ "${router}" = actix ] && router_rounds=$((rounds / 100))
  echo "${router} $(run /bin-bench/rust ${router} /bin-bench/github_routes.txt "${router_rounds}" | sed -n 's/.*ns_per_match=//p') $(instructions /bin-bench/rust ${router} /bin-bench/github_routes.txt)"
done
for router in httprouter chi servemux; do
  echo "${router} $(run /bin-bench/go ${router} /bin-bench/github_routes.txt "${rounds}" | sed -n 's/.*ns_per_match=//p') -"
done
rm -rf "${work}/node" && cp -R "${here}/node" "${work}/node"
echo "find-my-way $(docker run --rm --platform "${platform}" -v "${work}/node:/src" -v "${work}/bin:/bin-bench" -w /src "${node_image}" \
  sh -c "npm ci --silent --no-audit --no-fund >/dev/null && node main.js /bin-bench/github_routes.txt ${rounds}" | sed -n 's/.*ns_per_match=//p') -"
