# shellcheck shell=bash
#
# The competitors of bench/run.sh with --competitors (design §8 steps 13c, 13g, 13o and 13r): which
# ones the run measures, and the builds of hyper, axum, http.zig and Go's servers. run.sh sources
# this file after it builds colibri's servers.
#
# run.sh assigns the variables that this file reads, and reads the ones that it assigns, as
# run_h3.sh does. Check the two files with `shellcheck bench/run.sh`.

# Whether --competitors measures <competitor>.
wants() {  # wants <competitor>
  local name
  for name in "${competitor_names[@]}"; do [ "$name" = "$1" ] && return 0; done
  return 1
}

# The version of <crate> that the Cargo.lock of bench/competitors/<server> pins, hyper's by default.
locked() {  # locked <crate> [server]
  awk -v crate="$1" '$0 == "name = \"" crate "\"" { getline; gsub(/version = |"/, ""); print; exit }' \
    "$repository_root/bench/competitors/${2:-hyper}/Cargo.lock"
}

hyper_server="${BENCH_HYPER:-}"
if [ -n "$competitors" ] && wants hyper && [ -z "$hyper_server" ]; then
  echo "run.sh: building hyper" >&2
  # rustup reads the release that rust-toolchain.toml names in the directory cargo runs in.
  (cd "$repository_root/bench/competitors/hyper" && cargo build --release --locked --quiet --target-dir "$scratch/hyper")
  hyper_server="$scratch/hyper/release/colibri-bench-hyper"
fi
httpz_server="${BENCH_HTTPZ:-}"
if [ -n "$competitors" ] && wants httpz && [ -z "$httpz_server" ]; then
  echo "run.sh: building http.zig" >&2
  (cd "$repository_root/bench/competitors/httpz" &&
    "${BENCH_ZIG_HTTPZ:?BENCH_ZIG_HTTPZ names the Zig 0.17.1 that builds http.zig}" build \
      --prefix "$scratch/httpz" --cache-dir "$scratch/httpz-cache" >/dev/null)
  httpz_server="$scratch/httpz/bin/colibri-bench-httpz"
fi

axum_server="${BENCH_AXUM:-}"
if [ -n "$competitors" ] && wants axum && [ -z "$axum_server" ]; then
  echo "run.sh: building axum" >&2
  (cd "$repository_root/bench/competitors/axum" &&
    cargo build --release --locked --quiet --target-dir "$scratch/axum-target")
  axum_server="$scratch/axum-target/release/colibri-bench-axum"
fi

nethttp_server="${BENCH_NETHTTP:-}"
if [ -n "$competitors" ] && wants nethttp && [ -z "$nethttp_server" ]; then
  echo "run.sh: building Go's net/http server" >&2
  (cd "$repository_root/bench/competitors/nethttp" && go build -trimpath -o "$scratch/nethttp" .)
  nethttp_server="$scratch/nethttp"
fi
fasthttp_server="${BENCH_FASTHTTP:-}"
if [ -n "$competitors" ] && wants fasthttp && [ -z "$fasthttp_server" ]; then
  echo "run.sh: building fasthttp" >&2
  (cd "$repository_root/bench/competitors/fasthttp" && go build -trimpath -o "$scratch/fasthttp" .)
  fasthttp_server="$scratch/fasthttp"
fi
if [ -n "$competitors" ] && wants fastify; then
  echo "run.sh: installing Fastify" >&2
  cp -R "$repository_root/bench/competitors/fastify" "$scratch/fastify"
  (cd "$scratch/fastify" && npm ci --silent --no-audit --no-fund >/dev/null)
fi

# The machine lines that name each competitor's version, which run.sh's report header holds.
competitors_machine() {
  if wants nginx; then
    echo "nginx=$(nginx -v 2>&1 | sed 's/^nginx version: //'), $(nginx -V 2>&1 | sed -n 's/^built with //p')"
  fi
  if wants h2o; then
    echo "h2o=$(h2o --version 2>/dev/null | sed -n 's/^h2o version //p'), $(h2o --version 2>/dev/null | sed -n 's/^OpenSSL: //p')"
  fi
  # Cargo.lock names each crate's version; rustls's provider is aws-lc-rs.
  if wants hyper; then
    # rustc runs in hyper's directory, whose rust-toolchain.toml names the release.
    echo "hyper=$(locked hyper), hyper-util $(locked hyper-util), tokio $(locked tokio), rustls $(locked rustls), aws-lc-rs $(locked aws-lc-rs), $(cd "$repository_root/bench/competitors/hyper" && rustc --version 2>/dev/null || echo 'rustc unknown')"
  fi
  if wants axum; then
    echo "axum=$(locked axum axum), h3 $(locked h3 axum), quinn $(locked quinn axum), $(cd "$repository_root/bench/competitors/axum" && rustc --version 2>/dev/null || echo 'rustc unknown')"
  fi
  if wants httpz; then
    echo "http.zig=$(sed -n 's|.*karlseguin/http.zig#\([0-9a-f]*\).*|\1|p' "$repository_root/bench/competitors/httpz/build.zig.zon" | head -1), zig $("${BENCH_ZIG_HTTPZ:-zig}" version 2>/dev/null || echo unknown)"
  fi
  if wants nethttp; then echo "net/http=$(go version 2>/dev/null | cut -d' ' -f3)"; fi
  if wants fastify; then
    echo "fastify=$(sed -n 's/.*"fastify": "\(.*\)".*/\1/p' "$repository_root/bench/competitors/fastify/package.json"), node $(node --version)"
  fi
  if wants fasthttp; then
    echo "fasthttp=$(sed -n 's|^require github.com/valyala/fasthttp \(.*\)|\1|p' "$repository_root/bench/competitors/fasthttp/go.mod"), $(go version 2>/dev/null | cut -d' ' -f3)"
  fi
}
