# shellcheck shell=bash
#
# The competitors of bench/run.sh with --competitors (design §8 steps 13c and 13g): which ones the
# run measures, and the builds of hyper and http.zig. run.sh sources this file after it builds
# colibri's servers.
#
# run.sh assigns the variables that this file reads, and reads the ones that it assigns, as
# run_h3.sh does. Check the two files with `shellcheck bench/run.sh`.

# Whether --competitors measures <competitor>.
wants() {  # wants <competitor>
  local name
  for name in "${competitor_names[@]}"; do [ "$name" = "$1" ] && return 0; done
  return 1
}

# The version of <crate> that bench/competitors/hyper/Cargo.lock pins.
locked() {  # locked <crate>
  awk -v crate="$1" '$0 == "name = \"" crate "\"" { getline; gsub(/version = |"/, ""); print; exit }' \
    "$repository_root/bench/competitors/hyper/Cargo.lock"
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
    "${BENCH_ZIG_HTTPZ:?BENCH_ZIG_HTTPZ names the Zig 0.17.0 that builds http.zig}" build \
      --prefix "$scratch/httpz" --cache-dir "$scratch/httpz-cache" >/dev/null)
  httpz_server="$scratch/httpz/bin/colibri-bench-httpz"
fi
