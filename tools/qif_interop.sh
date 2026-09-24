#!/usr/bin/env bash
#
# The QIF interop of design §8 step 11: colibri's two QIF tools (design §9) against ls-qpack,
# through pylsqpack, the QPACK of aioquic, in both directions, over the qpackers/qifs inputs.
# For each input and setting:
# - colibri encodes, in both acknowledgment modes, and ls-qpack decodes;
# - ls-qpack encodes, with each section ahead of its encoder stream octets when streams may
#   block, and colibri decodes;
# - colibri encodes and colibri decodes.
# Every decoded file must hold the input's header sets, in stream order.
#
# It needs python3. aioquic, which brings pylsqpack, is pinned and installed once into the same
# cached virtual environment tools/quic_aioquic.sh uses. The qifs inputs come from the Zig package
# (decision 75), which the first build fetches. It is not part of `zig build test`.
#
#   tools/qif_interop.sh
set -euo pipefail

readonly aioquic_version="1.3.0"
readonly venv="${XDG_CACHE_HOME:-$HOME/.cache}/colibri/aioquic-${aioquic_version}"
readonly inputs=(netbsd fb-req fb-resp)
# Table capacity and blocked streams: none, a small table that must evict, and a large one that
# may block.
readonly settings=("0 0" "256 0" "4096 100")

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

echo "qif_interop: building the tools"
zig build
qif=./zig-out/bin/qif
if [ ! -x "$venv/bin/python" ]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q "aioquic==${aioquic_version}"
fi
peer=("$venv/bin/python" tools/quic_interop/qif_peer.py)

# Runs one command with its output in a log, which is printed only when the command fails.
quietly() {
  "$@" >"$scratch/log" 2>&1 || {
    echo "qif_interop: failed: $*" >&2
    cat "$scratch/log" >&2
    exit 1
  }
}
netbsd="$(ls zig-pkg/*/qifs/netbsd.qif 2>/dev/null | head -1)"
[ -n "$netbsd" ] || { echo "qif_interop: no qifs package in zig-pkg; run zig build test once" >&2; exit 1; }
qifs="$(dirname "$netbsd")"

runs=0
for input in "${inputs[@]}"; do
  source="$qifs/$input.qif"
  for setting in "${settings[@]}"; do
    read -r capacity blocked <<<"$setting"
    for acknowledgment in 0 1; do
      quietly "$qif" encode "$source" "$scratch/colibri.out" "$capacity" "$blocked" "$acknowledgment"
      quietly "${peer[@]}" decode "$scratch/colibri.out" "$scratch/lsqpack.qif" "$capacity" "$blocked"
      quietly "${peer[@]}" compare "$source" "$scratch/lsqpack.qif"
      quietly "$qif" decode "$scratch/colibri.out" "$scratch/colibri.qif" "$capacity" "$blocked"
      quietly "${peer[@]}" compare "$source" "$scratch/colibri.qif"
      runs=$((runs + 2))
    done
    reorder=""
    [ "$blocked" -gt 0 ] && reorder="reorder"
    quietly "${peer[@]}" encode "$source" "$scratch/lsqpack.out" "$capacity" "$blocked" $reorder
    quietly "$qif" decode "$scratch/lsqpack.out" "$scratch/from-lsqpack.qif" "$capacity" "$blocked"
    quietly "${peer[@]}" compare "$source" "$scratch/from-lsqpack.qif"
    runs=$((runs + 1))
    echo "qif_interop: $input at capacity $capacity, $blocked blocked streams: ok"
  done
done
echo "qif_interop: ok, $runs runs, ls-qpack through pylsqpack $("$venv/bin/pip" show pylsqpack | sed -n 's/^Version: //p')"
