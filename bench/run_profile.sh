# shellcheck shell=bash
#
# The profile of bench/run.sh with --profile (design §8 step 13h): after the warm-up round, perf
# record samples colibri's server and its call stacks under each input, once. Then
# bench/report_profile.py writes the functions that took the most samples, and the folded stacks
# that a flame graph reads. A profile shows where the time goes. It never counts as a measurement,
# and no document publishes its numbers (docs/performance.md).
#
# run.sh assigns the variables that this file reads, as run_h3.sh does. Check the files with
# `shellcheck bench/run.sh`.

# The samples each second, and the octets of stack that each sample copies. perf unwinds the stack
# with the DWARF call frame information, which a ReleaseSafe build keeps for Zig and for chapulin's
# C code.
readonly profile_frequency=1999
readonly profile_stack_bytes=16384
# The times perf record runs each input's load. One h2-many load keeps the server busy for about
# a quarter of a second, which gave 127 samples at 499 Hz on a laptop.
readonly profile_loads=10
# The event perf samples on: the cycles on the judge, or BENCH_PROFILE_EVENT=cpu-clock on a machine
# whose kernel exposes no hardware counters, such as a virtual machine on a laptop.
readonly profile_event="${BENCH_PROFILE_EVENT:-cycles}"

# A profile needs perf, and records colibri's build alone, in one round after the warm-up.
check_profile() {
  [ -z "$profile" ] && return 0
  if [ "$mode" != judge ] || [ -n "$base" ] || [ -n "$competitors" ]; then
    echo "run.sh: --profile needs perf, and takes no --filter, --base or --competitors" >&2
    exit 2
  fi
  rounds=1
}

# Samples the server under one input, and writes each sample's stack as text for the report. Zig
# inlines much of colibri, so perf script names each inlined function as a frame of its own.
record_profile() {  # record_profile <name> <variant> <input>
  sudo -n "${PERF:-perf}" record -q -e "$profile_event" -F "$profile_frequency" \
    --call-graph "dwarf,$profile_stack_bytes" \
    -o "$scratch/$1.data" -p "$server_pid" -- \
    taskset -c "$load_cores" bash -c 'for _ in $(seq "$1"); do bash "$2" "$3" "$4"; done' \
    load "$profile_loads" "$scratch/load.sh" "$3" "$(port_of "$2")" >"$scratch/$1.h2load"
  sudo -n "${PERF:-perf}" script -i "$scratch/$1.data" --inline -F comm,ip,sym,dso >"$scratch/$1.stacks" 2>/dev/null
  echo "$3,$scratch/$1.stacks" >>"$scratch/profiles.csv"
}
