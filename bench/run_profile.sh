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

# The samples each second.
readonly profile_frequency=1999
# The times perf record runs each input's load. One h2-many load keeps the server busy for about
# a quarter of a second, which gave 127 samples at 499 Hz on a laptop.
readonly profile_loads=10
# The events perf may sample on, in order: the first one that the kernel lets perf sample. The
# judge's PMU refuses overflow interrupts, so perf there cannot sample `cycles`, and it read
# `cpu-clock` as a hardware event (run 40566337675). BENCH_PROFILE_EVENT names one event instead.
readonly profile_events=(cpu-clock software/cpu-clock/ task-clock cycles)
profile_event=""

# A profile needs perf, and records colibri's build alone, in one round after the warm-up.
check_profile() {
  [ -z "$profile" ] && return 0
  if [ "$mode" != judge ] || [ -n "$base" ] || [ -n "$competitors" ]; then
    echo "run.sh: --profile needs perf, and takes no --filter, --base or --competitors" >&2
    exit 2
  fi
  rounds=1
  local event
  for event in ${BENCH_PROFILE_EVENT:-"${profile_events[@]}"}; do
    if sudo -n "${PERF:-perf}" record -q -e "$event" -F "$profile_frequency" -o /dev/null -- true 2>/dev/null; then
      profile_event="$event"
      return 0
    fi
  done
  echo "run.sh: perf samples none of the events ${BENCH_PROFILE_EVENT:-${profile_events[*]}}" >&2
  exit 2
}

# Samples the server under one input, and writes each sample's stack as text for the report.
# perf walks each stack by its frame pointers, which Zig and chapulin's C code keep on arm64. The
# DWARF unwinder of perf 6.17 and 7.0 gave no frame in user space, and perf 7.0's inlined frames
# drop each name's namespace, so the report names the functions the binary holds.
record_profile() {  # record_profile <name> <variant> <input>
  sudo -n "${PERF:-perf}" record -e "$profile_event" -F "$profile_frequency" --call-graph fp \
    -o "$scratch/$1.data" -p "$server_pid" -- \
    taskset -c "$load_cores" bash -c 'for _ in $(seq "$1"); do bash "$2" "$3" "$4"; done' \
    load "$profile_loads" "$scratch/load.sh" "$3" "$(port_of "$2")" >"$scratch/$1.h2load"
  # perf's warnings, such as lost samples, go to the job's log.
  sudo -n "${PERF:-perf}" script -i "$scratch/$1.data" --no-inline -F comm,ip,sym,dso >"$scratch/$1.stacks"
  echo "$3,$scratch/$1.stacks" >>"$scratch/profiles.csv"
}
