# shellcheck shell=bash
#
# The counts of bench/run_latency.sh that say which side of a load was the limit (design §8 step
# 13s): how long the threads of a process ran, and the UDP datagrams the kernel dropped.
# run_latency.sh sources this file. Check the two files with `shellcheck -x bench/run_latency.sh`.

# Each thread of <pid>, one line each: its number and the nanoseconds it has run, from the first
# field of its schedstat. A thread that ends as the loop reads it is left out.
thread_nanoseconds() {  # thread_nanoseconds <pid>
  local stat ns rest thread
  for stat in /proc/"$1"/task/*/schedstat; do
    { read -r ns rest <"$stat"; } 2>/dev/null || continue
    thread="${stat%/schedstat}"
    echo "${thread##*/} $ns"
  done
}

# The UDP datagrams the kernel dropped since it started, from /proc/net/snmp: InErrors, which
# counts the drops of a full receive buffer, and SndbufErrors.
udp_drops() {
  awk '$1 == "Udp:" && !named { for (i = 2; i <= NF; i++) column[$i] = i; named = 1; next }
    $1 == "Udp:" { print $column["InErrors"] + $column["SndbufErrors"] }' /proc/net/snmp
}
