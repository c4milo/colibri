# shellcheck shell=bash
#
# The throughput mode of bench/run.sh, --throughput (design §8 step 13q). Each server answers
# h2load, or wrk for h11, at full speed for throughput_seconds, from the load cores. The report,
# bench/report_throughput.py, gives the requests a second the load tool counted, and the share of
# its core the server's threads ran. A server whose core was not near full ran faster than the
# load tool could ask, and the report says the load was the limit.
#
# run.sh sources this file after it builds the servers, as it sources run_competitors.sh, and
# reads what it assigns. Check the files with `shellcheck bench/run.sh`.

# The seconds each load lasts.
readonly throughput_seconds=10
# The connections each load holds: colibri's test-only server holds 32 at once on its one worker.
readonly throughput_clients=32
# The streams h2load keeps open on each h2 or h3 connection, and the threads of each load tool, one
# on each load core.
readonly throughput_streams=100
readonly throughput_threads=2

# The load of each input, as a script of its own, as load.sh is. wrk and h2load each write their
# own count of requests a second.
cat >"$scratch/load_throughput.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
case "\$1" in
  *-tls-*) target=https://127.0.0.1:\$2/; options=(--tls13-ciphers=${tls_suite}) ;;
  *) target=http://127.0.0.1:\$2/; options=() ;;
esac
case "\$1" in
  h11-*)
    OPENSSL_CONF=${scratch}/openssl.cnf exec wrk -t ${throughput_threads} -c ${throughput_clients} \\
      -d ${throughput_seconds}s "\$target" ;;
  h3-*) ${h3_shell[*]} "h2load --alpn-list=h3 --tls13-ciphers=${tls_suite} -D ${throughput_seconds} -t ${throughput_threads} -c ${throughput_clients} -m ${throughput_streams} https://127.0.0.1:\$2/${h3_file}" ;;
  *) exec h2load "\${options[@]}" -D ${throughput_seconds} -t ${throughput_threads} \\
      -c ${throughput_clients} -m ${throughput_streams} "\$target" ;;
esac
EOF

# The line machine.txt holds for the mode.
throughput_machine() {
  echo "throughput=${throughput_seconds} s a load, ${throughput_clients} connections, ${throughput_streams} streams on each h2 or h3 connection, ${throughput_threads} load threads"
}

# Runs <input>'s load against <variant>'s server, and keeps the server's CPU time and the load's
# wall time beside the load tool's report.
measure_throughput() {  # measure_throughput <variant> <input> <round>
  local name="$1-$2-$3" cpu_before wall_before pin=()
  start_server "$1" "$2" "$scratch/$name.server"
  if [ "$mode" = judge ]; then pin=(taskset -c "$load_cores"); fi
  cpu_before="$(cpu_nanoseconds "$server_pid")"
  wall_before="$(date +%s%N)"
  "${pin[@]}" bash "$scratch/load_throughput.sh" "$2" "$(port_of "$1")" >"$scratch/$name.load"
  echo "$(($(cpu_nanoseconds "$server_pid") - cpu_before)),$(($(date +%s%N) - wall_before))" >"$scratch/$name.cpu"
  stop_server
  echo "$1,$2,$3,$scratch/$name.cpu,$scratch/$name.load" >>"$scratch/throughput.csv"
}
