# shellcheck shell=bash
#
# The h3 pieces of bench/run.sh (design §8 step 13d): the load of the h3 inputs, colibri's UDP
# servers, and quic-go's server, which runs from an image in a container. run.sh sources this file
# after it sets its options and constants.
#
# run.sh assigns the variables that this file reads, and reads the ones that it assigns.
# bench/.shellcheckrc lets shellcheck follow run.sh's source line, so check the two files with
# `shellcheck bench/run.sh`. A check of this file alone warns about the variables run.sh owns.

# h3-one's load: h2load runs this many times, with this many connections each, as many connections
# in all as h2-one's. The UDP server holds 64 connections at once, and one that ended keeps its
# slot through its draining period (RFC 9000 §10.2.2), so each run opens fewer.
readonly one_h3_runs=80
readonly one_h3_clients=8
# An h3 competitor runs from the image its project publishes for the QUIC Interop Runner, pinned
# by digest. quic-go's is the one tools/channel_interop.sh pins.
readonly quic_go_image="martenseemann/quic-go-interop@sha256:5b921a144cbac11d465f63bd49e0d391b72773643288612fd65a3243cd423f10"
# The port a server of the QUIC Interop Runner listens on, which it takes no argument for.
readonly interop_port=443
# The image tools/h3load/Dockerfile builds, and the shell that runs an h2load with HTTP/3: the
# image's, or this one when the PATH's h2load has HTTP/3. A container does not take the cores
# taskset gives the command that starts it, so the judge names the load generator's cores here.
readonly h3load_image="${BENCH_H3LOAD_IMAGE:-colibri-h3load:latest}"
if [ "${BENCH_H3LOAD:-image}" = native ]; then
  h3_shell=(bash -c)
else
  h3_shell=(docker run --rm --network host)
  if [ "$mode" = judge ]; then h3_shell+=(--cpuset-cpus "$load_cores"); fi
  h3_shell+=("$h3load_image" sh -c)
fi
readonly h3_shell
# What an h3 input asks for: a file of the eight octets colibri's h2 server answers with, which
# each server reads from its directory. The servers of design §11.3 that colibri's is measured
# against over h3 answer from files alone, so colibri's does the same work.
readonly h3_file=colibri.txt
# The container a server runs in, for a competitor that runs from an image, and the log its
# measurement keeps.
server_container=""
server_log=""

# Whether a variant runs from an image, in a container, and not as a command of this machine.
runs_from_image() {  # runs_from_image <variant>
  case "$1" in
    quic-go) true ;;
    *) false ;;
  esac
}

port_of() {  # port_of <variant>
  if runs_from_image "$1"; then echo "$interop_port"; else echo "$port"; fi
}

# The command that serves an h3 input as a build of colibri, into the array `command`: the UDP
# server of the change or of the base, in its h3 mode.
quic_server_command() {  # quic_server_command <variant>
  if [ "$1" = base ]; then command=("$base_quic_server"); else command=("$change_quic_server"); fi
  command+=(server 127.0.0.1 "$port" "$identity" "$scratch/www" h3)
}

# A server in a container writes the container's log. Before stop_container removes the
# container, this function copies that log to the measurement's log.
save_container_log() {
  if [ -n "$server_container" ]; then docker logs "$server_container" >"$server_log" 2>&1 || true; fi
}

# Starts a competitor from its image, on the server's core in a judge run, and names the process
# that serves in server_pid. The identity and the file are copied in, because a path of this
# machine means nothing to a Docker daemon that runs on another.
start_container() {  # start_container <variant>
  local pin=()
  if [ "$mode" = judge ]; then pin=(--cpuset-cpus "$server_core"); fi
  server_container="colibri-bench-$1-$$"
  case "$1" in
    # The QUIC Interop Runner's contract: TESTCASE names what the server serves, from /www, with
    # the identity in /certs, and the server writes its log in /logs, without which it does not
    # start. The image's own start script sets up the runner's network and turns debug logging
    # on, so the server is started without it.
    quic-go)
      docker create --name "$server_container" --network host "${pin[@]}" -e TESTCASE=http3 \
        --tmpfs /logs --entrypoint /quic-go/server "$quic_go_image" >/dev/null
      ;;
  esac
  docker cp -q "$scratch/certs/." "$server_container:/certs"
  docker cp -q "$scratch/www/." "$server_container:/www"
  docker start "$server_container" >/dev/null
  server_pid="$(docker inspect -f '{{.State.Pid}}' "$server_container")"
}

# Ends the server in the container: copies the container's log, then removes the container.
stop_container() {
  save_container_log
  docker rm -f "$server_container" >/dev/null
  server_container=""
  server_pid=""
}

# The lines machine.txt holds for h3: the h2load that sends the h3 inputs, and the quic-go commit
# that quic-go's image holds.
h3_machine() {
  if [ -n "$h3" ]; then
    echo "h2load for h3=$("${h3_shell[@]}" "h2load --version" 2>/dev/null | head -1), ${BENCH_H3LOAD:-$h3load_image}"
  fi
  if [ -n "$competitors" ] && wants quic-go; then
    echo "quic-go=commit $(docker run --rm --entrypoint cat "$quic_go_image" /quic-go/commit.txt 2>/dev/null), $quic_go_image"
  fi
}

# Writes what the h3 servers read: the file each request asks for, and the identity where a server
# of the QUIC Interop Runner reads it. It names colibri's UDP servers, which come from the same
# builds as the h2 servers. It fetches quic-go's image before any measurement when this machine
# does not hold it.
prepare_h3() {
  change_quic_server="${BENCH_QUIC_SERVER:-$(dirname "$change_server")/quic-udp}"
  base_quic_server="${BENCH_BASE_QUIC_SERVER:-}"
  if [ -z "$base_quic_server" ] && [ -n "$base_server" ]; then base_quic_server="$(dirname "$base_server")/quic-udp"; fi
  mkdir -p "$scratch/www" "$scratch/certs"
  printf 'colibri\n' >"$scratch/www/$h3_file"
  cp "$identity.chain.pem" "$scratch/certs/cert.pem"
  cp "$identity.key.pem" "$scratch/certs/priv.key"
  if [ -n "$competitors" ] && wants quic-go && ! docker image inspect "$quic_go_image" >/dev/null 2>&1; then
    docker pull -q "$quic_go_image" >/dev/null
  fi
}
