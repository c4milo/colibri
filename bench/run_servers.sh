# shellcheck shell=bash
#
# The command that starts each server bench/run.sh measures: colibri's test-only server, built from
# the change or from the base, and each competitor, configured for cleartext or for TLS. Split off
# bench/run.sh for length.
#
# run.sh assigns the variables that this file reads, as run_h3.sh does. Check the files with
# `shellcheck bench/run.sh`.

# Writes a competitor's configuration from bench/competitors/ into the scratch directory. @SSL@
# goes first, because what it writes for h2o names @CHAIN@ and @KEY@ in turn. h2o's `user: root`
# line stays only when root runs this script, as its configuration says why.
render() {  # render <competitor> <ssl>
  local drop_user_line=(-e "/^user: root\$/d")
  if [ "$(id -u)" -eq 0 ]; then drop_user_line=(); fi
  sed -e "s|@SSL@|$2|g" -e "s|@PORT@|$port|g" -e "s|@SCRATCH@|$scratch|g" \
    -e "s|@CHAIN@|$identity.chain.pem|g" -e "s|@KEY@|$identity.key.pem|g" "${drop_user_line[@]}" \
    "$repository_root/bench/competitors/$1.conf" >"$scratch/$1.conf"
}

# Whether colibri's test-only server at <path> takes --seconds (design §8 step 48). A base tree
# from before that step refuses the option, and its usage does not name it. The server exits 2 at
# the unknown option, which pipefail would give a pipe, so the usage is read first.
takes_seconds() {  # takes_seconds <path>
  local usage
  usage="$("$1" --help 2>&1 || true)"
  grep -q -- '--seconds' <<<"$usage"
}

# The command that serves <input> as <variant>, into the array `command`: colibri's server built
# from the change or from the base, or a competitor configured for cleartext or for TLS.
server_command() {  # server_command <variant> <input>
  local tls=""
  case "$2" in *-tls-*) tls=yes ;; esac
  case "$1" in
    nginx)
      # The listen parameters. nginx 1.24 speaks no h11 on a cleartext port that has http2, and
      # over TLS it chooses by ALPN.
      local listen=http2
      case "$2" in h11-*) listen="" ;; esac
      if [ -n "$tls" ]; then listen="ssl http2"; fi
      render nginx "$listen"
      command=(nginx -p "$scratch" -e "$scratch/nginx.error.log" -c "$scratch/nginx.conf")
      ;;
    h2o)
      if [ -n "$tls" ]; then
        render h2o ", ssl: {certificate-file: @CHAIN@, key-file: @KEY@}"
      else
        render h2o ""
      fi
      command=(h2o -c "$scratch/h2o.conf")
      ;;
    hyper)
      command=("$hyper_server" --port "$port")
      if [ -n "$tls" ]; then command+=(--tls "$identity"); fi
      ;;
    httpz)
      command=("$httpz_server" --port "$port")
      ;;
    *)
      if [[ "$2" == h3-* ]]; then quic_server_command "$1" "$2"; return; fi
      if [ "$1" = base ]; then command=("$base_server"); else command=("$change_server"); fi
      command+=(--port "$port")
      if [ -n "$tls" ]; then command+=(--tls "$identity"); fi
      # Decision 161: with the Unix time the server issues session tickets, which a client such as
      # wrk resumes with, as it does with hyper's.
      if [ -n "$tls" ] && takes_seconds "${command[0]}"; then command+=(--seconds "$(date +%s)"); fi
      if [[ "$2" == *-routes-* ]]; then command+=(--routes github); fi
      ;;
  esac
}
