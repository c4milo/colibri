# shellcheck shell=bash
#
# The checks bench/run.sh makes of each server before it measures it: that the server answers, that
# its warm-up answers in full, and that it codes the answers of a coded input. Split off
# bench/run.sh for length.
#
# run.sh assigns the variables that this file reads, as run_h3.sh does. Check the files with
# `shellcheck bench/run.sh`.

# h2load exits 0 even when every request fails, so each use of it here reads the count it reports.
# The output is read whole, because a reader that stops at the first match ends h2load early.
# <seconds> bounds h2load's run, and 0 leaves it unbounded.
succeeded() {  # succeeded <requests> <input> <seconds> <h2load arguments...>: whether all succeeded
  local requests="$1" input="$2" bound=() output
  if [ "$3" -gt 0 ]; then bound=(timeout "$3"); fi
  shift 3
  case "$input" in
    h3-*) output="$("${h3_shell[@]}" "${bound[*]} h2load --alpn-list=h3 --tls13-ciphers=${tls_suite} $*" 2>/dev/null)" || true ;;
    *) output="$("${bound[@]}" h2load "$@" 2>/dev/null)" || true ;;
  esac
  [[ "$output" == *", ${requests} succeeded, 0 failed,"* ]]
}

# Whether wrk's report <output> shows answers, none outside 2xx and 3xx, and no socket error but
# the read errors that a server's close after `Connection: close` counts as.
wrk_clean() {  # wrk_clean <output>
  [[ "$1" == *" requests in "* && "$1" != *"Non-2xx or 3xx responses"* ]] || return 1
  [[ "$1" != *"Socket errors:"* || "$1" == *"Socket errors: connect 0, read "*", write 0, timeout 0"* ]]
}

# Whether <variant>'s server answers one request for <input>: curl for h11, as wrk speaks it, and
# h2load for h2 and h3, which may take ready_seconds.
answers() {  # answers <variant> <input>
  local offer
  case "$2" in
    h11-*)
      [ "$(curl -sk --http1.1 --tls13-ciphers "$tls_suite" -o /dev/null -w '%{http_code}' "$(url "$1" "$2")")" = 200 ]
      ;;
    *)
      offer_of "$2"
      succeeded 1 "$2" "$ready_seconds" "${offer[@]}" -n 1 -c 1 "$(url "$1" "$2")"
      ;;
  esac
}

# Whether <variant>'s warm-up for <input> answers every request: load.sh's wrk for
# h11_warm_seconds, or h2load.
warms() {  # warms <variant> <input>
  local offer
  case "$2" in
    h11-*) wrk_clean "$(bash "$scratch/load.sh" "$2" "$(port_of "$1")" "$h11_warm_seconds" 2>/dev/null || true)" ;;
    *)
      offer_of "$2"
      succeeded "$warm_requests" "$2" 0 "${offer[@]}" -n "$warm_requests" -c "$many_clients" -m "$many_streams" "$(url "$1" "$2")"
      ;;
  esac
}

# Whether <variant>'s answer for <input> is coded as the input asks, so that the input counts coded
# responses: for a coded input, an answer to a request that accepts gzip names gzip in its
# Content-Encoding (RFC 9110 §8.4). Any other input passes.
codes() {  # codes <variant> <input>
  [[ "$2" == *-coded-* ]] || return 0
  curl -s --http2-prior-knowledge -H "$coded_accept" -D - -o /dev/null "$(url "$1" "$2")" |
    tr -d '\r' | grep -qi '^content-encoding: gzip$'
}
