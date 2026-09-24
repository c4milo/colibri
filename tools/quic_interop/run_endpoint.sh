#!/bin/bash
#
# The QUIC Interop Runner's endpoint contract (its quic.md) mapped onto colibri's quic-udp
# endpoint (design §9). The runner sets ROLE, TESTCASE and, for a client, REQUESTS, mounts /www,
# /downloads and /certs, and treats exit status 127 as a test case the endpoint does not support.
set -euo pipefail

# The runner's network setup, which every endpoint image runs first.
/setup.sh

# hq-interop over one connection covers these, and a Retry both roles now handle: the server
# sends one when asked, with a token chapulin mints (decision 55). The rest are not built.
case "$TESTCASE" in
  handshake | transfer | chacha20 | multiconnect | retry) ;;
  *) exit 127 ;;
esac

python3 /qns_identity.py /certs /tmp/identity

if [ "$ROLE" = server ]; then
  server_options=()
  [ "$TESTCASE" = retry ] && server_options+=(retry)
  exec quic-udp server 0.0.0.0 443 /tmp/identity /www "${server_options[@]}"
fi

/wait-for-it.sh sim:57832 -s -t 30

# Every URL names the same host and port; the paths are what the client fetches.
first="${REQUESTS%% *}"
authority="${first#https://}"
authority="${authority%%/*}"
host="${authority%%:*}"
port=443
[ "$authority" != "$host" ] && port="${authority##*:}"
paths=()
for url in $REQUESTS; do
  paths+=("/${url#https://*/}")
done

# The endpoint speaks IPv4, so a host with no IPv4 address is a test case it does not support.
address="$(getent ahostsv4 "$host" | awk 'NR == 1 { print $1 }')"
[ -n "$address" ] || exit 127

client() {
  quic-udp client "$address" "$port" /tmp/identity "$host" "$(date +%s)" /downloads "$@"
}

if [ "$TESTCASE" = multiconnect ]; then
  # One connection per file, one after the other.
  for path in "${paths[@]}"; do client "$path"; done
else
  client "${paths[@]}"
fi
