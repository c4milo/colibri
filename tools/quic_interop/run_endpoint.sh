#!/bin/bash
#
# The QUIC Interop Runner's endpoint contract (its quic.md) mapped onto colibri's quic-udp
# endpoint (design §9). The runner sets ROLE, TESTCASE and, for a client, REQUESTS, mounts /www,
# /downloads and /certs, and treats exit status 127 as a test case the endpoint does not support.
set -euo pipefail

# The runner's network setup, which every endpoint image runs first.
/setup.sh

# hq-interop over one connection covers these, and a Retry both roles now handle: the server
# sends one when asked, with a token chapulin mints (decision 55). A key update is the client's
# to start; the runner gives the server `transfer` for it, as it does for the amplification limit
# and IPv6 cases. Both roles mark ECT(0) and report ECN counts in every case (decision 68), so
# `ecn` is a transfer. The rest are not built.
case "$TESTCASE" in
  handshake | transfer | chacha20 | multiconnect | retry | ecn) ;;
  keyupdate) [ "$ROLE" = client ] || exit 127 ;;
  *) exit 127 ;;
esac

python3 /qns_identity.py /certs /tmp/identity

if [ "$ROLE" = server ]; then
  server_options=()
  [ "$TESTCASE" = retry ] && server_options+=(retry)
  # Bound to the IPv6 wildcard, the one socket takes IPv4 clients too (as IPv4-mapped addresses),
  # because the runner gives the server no hint of which family its IPv6 case uses.
  exec quic-udp server :: 443 /tmp/identity /www "${server_options[@]}"
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

# IPv4 when the host has an IPv4 address, and IPv6 otherwise, which is the runner's IPv6 case.
# getent exits 2 for a name with no address of the family asked, which is not a failure here.
address="$(getent ahostsv4 "$host" | awk 'NR == 1 { print $1 }' || true)"
[ -n "$address" ] || address="$(getent ahostsv6 "$host" | awk 'NR == 1 { print $1 }' || true)"
[ -n "$address" ] || exit 127

client_options=()
[ "$TESTCASE" = keyupdate ] && client_options+=(keyupdate)

client() {
  quic-udp client "$address" "$port" /tmp/identity "$host" "$(date +%s)" /downloads "${client_options[@]}" "$@"
}

if [ "$TESTCASE" = multiconnect ]; then
  # One connection per file, one after the other.
  for path in "${paths[@]}"; do client "$path"; done
else
  client "${paths[@]}"
fi
