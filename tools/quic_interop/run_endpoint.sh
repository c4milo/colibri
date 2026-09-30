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
# `ecn` is a transfer. A server issues a session ticket on every connection, and a client asked
# for `resumption` presents the first connection's ticket on a second. `http3` fetches over h3,
# which the server serves in its `h3` mode, through the `server` module (design §8 step 17b). In
# `v2` the client starts in version 1, lists version 2, and switches when the server answers in it
# (RFC 9369 §4.1), and the server switches every client that lists version 2 (decision 111). Every
# other case requires one version on the wire, version 1, so there the server keeps each client in
# the version it started in (`no-switch`, decision 111). The rest are not built.
case "$TESTCASE" in
  handshake | transfer | chacha20 | multiconnect | retry | ecn | resumption | http3 | v2) ;;
  keyupdate) [ "$ROLE" = client ] || exit 127 ;;
  *) exit 127 ;;
esac

python3 /qns_identity.py /certs /tmp/identity

# Main schema §12.1: the runner names the directory each connection's qlog goes in, and keeps it
# with the run's logs (design §8 step 18c).
[ -n "${QLOGDIR:-}" ] && mkdir -p "$QLOGDIR"

if [ "$ROLE" = server ]; then
  # The Unix time the server starts at, which its session tickets carry (RFC 9846 §4.7.1).
  server_options=("seconds=$(date +%s)")
  [ "$TESTCASE" = retry ] && server_options+=(retry)
  [ "$TESTCASE" = v2 ] || server_options+=(no-switch)
  # The `h3` mode serves `http3` through the `server` module, whose log provider writes each
  # connection's qlog too (decision 102 as amended).
  if [ "$TESTCASE" = http3 ]; then
    server_options+=(h3)
  fi
  if [ -n "${QLOGDIR:-}" ]; then
    server_options+=("qlogdir=$QLOGDIR")
  fi
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

# The runner's certificates fail the Web PKI profile, so the client pins the server's key.
client_options=(pin)
[ "$TESTCASE" = keyupdate ] && client_options+=(keyupdate)
[ "$TESTCASE" = resumption ] && client_options+=(resumption)
[ "$TESTCASE" = http3 ] && client_options+=(h3)
# The chacha20 case requires the client to offer TLS_CHACHA20_POLY1305_SHA256 alone.
[ "$TESTCASE" = chacha20 ] && client_options+=(chacha20)
[ -n "${QLOGDIR:-}" ] && client_options+=("qlogdir=$QLOGDIR")

client() {
  quic-udp client "$address" "$port" /tmp/identity "$host" "$(date +%s)" /downloads "${client_options[@]}" "$@"
}

if [ "$TESTCASE" = multiconnect ]; then
  # One connection per file, one after the other.
  for path in "${paths[@]}"; do client "$path"; done
else
  client "${paths[@]}"
fi
