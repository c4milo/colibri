#!/usr/bin/env bash
#
# A colibri client fetches files from a colibri server over real UDP on 127.0.0.1, over
# hq-interop and over h3, both over chapulin's QUIC mode and Rotor's loop. Part of design §8 steps
# 9e and 12. Each file must arrive octet for octet, and a client with `resumption` must resume its
# first connection's session on its second (RFC 9846 §2.2). The hq-interop and h3 runs write each
# connection's qlog, and every file must pass tools/qlog_check.py (design §8 step 18c). The files
# come over h3 from the server's `h3` mode too, which serves them through the `server` module
# (design §8 step 17b).
#
# It needs a Go toolchain, for the identity, and python3. chapulin comes from the package build.zig.zon pins
# (design §8 step 16a). It is not part of `zig build test`.
#
#   tools/quic_udp.sh
#
# Each server binds port 0, and the run reads the port the kernel chose from its log, so two runs
# on one machine do not collide (https://github.com/c4milo/colibri/issues/94).
# SSLKEYLOGFILE, when set, receives both endpoints' traffic secrets.
set -euo pipefail

readonly hostname="localhost"
# The port the server now running listens on.
port=""

scratch="$(mktemp -d)"
server_pid=""
cleanup() {
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

echo "quic_udp: building the endpoint"
zig build
go run tools/h2_interop/tls_identity.go "$scratch/identity"

# Three files: one smaller than a packet, one of many packets, and one past the receive pool,
# which only arrives if the client's reads give the server credit (RFC 9000 §4.1).
mkdir -p "$scratch/www" "$scratch/downloads" "$scratch/qlog"
readonly qlogdir="qlogdir=$scratch/qlog/"
head -c 1000 /dev/urandom >"$scratch/www/small"
head -c 100000 /dev/urandom >"$scratch/www/medium"
head -c 3000000 /dev/urandom >"$scratch/www/large"

# Starts a server with the options given, and waits for it to listen. With `once` it exits when
# its first connection ends.
start_server() {
  ./zig-out/bin/quic-udp server 127.0.0.1 0 "$scratch/identity" "$scratch/www" "$@" \
    >"$scratch/server.log" 2>&1 &
  server_pid=$!
  port="$(tools/listening_port.sh "$scratch/server.log")"
}

client() {
  ./zig-out/bin/quic-udp client 127.0.0.1 "$port" "$scratch/identity" "$hostname" "$(date +%s)" \
    "$scratch/downloads" "$@"
}

# Waits for a server started with `once` to exit, which the client's CONNECTION_CLOSE brings about
# at once (RFC 9000 §10.2.2). A server still running after a few seconds never received it, and
# would sit out its idle timeout. The argument names the server in what the check prints.
await_close() {
  for _ in $(seq 1 50); do
    kill -0 "$server_pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$server_pid" 2>/dev/null; then
    echo "quic_udp: $1 never saw the client's close" >&2
    exit 1
  fi
  wait "$server_pid" || {
    echo "quic_udp: $1 failed:" >&2
    cat "$scratch/server.log" >&2
    exit 1
  }
  server_pid=""
}

start_server once "$qlogdir"
if ! client "$qlogdir" /small /medium /large >"$scratch/client.log" 2>&1; then
  echo "quic_udp: the client failed; it and the server said:" >&2
  cat "$scratch/client.log" "$scratch/server.log" >&2
  exit 1
fi
cat "$scratch/client.log"
await_close "the server"
cat "$scratch/server.log"
# The next server writes its own log, and this one's is read with the qlog files below.
cp "$scratch/server.log" "$scratch/server_hq.log"

for file in small medium large; do
  if ! cmp -s "$scratch/www/$file" "$scratch/downloads/$file"; then
    echo "quic_udp: $file arrived different from what the server holds" >&2
    exit 1
  fi
done
# A path the server does not hold is answered by resetting its stream, which the client reports.
start_server once
if client /small /missing >"$scratch/missing.log" 2>&1; then
  echo "quic_udp: the client fetched a file the server does not hold" >&2
  exit 1
fi
if ! grep -q StreamReset "$scratch/missing.log"; then
  echo "quic_udp: a missing file did not reset its stream:" >&2
  cat "$scratch/missing.log" >&2
  exit 1
fi
kill "$server_pid" 2>/dev/null || true
server_pid=""
# The same three files over h3 (design §8 step 12): the server serves h3 to a client that asks
# for it by ALPN, and a path it does not hold is answered 404, which the client reports. This
# client offers TLS_CHACHA20_POLY1305_SHA256 alone, as the runner's chacha20 case asks.
rm -f "$scratch/downloads/small" "$scratch/downloads/medium" "$scratch/downloads/large"
start_server once "$qlogdir"
if ! client h3 chacha20 "$qlogdir" /small /medium /large >"$scratch/h3.log" 2>&1; then
  echo "quic_udp: the h3 client failed:" >&2
  cat "$scratch/h3.log" "$scratch/server.log" >&2
  exit 1
fi
cat "$scratch/h3.log"
grep -q "alpn=h3" "$scratch/h3.log" || {
  echo "quic_udp: the h3 client did not negotiate h3" >&2
  exit 1
}
# RFC 9846 §4.2.3: the server selects from what the client offered, whatever its own order.
grep -q "suite=0x1303" "$scratch/h3.log" || {
  echo "quic_udp: the client offering ChaCha20 alone ran another suite" >&2
  exit 1
}
# RFC 9368 §2.5: a client starts in version 1 and lists version 2, and colibri's server switches
# it to version 2 (decision 111).
grep -q "version=0x6b3343cf" "$scratch/h3.log" || {
  echo "quic_udp: the server did not switch the client to version 2" >&2
  exit 1
}
for file in small medium large; do
  if ! cmp -s "$scratch/www/$file" "$scratch/downloads/$file"; then
    echo "quic_udp: $file arrived over h3 different from what the server holds" >&2
    exit 1
  fi
done
# The client's close, with H3_NO_ERROR (RFC 9114 §5.2), ends the server's connection too.
await_close "the h3 server"
# Two connections, each logged by its client and its server (main schema §12.1), with no event
# dropped for want of room.
python3 tools/qlog_check.py "$scratch/qlog" complete
if grep -h "qlog dropped" "$scratch/client.log" "$scratch/server_hq.log" "$scratch/h3.log" "$scratch/server.log"; then
  echo "quic_udp: an endpoint's qlog dropped events" >&2
  exit 1
fi
# Each file converts into the qlog 0.3 form qvis reads (decision 102 as amended).
for file in "$scratch"/qlog/*.sqlog; do
  python3 tools/qlog_to_qvis.py "$file" "$scratch/qvis.sqlog" >/dev/null
done
[ "$(find "$scratch/qlog" -name '*.sqlog' | wc -l | tr -d ' ')" = 4 ] || {
  echo "quic_udp: two connections left no four qlog files:" >&2
  ls "$scratch/qlog" >&2
  exit 1
}
start_server once
if client h3 /small /missing >"$scratch/h3_missing.log" 2>&1; then
  echo "quic_udp: the h3 client fetched a file the server does not hold" >&2
  exit 1
fi
if ! grep -q ResponseRefused "$scratch/h3_missing.log"; then
  echo "quic_udp: a missing file was not refused over h3:" >&2
  cat "$scratch/h3_missing.log" >&2
  exit 1
fi
kill "$server_pid" 2>/dev/null || true
server_pid=""
# The same three files from the server's `h3` mode, which serves h3 through the `server` module
# (design §8 step 17b), and logs its connection through the endpoint's log provider (decision 102
# as amended). The client's close ends its connection, which is no connection error, and a path it
# does not hold is answered 404.
rm -f "$scratch/downloads/small" "$scratch/downloads/medium" "$scratch/downloads/large"
mkdir -p "$scratch/qlog_h3"
readonly qlogdir_h3="qlogdir=$scratch/qlog_h3/"
start_server once h3 "$qlogdir_h3"
if ! client h3 "$qlogdir_h3" /small /medium /large >"$scratch/h3_mode.log" 2>&1; then
  echo "quic_udp: the h3 client failed against the h3 mode:" >&2
  cat "$scratch/h3_mode.log" "$scratch/server.log" >&2
  exit 1
fi
cat "$scratch/h3_mode.log"
# Decision 111: the `server` module switches a client that lists version 2 to it, as the other
# server does.
grep -q "version=0x6b3343cf" "$scratch/h3_mode.log" || {
  echo "quic_udp: the h3 mode did not switch the client to version 2" >&2
  exit 1
}
for file in small medium large; do
  if ! cmp -s "$scratch/www/$file" "$scratch/downloads/$file"; then
    echo "quic_udp: $file arrived from the h3 mode different from what the server holds" >&2
    exit 1
  fi
done
await_close "the h3 mode"
cat "$scratch/server.log"
grep -q "served 3 files, 0 connection errors" "$scratch/server.log" || {
  echo "quic_udp: the h3 mode did not report the three files it served" >&2
  exit 1
}
# The connection's two logs, the client's and the one the `server` module wrote, each whole.
python3 tools/qlog_check.py "$scratch/qlog_h3" complete
if grep -h "qlog dropped" "$scratch/h3_mode.log" "$scratch/server.log"; then
  echo "quic_udp: an endpoint's qlog dropped events in the h3 mode" >&2
  exit 1
fi
for file in "$scratch"/qlog_h3/*.sqlog; do
  python3 tools/qlog_to_qvis.py "$file" "$scratch/qvis.sqlog" >/dev/null
done
[ "$(find "$scratch/qlog_h3" -name '*.sqlog' | wc -l | tr -d ' ')" = 2 ] || {
  echo "quic_udp: the h3 mode's connection left no two qlog files:" >&2
  ls "$scratch/qlog_h3" >&2
  exit 1
}
# A client that starts in version 2 (RFC 9369) is served in it by both servers, each of which runs
# the version of the client's first flight (RFC 9368 §2).
for mode in hq h3; do
  rm -f "$scratch/downloads/small"
  if [ "$mode" = h3 ]; then start_server once h3; else start_server once; fi
  options=(v2)
  [ "$mode" = h3 ] && options+=(h3)
  if ! client "${options[@]}" /small >"$scratch/v2_$mode.log" 2>&1; then
    echo "quic_udp: the $mode server did not serve a client in version 2:" >&2
    cat "$scratch/v2_$mode.log" "$scratch/server.log" >&2
    exit 1
  fi
  grep -q "version=0x6b3343cf" "$scratch/v2_$mode.log" || {
    echo "quic_udp: the client that started in version 2 ran another version against $mode" >&2
    exit 1
  }
  cmp -s "$scratch/www/small" "$scratch/downloads/small" || {
    echo "quic_udp: small arrived in version 2 different from what the $mode server holds" >&2
    exit 1
  }
  await_close "the $mode server in version 2"
done
# A server with `no-switch` keeps a client that lists version 2 in version 1, the version of its
# first flight (decision 111), in both modes.
for mode in hq h3; do
  rm -f "$scratch/downloads/small"
  if [ "$mode" = h3 ]; then
    start_server once h3 no-switch
    options=(h3 /small)
  else
    start_server once no-switch
    options=(/small)
  fi
  if ! client "${options[@]}" >"$scratch/no_switch_$mode.log" 2>&1; then
    echo "quic_udp: the $mode server with no-switch did not serve the client:" >&2
    cat "$scratch/no_switch_$mode.log" "$scratch/server.log" >&2
    exit 1
  fi
  grep -q "version=0x00000001" "$scratch/no_switch_$mode.log" || {
    echo "quic_udp: the $mode server with no-switch switched the client" >&2
    exit 1
  }
  cmp -s "$scratch/www/small" "$scratch/downloads/small" || {
    echo "quic_udp: small arrived in version 1 different from what the $mode server holds" >&2
    exit 1
  }
  await_close "the $mode server with no-switch"
done
start_server once h3
if client h3 /small /missing >"$scratch/h3_mode_missing.log" 2>&1; then
  echo "quic_udp: the h3 client fetched a file the h3 mode does not hold" >&2
  exit 1
fi
if ! grep -q ResponseRefused "$scratch/h3_mode_missing.log"; then
  echo "quic_udp: a missing file was not refused by the h3 mode:" >&2
  cat "$scratch/h3_mode_missing.log" >&2
  exit 1
fi
kill "$server_pid" 2>/dev/null || true
server_pid=""
# The `h3` mode offers h3 alone, so it refuses a client that offers hq-interop (RFC 9001 §8.1),
# and without `errors` the refused connection ends its run with a failure.
start_server h3
if client /small >"$scratch/h3_mode_hq.log" 2>&1; then
  echo "quic_udp: the h3 mode served an hq-interop client" >&2
  exit 1
fi
for _ in $(seq 1 50); do
  kill -0 "$server_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$server_pid" 2>/dev/null || wait "$server_pid"; then
  echo "quic_udp: the h3 mode did not fail on the connection it refused:" >&2
  cat "$scratch/server.log" >&2
  exit 1
fi
server_pid=""
# A server given the time issues a ticket, and the client's second connection presents it.
# chapulin fails a handshake whose ticket the server declines, so a second connection that
# fetches its file resumed.
rm -f "$scratch/downloads/small" "$scratch/downloads/medium"
start_server "seconds=$(date +%s)"
if ! client resumption /small /medium >"$scratch/resumption.log" 2>&1; then
  echo "quic_udp: the resuming client failed:" >&2
  cat "$scratch/resumption.log" "$scratch/server.log" >&2
  exit 1
fi
kill "$server_pid" 2>/dev/null || true
server_pid=""
cat "$scratch/resumption.log"
grep -q "resumed the first" "$scratch/resumption.log" || {
  echo "quic_udp: the client did not resume" >&2
  exit 1
}
# The first connection fetches one file and the second the other.
grep -q "fetched 2 of 2 files, 101000 octets" "$scratch/resumption.log" || {
  echo "quic_udp: the two connections did not split the files between them" >&2
  exit 1
}
for file in small medium; do
  if ! cmp -s "$scratch/www/$file" "$scratch/downloads/$file"; then
    echo "quic_udp: $file arrived different from what the server holds on resumption" >&2
    exit 1
  fi
done
echo "quic_udp: ok"
