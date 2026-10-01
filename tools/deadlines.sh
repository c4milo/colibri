#!/usr/bin/env bash
#
# Decision 110's deadlines on design §9's test-only server, over real sockets and on its loop's
# clock (design §8 step 20b). Four peers the server must cut at the default limits:
#   1. an h11 peer that sends half a request head gets a 408 at the first-request deadline, 10 s;
#   2. an h11 peer that sends nothing is closed then, with nothing sent, though another connection
#      opens halfway there: the loop must wait for the deadline, not a tick of its own length;
#   3. an h11 peer that sends a head and three octets of its body gets a 408 when the body's first
#      window ends, the grace period and a window after the head, 20 s;
#   4. an h2 peer that sends its preface alone gets a GOAWAY at the first-request deadline.
# Each must end within a second after its instant and not before it. It needs python3, and it is
# not part of `zig build test`.
#
#   tools/deadlines.sh [port]
#
# The h11 server listens on the port, and the h2 server on the one after it.
set -euo pipefail

readonly port="${1:-18474}"

pids=()
cleanup() {
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

echo "deadlines.sh: building the server"
zig build install
readonly server="zig-out/bin/http-server"
"$server" --port "$port" --h11 >/dev/null 2>&1 &
pids+=("$!")
"$server" --port "$((port + 1))" >/dev/null 2>&1 &
pids+=("$!")
sleep 1

python3 - "$port" <<'PYTHON'
import socket
import sys
import time

h11_port = int(sys.argv[1])
h2_port = h11_port + 1
# The client's connection preface and an empty SETTINGS frame (RFC 9113 §3.4).
preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
goaway_type = 0x07


def probe(port, octets, nudge_after_s=None):
    """Sends `octets`, reads until the server closes, and returns when it closed and what it sent.
    With `nudge_after_s`, another connection opens and sends an octet that long after the start."""
    # The stopwatch starts before the connection does. The server is idle when each peer connects,
    # so it times the connection from when its loop wakes for it, after the handshake. The time
    # measured here can only be longer than the server's, and a close before the deadline still
    # fails. Started after create_connection returned, it read 9.99 s once, at a load average of 32.
    started = time.monotonic()
    connection = socket.create_connection(("127.0.0.1", port))
    if octets:
        connection.sendall(octets)
    nudge = None
    if nudge_after_s is not None:
        time.sleep(nudge_after_s)
        nudge = socket.create_connection(("127.0.0.1", port))
        nudge.sendall(b"G")
    connection.settimeout(60)
    received = b""
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        received += chunk
    closed_at = time.monotonic() - started
    connection.close()
    if nudge is not None:
        nudge.close()
    return closed_at, received


def has_goaway(received):
    """Whether the frames in `received` include a GOAWAY (RFC 9113 §6.8)."""
    offset = 0
    while offset + 9 <= len(received):
        length = int.from_bytes(received[offset:offset + 3], "big")
        if received[offset + 3] == goaway_type:
            return True
        offset += 9 + length
    return False


# Each check: what it is, where, what the peer sends, when another connection opens, when the
# server must close, and what it must have sent.
checks = [
    ("an h11 peer that sends half a head", h11_port, b"GET / HT", None, 10, lambda r: r.startswith(b"HTTP/1.1 408 ")),
    ("an h11 peer that sends nothing", h11_port, b"", 5, 10, lambda r: r == b""),
    ("an h11 peer whose body is too slow", h11_port,
     b"POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 100000\r\n\r\nabc", None, 20, lambda r: r.startswith(b"HTTP/1.1 408 ")),
    ("an h2 peer that sends its preface alone", h2_port, preface, None, 10, has_goaway),
]
failures = 0
for label, port, octets, nudge_after_s, expected, answered in checks:
    closed_at, received = probe(port, octets, nudge_after_s)
    ok = expected <= closed_at < expected + 1 and answered(received)
    failures += 0 if ok else 1
    verdict = "ok" if ok else "FAILED"
    print(f"deadlines.sh: {label}: closed after {closed_at:.2f} s, {len(received)} octets, {verdict}")
sys.exit(1 if failures else 0)
PYTHON
echo "deadlines.sh: every peer was cut at its deadline"
