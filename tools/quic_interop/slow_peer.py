"""Slow h3 peers on aioquic, for decision 110's deadlines on colibri's h3 server.
tools/h3_deadlines.sh runs it; design §8 step 20c records what it proves.

    slow_peer.py <host> <port> <identity-prefix> <server-name> [peer...]

Four peers run at once against the server's default limits, or only the ones named. The server
must end each within a second after its deadline's instant, and not before it:

  silent     completes the handshake, sends a PING every second and no request. It gets a GOAWAY
             at the first-request deadline, 10 s after its first datagram, and then a close with
             H3_NO_ERROR.
  half_head  fetches a file, then sends half of a request's HEADERS frame. That stream gets a 408
             at the head deadline, 10 s after it opened, and the connection serves a later fetch.
  slow_body  sends a request's head and three octets of its content. It gets a 408 when the
             body's first window ends, 20 s after the head.
  deaf       asks for a large file and acknowledges nothing of the response. Its connection
             closes with H3_EXCESSIVE_LOAD when the first window ends, 20 s after the request.

The identity files are tools/h2_interop/tls_identity.go's, which hq_peer.py converts to the PEM
aioquic loads.
"""
import asyncio
import os
import sys
import time

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

from hq_peer import keylog, pem_files

# Decision 110's defaults, in seconds, and how long after its instant a deadline may act.
FIRST_REQUEST_S = 10
HEAD_S = 10
BODY_FIRST_WINDOW_S = 20
SEND_FIRST_WINDOW_S = 20
SLACK_S = 1
# The longest the four peers run together.
RUN_S = 40
# RFC 9114 §8.1.
H3_NO_ERROR = 0x100
H3_EXCESSIVE_LOAD = 0x107
# RFC 9114 §6.2.1 and §7.2.6.
CONTROL_STREAM = 0x00
GOAWAY_FRAME = 0x07
# RFC 9114 §7.2.2 and RFC 9204 §4.5: a HEADERS frame for "GET https://localhost/", its field
# lines taken from QPACK's static table but the authority's value.
GET_HEADERS = bytes([0x01, 0x10, 0x00, 0x00, 0xD1, 0xD7, 0xC1, 0x50, 0x09]) + b"localhost"


def read_varint(data, at):
    """RFC 9000 §16: the integer at `at`, and where the next one starts, or None when short."""
    if at >= len(data):
        return None
    length = 1 << (data[at] >> 6)
    if at + length > len(data):
        return None
    value = data[at] & 0x3F
    for octet in data[at + 1 : at + length]:
        value = (value << 8) | octet
    return value, at + length


def carries_goaway(data):
    """Whether a unidirectional stream's octets are a control stream that holds a GOAWAY frame."""
    kind = read_varint(data, 0)
    if kind is None or kind[0] != CONTROL_STREAM:
        return False
    at = kind[1]
    while True:
        frame = read_varint(data, at)
        length = read_varint(data, frame[1]) if frame else None
        if length is None:
            return False
        if frame[0] == GOAWAY_FRAME:
            return True
        at = length[1] + length[0]


def is_no_error(code):
    """H3_NO_ERROR, or a reserved code an endpoint may send in its place (RFC 9114 §8.1)."""
    return code == H3_NO_ERROR or (code >= 0x21 and (code - 0x21) % 0x1F == 0)


class Outlet:
    """A peer's socket, which drops every datagram a muted peer writes. aioquic goes on running
    its timers, so the peer still ends when the server closes its connection."""

    def __init__(self, transport, peer):
        self.transport = transport
        self.peer = peer

    def sendto(self, data, addr=None):
        if not self.peer.muted:
            self.transport.sendto(data, addr)

    def __getattr__(self, name):
        return getattr(self.transport, name)


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        # A muted peer's datagrams are dropped: the server reads no acknowledgment and no credit.
        self.muted = False
        self.goaway_at = None
        self.unidirectional = {}
        self.statuses = {}
        self.bodies = {}
        self.answered = {}
        self.closed = asyncio.get_running_loop().create_future()

    def connection_made(self, transport):
        super().connection_made(Outlet(transport, self))

    def datagram_received(self, data, addr):
        super().datagram_received(data, addr)
        # aioquic reports ConnectionTerminated only once its draining period ends, three PTOs
        # after the server's CONNECTION_CLOSE arrived, and a muted peer's PTO has grown. The
        # pinned aioquic keeps the close it read in `_close_event`, which is there at once.
        close = self._quic._close_event
        if close is not None and not self.closed.done():
            self.closed.set_result((close.error_code, time.monotonic()))

    def quic_event_received(self, event):
        now = time.monotonic()
        if isinstance(event, ConnectionTerminated):
            return
        if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 3:
            held = self.unidirectional.get(event.stream_id, b"") + event.data
            self.unidirectional[event.stream_id] = held
            if self.goaway_at is None and carries_goaway(held):
                self.goaway_at = now
        for h3_event in self.h3.handle_event(event):
            stream_id = h3_event.stream_id
            if isinstance(h3_event, HeadersReceived):
                self.statuses[stream_id] = dict(h3_event.headers)[b":status"]
                waiter = self.answered.get(stream_id)
                if waiter is not None and not waiter.done():
                    waiter.set_result((self.statuses[stream_id], now))
            elif isinstance(h3_event, DataReceived):
                self.bodies[stream_id] = self.bodies.get(stream_id, 0) + len(h3_event.data)

    def expect_answer(self, stream_id):
        """A future for the status of the response on `stream_id`, and when its head arrived."""
        self.answered[stream_id] = asyncio.get_running_loop().create_future()
        return self.answered[stream_id]

    def get(self, server_name, path):
        """Sends a whole GET, and returns the future of its response's head."""
        stream_id = self._quic.get_next_available_stream_id()
        waiter = self.expect_answer(stream_id)
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", server_name.encode()),
            (b":path", path.encode()),
        ]
        self.h3.send_headers(stream_id, headers, end_stream=True)
        self.transmit()
        return waiter


def within(name, what, elapsed, limit):
    """Fails unless `elapsed` is at or after `limit` seconds, and within the slack after it."""
    if not limit <= elapsed <= limit + SLACK_S:
        raise RuntimeError(f"{name}: {what} after {elapsed:.2f} s, not within {SLACK_S} s after {limit} s")
    return f"{name}: {what} after {elapsed:.2f} s"


async def silent(open_peer):
    started = time.monotonic()
    async with open_peer() as peer:
        # A PING keeps QUIC's idle timeout away, and is no request (RFC 9000 §10.1.2).
        for count in range(FIRST_REQUEST_S + 2 * SLACK_S):
            if peer.closed.done():
                break
            peer._quic.send_ping(count)
            peer.transmit()
            await asyncio.sleep(1)
        code, closed_at = await asyncio.wait_for(peer.closed, 2 * SLACK_S)
        if peer.goaway_at is None:
            raise RuntimeError("silent: the server closed with no GOAWAY before it")
        if not is_no_error(code):
            raise RuntimeError(f"silent: closed with {code:#x}, not H3_NO_ERROR")
        if closed_at < peer.goaway_at:
            raise RuntimeError("silent: the close came before the GOAWAY")
        return within("silent", "a GOAWAY, then H3_NO_ERROR,", peer.goaway_at - started, FIRST_REQUEST_S)


async def half_head(open_peer, server_name):
    async with open_peer() as peer:
        status, _ = await asyncio.wait_for(peer.get(server_name, "/small"), 5)
        if status != b"200":
            raise RuntimeError(f"half_head: the first fetch got {status!r}")
        stream_id = peer._quic.get_next_available_stream_id()
        waiter = peer.expect_answer(stream_id)
        peer._quic.send_stream_data(stream_id, GET_HEADERS[: len(GET_HEADERS) // 2], end_stream=False)
        sent = time.monotonic()
        peer.transmit()
        status, at = await asyncio.wait_for(waiter, HEAD_S + 2 * SLACK_S)
        if status != b"408":
            raise RuntimeError(f"half_head: the late head got {status!r}, not 408")
        report = within("half_head", "408", at - sent, HEAD_S)
        status, _ = await asyncio.wait_for(peer.get(server_name, "/small"), 5)
        if status != b"200" or peer.closed.done():
            raise RuntimeError(f"half_head: the connection did not go on: {status!r}")
        return report


async def slow_body(open_peer, server_name):
    async with open_peer() as peer:
        stream_id = peer._quic.get_next_available_stream_id()
        waiter = peer.expect_answer(stream_id)
        headers = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", server_name.encode()),
            (b":path", b"/"),
        ]
        peer.h3.send_headers(stream_id, headers, end_stream=False)
        peer.h3.send_data(stream_id, b"abc", end_stream=False)
        sent = time.monotonic()
        peer.transmit()
        status, at = await asyncio.wait_for(waiter, BODY_FIRST_WINDOW_S + 2 * SLACK_S)
        if status != b"408":
            raise RuntimeError(f"slow_body: the slow body got {status!r}, not 408")
        return within("slow_body", "408", at - sent, BODY_FIRST_WINDOW_S)


async def deaf(open_peer, server_name):
    async with open_peer() as peer:
        peer.get(server_name, "/large")
        sent = time.monotonic()
        peer.muted = True
        code, at = await asyncio.wait_for(peer.closed, SEND_FIRST_WINDOW_S + 2 * SLACK_S)
        if code != H3_EXCESSIVE_LOAD:
            raise RuntimeError(f"deaf: closed with {code:#x}, not H3_EXCESSIVE_LOAD")
        return within("deaf", "H3_EXCESSIVE_LOAD", at - sent, SEND_FIRST_WINDOW_S)


async def run(host, port, prefix, server_name, scratch, names):
    _, root, _ = pem_files(prefix, scratch)

    def open_peer():
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=H3_ALPN, server_name=server_name, secrets_log_file=keylog()
        )
        configuration.load_verify_locations(root)
        return connect(host, port, configuration=configuration, create_protocol=Peer)

    async def reported(peer):
        # Every peer runs to its end, so one that fails does not hide what the others found.
        try:
            print(f"slow_peer: {await peer}", flush=True)
            return True
        except (RuntimeError, asyncio.TimeoutError) as failure:
            print(f"slow_peer: FAILED: {failure!r}", flush=True)
            return False

    every = {
        "silent": lambda: silent(open_peer),
        "half_head": lambda: half_head(open_peer, server_name),
        "slow_body": lambda: slow_body(open_peer, server_name),
        "deaf": lambda: deaf(open_peer, server_name),
    }
    peers = [every[name]() for name in (names or every)]
    # A peer the server never ends would wait on its own timeouts, and this bounds them all.
    passed = await asyncio.wait_for(asyncio.gather(*(reported(peer) for peer in peers)), RUN_S)
    if not all(passed):
        sys.exit(1)


def main():
    host, port, prefix, server_name = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    scratch = os.environ.get("HQ_PEER_SCRATCH", "/tmp")
    asyncio.run(run(host, port, prefix, server_name, scratch, sys.argv[5:]))


if __name__ == "__main__":
    main()
