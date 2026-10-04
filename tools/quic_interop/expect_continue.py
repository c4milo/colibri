"""An aioquic h3 client that sends a request's head with `expect: 100-continue` and no content, to
check that colibri's server writes the 100 (Continue) it owes (RFC 9110 §10.1.1, design §8 step
17i). tools/quic_aioquic.sh runs it.

    expect_continue.py <host> <port> <identity-prefix> <server-name>

The first response head the client reads must carry status 100, and must arrive long before a
client that waits for it would give up. It prints the status and the time, and exits 0 when both
hold and 1 otherwise. The check ends there: aioquic 1.3.0 validates a second HEADERS frame of a
response as a trailer section, so it reads no final response after an interim one.
"""
import asyncio
import os
import sys
import time

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated

from hq_peer import pem_files

# RFC 9110 §15.2.1: 100 (Continue).
EXPECTED_STATUS = b"100"
# How soon the 100 must arrive for it to be the server's answer to the head alone.
CONTINUE_WITHIN_SECONDS = 5


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.head = asyncio.get_running_loop().create_future()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            if not self.head.done():
                self.head.set_exception(RuntimeError(f"connection closed: {event.reason_phrase}"))
            return
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, HeadersReceived) and not self.head.done():
                self.head.set_result(dict(h3_event.headers)[b":status"])


async def run(host, port, prefix, server_name, scratch):
    _, root, _ = pem_files(prefix, scratch)
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name=server_name)
    configuration.load_verify_locations(root)
    async with connect(host, port, configuration=configuration, create_protocol=Client) as client:
        stream_id = client._quic.get_next_available_stream_id()
        headers = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", server_name.encode()),
            (b":path", b"/"),
            (b"expect", b"100-continue"),
            (b"content-length", b"5"),
        ]
        start = time.monotonic()
        # RFC 9110 §10.1.1: the client sends the head and waits for the 100 before its content.
        client.h3.send_headers(stream_id, headers, end_stream=False)
        client.transmit()
        try:
            status = await asyncio.wait_for(client.head, CONTINUE_WITHIN_SECONDS)
        except (asyncio.TimeoutError, RuntimeError):
            status = None
        seconds = time.monotonic() - start
        client.close()
        return status, seconds


def main():
    host, port, prefix, server_name = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    status, seconds = asyncio.run(run(host, port, prefix, server_name, os.environ.get("HQ_PEER_SCRATCH", "/tmp")))
    shown = "none" if status is None else status.decode()
    print(f"expect_continue: first response head carried {shown} after {seconds:.3f}s, with no content sent", flush=True)
    sys.exit(0 if status == EXPECTED_STATUS else 1)


if __name__ == "__main__":
    main()
