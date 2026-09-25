"""An aioquic client that offers only an ALPN colibri's server does not serve, to check the close a
failed handshake owes (RFC 9001 §4.8, https://github.com/c4milo/colibri/issues/59).
tools/quic_aioquic.sh runs it.

    wrong_alpn.py <host> <port> <identity-prefix> <server-name>

The server's TLS stack refuses the handshake with no_application_protocol (RFC 7301 §3.2), so its
CONNECTION_CLOSE must carry CRYPTO_ERROR 0x0100 + 120 and arrive long before the client's idle
timeout. It prints the code and exits 0 when both hold, and 1 otherwise.
"""
import asyncio
import os
import sys
import time

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated

from hq_peer import pem_files

# RFC 9001 §4.8: CRYPTO_ERROR is 0x0100 plus the alert, and no_application_protocol is 120.
EXPECTED_CODE = 0x0100 + 120
# The client's idle timeout, and how soon the close must arrive for it to be the server's close
# and not the client giving up.
IDLE_TIMEOUT_SECONDS = 20
CLOSE_WITHIN_SECONDS = 5


class Watch(QuicConnectionProtocol):
    code = None

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated) and Watch.code is None:
            Watch.code = event.error_code
        super().quic_event_received(event)


async def run(host, port, prefix, server_name, scratch):
    _, root, _ = pem_files(prefix, scratch)
    configuration = QuicConfiguration(
        is_client=True, alpn_protocols=["colibri-serves-no-such-protocol"], server_name=server_name,
        idle_timeout=IDLE_TIMEOUT_SECONDS,
    )
    configuration.load_verify_locations(root)
    start = time.monotonic()
    try:
        async with connect(host, port, configuration=configuration, create_protocol=Watch) as client:
            await client.ping()
    except ConnectionError:
        pass
    return Watch.code, time.monotonic() - start


def main():
    host, port, prefix, server_name = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    code, seconds = asyncio.run(run(host, port, prefix, server_name, os.environ.get("HQ_PEER_SCRATCH", "/tmp")))
    shown = "none" if code is None else f"0x{code:x}"
    print(f"wrong_alpn: close carried {shown} after {seconds:.2f}s", flush=True)
    sys.exit(0 if code == EXPECTED_CODE and seconds < CLOSE_WITHIN_SECONDS else 1)


if __name__ == "__main__":
    main()
