"""An h3 server and client on aioquic, to run against colibri's quic-udp endpoint.
tools/quic_aioquic.sh runs it; design §8 step 12 records what it proves.

    h3_peer.py server <host> <port> <identity-prefix> <www>
    h3_peer.py client <host> <port> <identity-prefix> <server-name> <downloads> <path>...

The server answers a GET for a file under <www> with 200 and the file, and any other with 404.
The client fetches each path with a GET and writes a 200's content to <downloads>. aioquic's h3
uses ls-qpack, through pylsqpack, with a dynamic table, so colibri's QPACK meets another
implementation's inside h3 as well as in tools/qif_interop.sh. The identity files are
tools/h2_interop/tls_identity.go's, which hq_peer.py converts to the PEM aioquic loads.
"""
import asyncio
import os
import sys

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated

from hq_peer import keylog, pem_files


class Server(QuicConnectionProtocol):
    www = "."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.paths = {}

    def quic_event_received(self, event):
        for h3_event in self.h3.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                self.paths[h3_event.stream_id] = dict(h3_event.headers).get(b":path", b"").decode()
            if getattr(h3_event, "stream_ended", False):
                self.answer(h3_event.stream_id)
        self.transmit()

    def answer(self, stream_id):
        path = self.paths.pop(stream_id, "")
        target = os.path.join(self.www, path.lstrip("/"))
        if not path.startswith("/") or ".." in path or not os.path.isfile(target):
            print(f"h3_peer: 404 for {path!r}", flush=True)
            self.h3.send_headers(stream_id, [(b":status", b"404"), (b"content-length", b"0")], end_stream=True)
            return
        data = open(target, "rb").read()
        headers = [(b":status", b"200"), (b"content-length", str(len(data)).encode())]
        self.h3.send_headers(stream_id, headers)
        self.h3.send_data(stream_id, data, end_stream=True)
        print(f"h3_peer: served {path} ({len(data)} octets)", flush=True)


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.statuses = {}
        self.bodies = {}
        self.waiters = {}

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            for waiter in self.waiters.values():
                waiter.set_exception(RuntimeError(f"connection closed: {event.reason_phrase}"))
            self.waiters.clear()
            return
        for h3_event in self.h3.handle_event(event):
            stream_id = h3_event.stream_id
            if isinstance(h3_event, HeadersReceived):
                self.statuses[stream_id] = dict(h3_event.headers)[b":status"]
            elif isinstance(h3_event, DataReceived):
                self.bodies[stream_id] = self.bodies.get(stream_id, b"") + h3_event.data
            if getattr(h3_event, "stream_ended", False):
                status = self.statuses.get(stream_id)
                waiter = self.waiters.pop(stream_id)
                if status != b"200":
                    waiter.set_exception(RuntimeError(f"status {status!r}"))
                else:
                    waiter.set_result(self.bodies.get(stream_id, b""))

    def fetch(self, server_name, path):
        stream_id = self._quic.get_next_available_stream_id()
        waiter = asyncio.get_running_loop().create_future()
        self.waiters[stream_id] = waiter
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", server_name.encode()),
            (b":path", path.encode()),
        ]
        self.h3.send_headers(stream_id, headers, end_stream=True)
        self.transmit()
        return waiter


async def run_server(host, port, prefix, www, scratch):
    chain, _, key = pem_files(prefix, scratch)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN, secrets_log_file=keylog())
    configuration.load_cert_chain(chain, key)
    Server.www = www
    await serve(host, port, configuration=configuration, create_protocol=Server)
    print(f"h3_peer: listening on port {port}", flush=True)
    await asyncio.Future()


async def run_client(host, port, prefix, server_name, downloads, paths, scratch):
    _, root, _ = pem_files(prefix, scratch)
    configuration = QuicConfiguration(
        is_client=True, alpn_protocols=H3_ALPN, server_name=server_name, secrets_log_file=keylog()
    )
    configuration.load_verify_locations(root)
    async with connect(host, port, configuration=configuration, create_protocol=Client) as client:
        fetches = (client.fetch(server_name, path) for path in paths)
        answers = await asyncio.wait_for(asyncio.gather(*fetches), 30)
        for path, answer in zip(paths, answers):
            with open(os.path.join(downloads, path.lstrip("/")), "wb") as out:
                out.write(answer)
        print(f"h3_peer: fetched {len(paths)} files, {sum(map(len, answers))} octets", flush=True)
        client.close()


def main():
    role, host, port, prefix = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    scratch = os.environ.get("HQ_PEER_SCRATCH", "/tmp")
    if role == "server":
        asyncio.run(run_server(host, port, prefix, sys.argv[5], scratch))
    else:
        asyncio.run(run_client(host, port, prefix, sys.argv[5], sys.argv[6], sys.argv[7:], scratch))


if __name__ == "__main__":
    main()
