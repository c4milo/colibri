"""An hq-interop server and client on aioquic, to run against colibri's quic-udp endpoint.
tools/quic_aioquic.sh runs it; design §8 step 9e records what it proves.

    hq_peer.py server <host> <port> <identity-prefix> <www>
    hq_peer.py client <host> <port> <identity-prefix> <server-name> <downloads> <path>...

The identity prefix names the files tools/h2_interop/tls_identity.go wrote: raw DER certificates
and a raw P-256 scalar, which this converts to the PEM aioquic loads. SSLKEYLOGFILE, when set,
receives the traffic secrets.
"""
import asyncio
import os
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ALPN = "hq-interop"


def pem_files(prefix, directory):
    """Writes the leaf and root as one PEM chain and the key as PEM, and returns their paths."""
    leaf = open(prefix + ".leaf.der", "rb").read()
    root = open(prefix + ".ca.der", "rb").read()
    scalar = int.from_bytes(open(prefix + ".priv", "rb").read(), "big")
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    chain = os.path.join(directory, "chain.pem")
    root_path = os.path.join(directory, "root.pem")
    key_path = os.path.join(directory, "key.pem")
    with open(chain, "w") as out:
        out.write(ssl.DER_cert_to_PEM_cert(leaf) + ssl.DER_cert_to_PEM_cert(root))
    with open(root_path, "w") as out:
        out.write(ssl.DER_cert_to_PEM_cert(root))
    with open(key_path, "wb") as out:
        out.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return chain, root_path, key_path


def keylog():
    path = os.environ.get("SSLKEYLOGFILE")
    return open(path, "a") if path else None


class Server(QuicConnectionProtocol):
    www = "."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requests = {}

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            return
        request = self.requests.get(event.stream_id, b"") + event.data
        self.requests[event.stream_id] = request
        if not event.end_stream:
            return
        line = request.decode("ascii", "replace").strip()
        path = line[4:] if line.startswith("GET /") else ""
        target = os.path.join(self.www, path.lstrip("/"))
        if not path or ".." in path or not os.path.isfile(target):
            print(f"hq_peer: refusing {line!r}", flush=True)
            self._quic.reset_stream(event.stream_id, 0)
        else:
            data = open(target, "rb").read()
            self._quic.send_stream_data(event.stream_id, data, end_stream=True)
            print(f"hq_peer: served {path} ({len(data)} octets)", flush=True)
        self.transmit()


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.answers = {}
        self.waiters = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self.answers[event.stream_id] = self.answers.get(event.stream_id, b"") + event.data
            if event.end_stream:
                self.waiters.pop(event.stream_id).set_result(self.answers[event.stream_id])
        elif isinstance(event, StreamReset):
            self.waiters.pop(event.stream_id).set_exception(RuntimeError("stream reset"))
        elif isinstance(event, ConnectionTerminated):
            for waiter in self.waiters.values():
                waiter.set_exception(RuntimeError(f"connection closed: {event.reason_phrase}"))
            self.waiters.clear()

    def fetch(self, path):
        stream_id = self._quic.get_next_available_stream_id()
        waiter = asyncio.get_running_loop().create_future()
        self.waiters[stream_id] = waiter
        self._quic.send_stream_data(stream_id, f"GET {path}\r\n".encode(), end_stream=True)
        self.transmit()
        return waiter


async def run_server(host, port, prefix, www, scratch):
    chain, _, key = pem_files(prefix, scratch)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=[ALPN], secrets_log_file=keylog())
    configuration.load_cert_chain(chain, key)
    Server.www = www
    await serve(host, port, configuration=configuration, create_protocol=Server)
    print(f"hq_peer: listening on port {port}", flush=True)
    await asyncio.Future()


async def run_client(host, port, prefix, server_name, downloads, paths, scratch):
    _, root, _ = pem_files(prefix, scratch)
    configuration = QuicConfiguration(
        is_client=True, alpn_protocols=[ALPN], server_name=server_name, secrets_log_file=keylog()
    )
    configuration.load_verify_locations(root)
    async with connect(host, port, configuration=configuration, create_protocol=Client) as client:
        answers = await asyncio.wait_for(asyncio.gather(*(client.fetch(path) for path in paths)), 30)
        for path, answer in zip(paths, answers):
            with open(os.path.join(downloads, path.lstrip("/")), "wb") as out:
                out.write(answer)
        print(f"hq_peer: fetched {len(paths)} files, {sum(map(len, answers))} octets", flush=True)
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
