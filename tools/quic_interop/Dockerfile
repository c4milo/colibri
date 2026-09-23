# colibri's endpoint image for the QUIC Interop Runner (design §9). tools/interop.sh builds it
# from a staged context: colibri's tree with its fetched packages in zig-pkg/, a chapulin
# checkout, and the two files beside this one.
#
# chapulin is built TRUST=raw-ecdsa: the runner's certificates carry no extended key usage, so
# they fail the Web PKI profile, and the client pins the server's key from the /certs it shares.
FROM martenseemann/quic-network-simulator-endpoint:latest

ARG ZIG_VERSION=0.16.0
RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential ca-certificates curl python3 xz-utils \
  && rm -rf /var/lib/apt/lists/*
RUN arch="$(uname -m)" \
  && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${arch}-linux-${ZIG_VERSION}.tar.xz" \
    | tar -xJ -C /opt \
  && ln -s "/opt/zig-${arch}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

COPY chapulin /src/chapulin
RUN cd /src/chapulin \
  && make RAND=drbg TRUST=raw-ecdsa TRANSPORT=quic ROLE=both KEYLOG=on lib \
  && cp bin/chapulin.o bin/chapulin-quic.o

COPY colibri /src/colibri
RUN cd /src/colibri \
  && zig build -Drelease -Dchapulin-quic=/src/chapulin -Dchapulin-quic-trust=raw-ecdsa \
  && cp zig-out/bin/quic-udp /usr/local/bin/quic-udp

COPY qns_identity.py run_endpoint.sh /
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
