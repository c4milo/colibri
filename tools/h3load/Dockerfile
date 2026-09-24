# h2load with HTTP/3, for tools/h3load.sh (design §8 step 12). Debian 13 packages h2load without
# HTTP/3, and ngtcp2 only with GnuTLS, while h2load does its TLS through OpenSSL. So this builds
# nghttp3, ngtcp2 on Debian's OpenSSL 3.5 (its QUIC API) and nghttp2 from their release tags.
# Nothing here is colibri's code.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS build
ARG NGHTTP3_TAG=v1.18.0
ARG NGTCP2_TAG=v1.25.0
ARG NGHTTP2_TAG=v1.70.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git build-essential autoconf \
    automake autotools-dev libtool pkg-config libssl-dev libev-dev libc-ares-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --recursive --shallow-submodules --depth 1 -b "${NGHTTP3_TAG}" https://github.com/ngtcp2/nghttp3 \
 && cd nghttp3 && autoreconf -i \
 && ./configure --disable-dependency-tracking --enable-lib-only && make -j"$(nproc)" && make install
RUN git clone --recursive --shallow-submodules --depth 1 -b "${NGTCP2_TAG}" https://github.com/ngtcp2/ngtcp2 \
 && cd ngtcp2 && autoreconf -i \
 && ./configure --disable-dependency-tracking --enable-lib-only --with-openssl \
 && make -j"$(nproc)" && make install
RUN git clone --recursive --shallow-submodules --depth 1 -b "${NGHTTP2_TAG}" https://github.com/nghttp2/nghttp2 \
 && cd nghttp2 && autoreconf -i \
 && ./configure --disable-dependency-tracking --disable-examples --disable-hpack-tools \
    --enable-http3 --enable-app \
 && make -j"$(nproc)" && make install

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 libev4t64 libc-ares2 zlib1g \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/ /usr/local/lib/
COPY --from=build /usr/local/bin/h2load /usr/local/bin/h2load
RUN ldconfig && h2load --version
