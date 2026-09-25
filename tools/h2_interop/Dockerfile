# The peers of tools/h2_interop.sh and tools/h2_server_interop.sh, from Debian's own packages, so
# a run names the versions it met by asking the binaries: nghttpd and h2o as servers, and nghttp
# and curl as clients. Nothing here is colibri's code.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nghttp2-server nghttp2-client curl ca-certificates h2o python3 \
 && rm -rf /var/lib/apt/lists/*
# What both servers serve: a short file, and one sixteen times the 65,535-octet window a stream
# starts with (RFC 9113 §6.9.2), whose octet i is i % 251, the pattern the client's requests use.
RUN mkdir -p /www \
 && printf 'colibri\n' > /www/index.html \
 && python3 -c "open('/www/large','wb').write(bytes(i % 251 for i in range(1 << 20)))"
COPY h2o.conf /etc/h2o/colibri.conf
COPY h2o_tls.conf /etc/h2o/colibri_tls.conf
