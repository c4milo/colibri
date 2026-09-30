# The peers of tools/h2_interop.sh, tools/h11_interop.sh and tools/h2_server_interop.sh, from
# Debian's own packages, so a run names the versions it met by asking the binaries: nghttpd, h2o
# and Caddy as servers, and nghttp and curl as clients. Nothing here is colibri's code.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nghttp2-server nghttp2-client curl ca-certificates h2o caddy python3 \
 && rm -rf /var/lib/apt/lists/*
# What the servers serve: a short file, one sixteen times the 65,535-octet window a stream starts
# with (RFC 9113 §6.9.2), whose octet i is i % 251, the pattern the client's requests use, and a
# text file h2o codes in br and Caddy in zstd for a client that accepts them (decision 101 as
# amended).
RUN mkdir -p /www \
 && printf 'colibri\n' > /www/index.html \
 && python3 -c "open('/www/large','wb').write(bytes(i % 251 for i in range(1 << 20)))" \
 && python3 -c "open('/www/text.txt','w').write('colibri\\n' * 8192)"
COPY h2o.conf /etc/h2o/colibri.conf
COPY h2o_tls.conf /etc/h2o/colibri_tls.conf
COPY Caddyfile /etc/caddy/colibri.Caddyfile
COPY Caddyfile_tls /etc/caddy/colibri_tls.Caddyfile
