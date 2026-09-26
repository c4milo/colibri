# colibri as an origin of the HTTP Garden (docs/design.md §8 step 15d, decision 88): its test-only
# server in the echo mode, which answers every request with what h11 read of it, as the Garden's
# other origins do. tools/http_garden.sh copies this directory into the Garden's images/ and puts
# colibri's committed tree beside it as colibri.tar. The base image is the Garden's own.
FROM http-garden-soil:latest

# Zig 0.16.0, pinned by checksum for each architecture the Garden runs on.
ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256_X86_64=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
ARG ZIG_SHA256_AARCH64=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17
RUN apt -y update \
 && apt -y install --no-install-recommends curl xz-utils \
 && architecture="$(uname -m)" \
 && case "${architecture}" in \
      x86_64) checksum="${ZIG_SHA256_X86_64}" ;; \
      aarch64) checksum="${ZIG_SHA256_AARCH64}" ;; \
      *) echo "no Zig checksum for ${architecture}" && exit 1 ;; \
    esac \
 && curl -sSfL -o zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-${architecture}-linux-${ZIG_VERSION}.tar.xz" \
 && echo "${checksum}  zig.tar.xz" | sha256sum -c - \
 && mkdir /opt/zig \
 && tar -xJf zig.tar.xz -C /opt/zig --strip-components=1 \
 && rm zig.tar.xz \
 && rm -rf /var/lib/apt/lists/*

# ReleaseSafe, as colibri ships: assertions stay on (CLAUDE.md, Commands).
COPY colibri.tar .
RUN mkdir colibri \
 && tar -xf colibri.tar -C colibri \
 && rm colibri.tar \
 && cd colibri \
 && /opt/zig/zig build install -Drelease

# The Garden reaches a cleartext origin on port 80 of its container's address.
CMD ["/app/colibri/zig-out/bin/http-server", "--port", "80", "--address", "0.0.0.0", "--h11", "--echo"]
