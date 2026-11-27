# Decision 46: Every endpoint in `src/testing/` does its I/O without blocking

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-19: the checks must show that colibri works under non-blocking I/O and
uses the processor well, because that is how a consumer will run it. A test-only endpoint holds its
connections in a fixed array, waits on all of them in one `poll` call, and makes no other call that
waits. The h2 server did this already; the h2 client of design §9 does it from its first commit, its
`connect` included.

The ruling decides what the client can link today. chapulin's TLS client reads its socket
through a callback that must return bytes or fail: `io.c` turns any result of 0 or less into
`CH_EIO` and the session is dead, so there is no way to say "nothing yet". Under a loop that
never blocks it cannot run. The client therefore speaks cleartext h2 with prior knowledge
(RFC 9113 §3.3), which carries the same h2 bytes, and TLS joins through `tls.Provider` when
chapulin offers a record mode that takes bytes in and returns bytes, the third h2 item of
[docs/chapulin.md](../chapulin.md). chapulin's server role is headers and fail-closed stubs
today, and its design names the same blocking callbacks, so the request applies to it before
it is written.

Two alternatives lost. A blocking client around `ch_connect`, `ch_read` and `ch_write` works
today and would show ALPN and TLS 1.3 against real servers, but it needs a thread for each
connection, it is not the shape a consumer would use, and it never crosses `tls.Provider`, so
it proves nothing about `connection_tls.zig`. A private stack for each connection, on which
the callback yields instead of blocking, keeps one thread; `std.Io`'s evented implementations
are the ready-made form, and they take an allocator for those stacks, which non-negotiable 4
forbids in `src/`.

Cost: the TLS half of step 5's interop waits on chapulin in both directions, not the server
direction alone. Gain: the client that exists is the one the TLS provider will sit under, so
no harness is written twice.
