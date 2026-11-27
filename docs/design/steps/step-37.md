# Design §8 step 37: the `colibri` module, proposed 2026-11-04

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 150](../../decisions/0150-colibri-binds-reads-its-files-and.md). It runs on Rotor's own API for good (rulings 6 and 10).
One loop runs on the thread that calls `run` (ruling 7).
- **The public names.** The root exports `Server`, `ServerOf`, `ServerConfig`, `Identity`,
  `InitError` and `RunError`.
  - `ServerOf(capacity)` takes a `server.Capacity`, and `Server` is `ServerOf(.{})`. A program
    places one, as it places an endpoint. Decision 156 renames `ServerOf` to `Server`, a type
    function, in step 44.
  - `ServerConfig` holds `host`, an IPv4 or IPv6 literal, `port`, `identity`, `cpu`, `random`,
    which defaults to the system's entropy (ruling 9), and `endpoint`, the `server.Config` the
    endpoint starts from. `colibri` fills its `tls`.
  - `Identity` holds `chain` and `key`, the PEM text the program holds. The program reads its
    own files (ruling 11).
  - `Server.init(config)` reads the identity and binds. `Server.run(router, context)` runs
    until `shutdown()`. `Server.port()` returns the port
    bound, for port 0. `Server.deinit()` closes each socket `run` did not close, and wipes the
    private key and the cookie key (the owner's ruling of 2026-11-05).
- **37a: the module.** `src/colibri/` in the graph, importing `server`, `tls` and Rotor, which
  stops being lazy. The io and determinism lint rules exempt it as they exempt `src/testing/`.
  The test that lists the names, and `init` with an identity of PEM text.
- **37b: TCP.** h11 and h2 in cleartext, h2 and h11 over TLS by ALPN, port 0 and `port()`, from
  `src/testing/server/`'s socket and pump, moved into the library.
- **37c: UDP.** h3 on the UDP socket of the same port, with UDP_GRO and UDP_SEGMENT on Linux,
  from `src/testing/quic/udp/`'s batches.
- **37d: the example.** `examples/colibri_server.zig` serves a route table on 127.0.0.1 port 0, and
  a client of `std.Io.Threaded` fetches over h11 and checks each response byte for byte. The
  fetch over h2 and h3 comes with `colibri.Client` in step 42. docs/usage.md and README.md show
  the example, and `tools/consumer/` calls `colibri`.
- **The record, 2026-11-05.** Each mutation below was **CAUGHT** by `zig build test-colibri`, or
  by `zig build examples` for 37d.
  - Ruling 11 removed 37e, `.files`, on 2026-11-05, with its code and its tests. The entries
    for 37e stay as the record of that code.
  - 37a: a `std.Io` accepted; no default source; the cookie key not drawn; the identity ignored;
    the key not read; entropy that fills one call alone.
  - 37b, five of them as a hang: no accept armed; shutdown ignored; a send event ignored;
    request events not stepped; a peer's close not passed on; a closing socket kept open; port
    0 kept.
  - 37c: the end-to-end h3 fetch moves to step 42 with the h2 fetch. The shutdown fix passed ten
    runs in a row.
  - 37d, by `zig build example-colibri_server`, two of them as a hang: shutdown ignored; port 0
    kept; a closing socket kept open.
  - 37e: the key's text not wiped; a file of `pem_file_len_max` bytes refused; no length check;
    a missing file reported as unreadable; the key read from the chain's name; a name with a
    zero byte accepted.
  - Rotor's `open_file` opens a file to read and to write, so a key file the program may only
    read, such as one of mode 0400, was refused with `IdentityFileAccessDenied`. A test pinned
    it until ruling 11.
  - After the review of 37d and 37e: the name's length check off by one; no length check;
    `AccessDenied` reported as unreadable; the key's text wiped on success alone; the key and
    the cookie key kept when `init` fails after the read; a TLS connection accepted as
    cleartext. The last one is caught by a fetch over TLS from std's client.
  - `deinit`, on 2026-11-05: no listener close; no UDP close; no key wipe; no cookie key
    wipe; a second close after `run`, in three forms.
  - **NOT CAUGHT:** no check for a file that became shorter after `file_size`. No test can
    shorten a file within `read`. Ruling 11 removed the check with 37e.
  - Ruling 11, on 2026-11-05: the key's parse error ignored; the key read from the chain's text;
    the cookie key drawn before the parse.
  - After the review of ruling 11: the chain's parse error ignored. The key's check hid it, so a
    test now loads a valid chain first and then refuses a chain that is not PEM.
  - **Not checked:** no test sends a datagram through `colibri.Server`'s socket, so its UDP
    receive and send paths have no check over a socket. The fetch over h3 with
    `colibri.Client` in step 42 checks them.
  - The ECN fix, after v0.14.0, on 2026-11-05. A dependent reported that a peer that marks its
    datagrams ECT(0), such as quic-go, halted the server. The loop passed each codepoint to an
    endpoint whose `ecn` was false, and decision 68's assertion refused it. `init` now sets
    `ecn`. A test passes `take_delivery` RFC 9001 Appendix A.2's Initial, marked ECT(0). It
    expects one ECT(0) count in the Initial space, and the endpoint to name ECT(0) for its
    answer. Each mutation was **CAUGHT**: the fix removed; the received codepoint passed as
    Not-ECT.
  - After the review of the ECN fix, on 2026-11-05: two tests in `server_udp.zig` check each
    codepoint each way. `outbound` asks Rotor to set the codepoint the endpoint named, and sets
    no flag for Not-ECT. `received_ecn` passes the codepoint Rotor read, and Not-ECT when Rotor
    read none. Each mutation was **CAUGHT**: `outbound`'s flag always false; ECT(0) sent as
    Not-ECT; CE sent as ECT(1); CE read as ECT(1); `received_ecn` without its check of the flag.
  - **NOT CAUGHT on macOS:** the batch match without the codepoint. On macOS each batch holds
    one datagram, so the mutant sends the same datagrams. **CAUGHT on Linux arm64**, in an
    Ubuntu 26.04 container on 2026-11-05: the test of `datagram_batch.zig` that gives one
    peer two codepoints expects two batches, and the mutant opens one.
- **The checks.** Each part's unit tests bind loopback. A shutdown ends `run` after the open
  connections close. The simulator's checks of `server` stay as they are.
