# Design §8 step 60: one input and one output buffer in each TCP socket, 2026-11-18

[Design §8, the build plan](../../design.md#8-build-plan)

[#137](https://github.com/c4milo/colibri/issues/137). connect-zig measured its OTLP sink, a
`colibri.Server` of 528 TCP connections: about 531 KB a connection, of which the `.private`
adapter's socket took 197,184 bytes. The owner ruled on 2026-11-18 for a single receive buffer and
an output of one engine output, in that socket and in the test-only server's, so the judge prices
the change. No public name changes.
- **What the socket held.** Two receive buffers of `socket_input_len` bytes each, so that a
  receive is in flight in one while the session reads the other, and an output of two engine
  outputs, so that the engine writes while a send is in flight. No decision chose the two over
  one: the design came with the code, and its comments gave that reason.
- **The input.** A receive writes into the bytes free after the unread ones. The session
  consumes from the front, also while a receive is in flight, and a consume moves the start and
  the count together, so what arrives follows the unread bytes. The unread bytes move to the
  front only when the next receive is written, when no receive owns the buffer. Before, the
  bytes that arrived behind unread ones were copied: now only the unread ones move.
- **The output.** `socket_output_len` is `output_len`, one engine output, which the test-only
  server's socket already had (`write_buffer_len`). While a send is in flight, the engine
  writes after the bytes it sends, and it waits for the send once the output is full.
- **Memory.** `colibri.Server`'s socket goes from 197,184 to 98,616 bytes, and the test-only
  server's from 82,504 to 65,856. A connection of connect-zig's sink goes from about 531,528 to
  432,960 bytes, and its 528 connections take about 52 MB less.
- **The checks.**
  - Each socket's tests require a receive to write right after the unread bytes, the unread
    bytes to move to the front only when the next receive is written, and an arrival to follow
    the rest when the session consumes while the receive is in flight. The fuzz script of each
    socket gains a consume while a receive is in flight.
  - 10 mutations, 5 of each socket, each **CAUGHT**: an arrival counted one byte short; no move
    to the front; a receive over the unread bytes; the start set back on a consume that empties
    the input; and the receive in flight read from the front. The last was **NOT CAUGHT** until
    the test compared the bytes the receive was given with those it writes.
  - The tests of `colibri` pass on arm64 Linux in a container, 150 of 150, its loopback servers
    over TCP and TLS included. On x86-64 in Debug under Zig's own backend, each socket test passes
    in both modules; the emulation cannot run the loopback servers (`Unsupported`).
- **The judge**, [run 44382719777](https://github.com/c4milo/colibri/actions/runs/44382719777),
  measured the test-only server's change against `7b2a9d29` with the h11 inputs, at 10 rounds.
  Every input stays within the noise in both jobs, and none loses. The system calls a request
  stay at 0.04 to 0.10, except on h2-routes-post-late-many, whose medians went from 0.037 and
  0.038 to 0.067 and 0.064 within spreads of 60% to 405%. Its CPU time a request fell, from
  7,350 to 6,812 ns and from 7,384 to 6,955 ns. The judge has always measured one engine output
  in the test-only server, so the output's change in `colibri.Server` follows a design it ran.
