# Decision 96: `examples/` holds programs a dependent writes, run on Rotor's loop over an in-memory link

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-26, who asked for examples like chapulin's and for them to use Rotor
and memory. It amends decision 58, which gave Rotor to `src/testing/` alone.
- Each example is a program that imports the library modules by the names a dependent uses
  (decision 86). `zig build examples` builds and runs every one, and `tools/ci.sh` runs that
  step, so an example that stops working fails CI.
- A client and a server run in one process, each on its own Rotor loop. What one side sends is
  copied into the other side's queue in memory, and a message posted between the loops says
  how many bytes arrived (`examples/link.zig`). The instant colibri takes is the one the
  side's loop read at its last tick.
- The examples open no socket, so `src/testing/` stays the one directory that does. Rotor is
  still a lazy package that only colibri's own build requests, and the library imports it
  nowhere.
- h11 and h2 come first, in cleartext. Examples over TLS, QUIC and h3 need chapulin, which
  design §8 step 16 links into the library.
- Amended on 2026-10-04, for design §8 step 17f: `tls_exchange.zig` runs `server` and `client`
  over TLS, and `h3_exchange.zig` runs `server.Endpoint` and `client.Channel` over
  `examples/link_datagram.zig`, a link that moves datagrams. Both present the test identity of
  `src/testing/testdata/`, which colibri's build gives them as the module `testdata`. The
  package still exports no test data.
- Amended on 2026-10-13, for design §8 step 21d (decision 121): `server_exchange.zig` and
  `client_exchange.zig` replace `tls_exchange.zig` and `h3_exchange.zig`, each with its peers
  in a file of its own. A program that moves a stream and datagrams runs both links on one
  pair of loops, so each side's instants come from one clock.

- Amended on 2026-11-05, for design §8 step 37 (decision 150 ruling 7): `examples/colibri_server.zig`
  binds 127.0.0.1 on port 0 through `colibri`, which a program uses to bind its sockets, and
  fetches from it over h11 with a client of `std.Io.Threaded`. The fetch over h2 and h3 comes
  with `colibri.Client` in design §8 step 42. `zig build examples` runs it. Every other example
  still opens no socket.
- Amended by decision 156 on 2026-11-06: `examples/colibri_shared_loop.zig` binds loopback
  too. One `rotor.Loop` holds a `colibri.Server`, a `colibri.Client` and a program timer.
  `zig build examples` runs it.

The alternatives refused:
- Programs over real sockets that CI builds and never runs, as chapulin's are. They show a
  whole program, but a broken one passes CI, and they would make a second directory open
  sockets.
- Bytes passed between the two sides with no loop at all. It is shorter, but it shows no
  program's shape: where the loop, the time and colibri's calls meet.
