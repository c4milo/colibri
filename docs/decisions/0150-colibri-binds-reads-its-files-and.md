# Decision 150: `colibri` binds, reads its files and runs the loop, through a `std.Io` the program may pass

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-04 (design §8 step 37), after a comparison of Zig's HTTP server
libraries. The owner asked for the shape of httpx.zig's server: a host, a port and the server's
certificate files in a configuration, a router, and one call that runs. Asked how that fits
non-negotiable 1, the owner ruled: "IO is a parameter and we use rotor by default if the user
doesn't provide one."

The rulings:
1. A new library module, `colibri`, above `server` and `client`. It is the one module that does
   I/O: it binds the TCP and the UDP socket of one port, reads the PEM files, accepts, reads,
   writes and sleeps, all through the `std.Io` its program passes. colibri still makes no
   system call itself: the `std.Io` implementation makes them.
2. Non-negotiable 1 holds for every other module. `core`, `wire`, `http`, the protocol modules,
   `quic`, `tls`, `server` and `client` own no I/O, and the simulator and the determinism
   checks cover them as before.
3. A program that passes no `std.Io` gets Rotor's. Rotor becomes a dependency of the library,
   for `colibri` alone. Rotor's `std.Io` adapter is its decision 22, accepted on 2026-09-27 and
   deferred until the owner asks for it, so step 37 depends on it.
4. `colibri`'s API names what httpx.zig's does where colibri has the same concept: a host, a
   port, the certificate chain and key files, the router, and `run`. h11, h2 and h3 come
   from the one port, h3 over UDP.
5. Amended by the owner on 2026-11-05, for a dependent that runs its examples on `colibri` in
   memory, through a `std.Io` that fakes the network:
   - `colibri` reads the clock and waits only through the `std.Io` it holds, never through
     Rotor or the operating system. A program that passes a fake `std.Io` controls time.
   - As amended by ruling 11, `colibri.ServerConfig.identity` is a `colibri.Identity`: the
     chain and the key as PEM text the program holds. An in-memory `std.Io` then needs no file
     system.
   - The port may be 0. `Server.port()` returns the port the `std.Io` bound, once `run` has
     bound it, so a script can read it.
6. Amended by the owner on 2026-11-05, for the same dependent, which asked for `colibri` before
   Rotor's `std.Io` adapter exists: `colibri` comes first on Rotor's own API, and the `std.Io`
   a program passes comes later.
   - With no `std.Io`, `colibri` drives a Rotor loop through Rotor's own calls. It keeps what
     `std.Io` cannot express: UDP_GRO and UDP_SEGMENT on Linux (design §8 step 13f.6), and
     Rotor's one system call a tick. Rotor's adapter would lose both.
   - Once Rotor's adapter exists, `Server.init` takes a program's `std.Io` as rulings 1 and 5
     say, and `colibri` runs through it with no other I/O.
   - The program passes the `std.Random` that each TLS session draws from (non-negotiable
     2), and `colibri` reads the loop's clock.
   - `colibri` takes a router that `server.router` built, unchanged.
7. Amended by the owner on 2026-11-05, for design §8 step 37:
   - `Server.run` runs one Rotor loop on the thread that calls it, and starts no thread. A
     program that wants more cores starts more servers on one port.
   - `colibri`'s example and its unit tests bind loopback sockets (decision 96 as amended), and
     `src/colibri/` is the second directory, after `src/testing/`, that opens a socket.
8. Amended by the owner on 2026-11-05: the module is `colibri`, a facade in the shape of
   httpx.zig's, so a program writes `colibri.Server` and, by decision 153, `colibri.Client`.
   The sans-I/O modules stay underneath it. The owner found `serve.Server` hard to read, and
   weighed it against Zig's own names, `std.http.Server` over a reader and a writer, and
   `std.Io.net.Server`, a listening socket:
   - `serve.Server` and `serve.Client` lost: the module and the type say the same thing.
   - `net.Server` lost: std's `net.Server` is a bare listener, not an HTTP server.
   - `http.Server` lost: colibri's `http` module is sans-I/O, and the protocol modules import
     it.
9. Amended by the owner on 2026-11-05: `ServerConfig.random` may be null, and `colibri` then
   draws from the operating system's entropy, through `getrandom` on Linux and `getentropy`
   on macOS. A program may still pass its own source. Only `colibri` has this default: every
   sans-I/O module still takes the program's source (non-negotiable 2).

10. Amended by the owner on 2026-11-05: Rotor builds no `std.Io` adapter, because it is too
   large. `colibri.Server` stays on Rotor's own API for good:
   - `Server.init` takes no `io`. Rulings 1 and 5 no longer pass a program's `std.Io`, and no
     example runs `colibri` over an in-memory `std.Io`. The examples stay in memory over
     `examples/link.zig`, which drives the sans-I/O modules.
   - The clock is the loop's, and ruling 9's default source stays. `colibri` reads no file, as
     amended by ruling 11.

11. Amended by the owner on 2026-11-05: `colibri.Server` takes its PEM chain and key as bytes
   alone, and the program reads its own files.
   - `colibri.Identity` is a struct of two fields, `chain` and `key`, each the PEM text the
     program holds. `.files`, its four `IdentityFile` errors and design §8 step 37e leave.
   - `colibri` reads no file. The PEM files of rulings 1 and 4 are the program's to read.
   - Rotor provides no file calls for `colibri`.
     [rotor#11](https://github.com/c4milo/rotor/issues/11), which asked for them, was closed
     as not needed.
   - `init` reads the key's text in place and keeps no copy, so the program may wipe the text
     once `init` returns.

12. Amended by decision 156 on 2026-11-06, for rulings 6 and 7:
   - A program whose `colibri.Client` or `colibri.Server` type names `.shared` passes the
     `*rotor.SharedLoop` of its own loop, and `colibri` then shares it with other libraries.
     Only the program ticks that loop.
   - `colibri` makes the loop it owns at `init`, not at `run`. So `init`, `run` and `deinit`
     run on one thread.

13. Amended by decision 159 on 2026-11-08, for rulings 3, 9 and 12:
   - Ruling 3: Rotor is a lazy dependency of `colibri`. A build fetches it only for the
     `.private` kind, the test endpoints and the examples. A dependent that uses `.private`
     passes `.rotor = true`.
   - Ruling 9: the entropy default applies to `.private` alone. `.hosted` takes the
     program's `std.Random`, with no default.
   - Ruling 12 is superseded. No configuration holds a `*rotor.SharedLoop`. `colibri` still
     makes its private loop at `init`.
   - Ruling 7 stays for `.private`. The tests of `.hosted` run on an in-memory host and bind
     no socket.

14. Amended by decision 159 on 2026-11-10, for ruling 12, as decisions 156 and 159 amended
    it. `colibri` makes its private loop at the first `run` or `fetch`, not at `init`. So
    `init` may run on another thread than `run`, and `fetch`, `run` and `deinit` run on one
    thread. This replaces the last sentence of item 12 and the sentence of item 13 that
    keeps the loop at `init`.

Alternatives that lost:
- A separate package on colibri and Rotor. The owner wants the shape in colibri itself.
- Wait for Rotor's adapter before any `colibri` (ruling 6). The dependent needs `colibri` now,
  and the adapter's calls cannot reach UDP batching.
- Documentation alone: the program keeps writing its own loop.
- Binding inside `server`, which would end non-negotiable 1 for the module the simulator
  drives.
- `.files` read through Rotor's file calls (ruling 11). Rotor opens a file to read and to
  write, so it refused a key file the program may only read, such as one of mode 0400.
- `.files` read through a local `std.Io.Threaded` (ruling 11): a second I/O implementation in
  `colibri`, beside Rotor's loop.
