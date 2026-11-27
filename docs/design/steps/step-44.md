# Design §8 step 44: colibri on a loop that the program hosts, proposed 2026-11-06, planned again 2026-11-08

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 159](../../decisions/0159-colibriclient-and-colibriserver-take-a-host.md), which amends decisions 150, 156 and 158. `colibri.Client`
and `colibri.Server` take a host interface in colibri's own terms. Each object is a driver and a
host. The driver does no I/O, reads no clock and imports no Rotor. The host does each operation on
its own loop. `.private` is the driver plus colibri's own Rotor adapter. `.hosted` is the driver
alone, and the program is the host. A program on libuv, libxev or `std.Io` can host `.hosted`. It
ships whole in v0.16.0: the owner cut v0.15.0 from main without it on 2026-11-08.
- **The plan that decision 159 replaces.** Decision 156 and its seven amendments put colibri on
  a `rotor.SharedLoop`, with completion records, a poller, a task, a scheduling group and one of
  the loop's 16 buffer group ids. The owner replaced that plan on 2026-11-08, after 44b had
  landed. The git history of this file holds its text. 44b's record stays below.
- **The public names**, in decision 115's order:
  - The root: `client`, `server`, `constants`, `Server`, `ServerConfig`, `Identity`,
    `InitError`, `RunError`, `Client`, `ClientCapacity`, `ClientConfig`, `SocketId`,
    `OperationId`, `Operation`, `Completion`, `Failure`, `Wait` and `Turn`. `client` and
    `server` are module re-exports. `ClientOf` and `ServerOf` shipped in v0.14.0, and v0.16.0
    removes them from the list (decision 156 ruling 1).
  - The seven names from `SocketId` to `Turn` are the host interface. Client and Server share
    them, so they are top-level names (decision 158 ruling 6). Decision 159 gives each one's
    fields. No name holds a Rotor type, and the root re-exports no `rotor`.
  - A peer address is `server.Address`, the same type as `client.Address`
    (`quic.PeerAddress`). The ECN codepoint is `server.Ecn` (`quic.Ecn`).
  - `Server`: `init`, `deinit`, `port`, `run`, `turn`, `complete`, `shutdown`, `stopped`,
    `operations_max`, `sockets_max`, `listener`, `datagram` and `InitError`. The owner's
    ruling 7 of 2026-11-10 adds `InitError`: a hosted program that returns the error of
    `init` from its own function names the set, as it names `Client.InitError`.
  - `Client`: `init`, `deinit`, `request`, `fetch`, `cancel`, `set_destination`, `run`, `turn`,
    `complete`, `shutdown`, `stopped`, `operations_max`, `sockets_max`, `datagram_ipv4`,
    `datagram_ipv6`, `InitError`, `RunError`, `FetchOptions`, `FetchResult` and `FetchError`.
  - Each list is the same for `.private` and `.hosted`. On `.hosted`, the body of `run`,
    `fetch` and `port` is a `@compileError` with colibri's message. On `.private`, the body of
    `turn` and `complete` is one too (decision 156 ruling 4 as amended).
  - `Client(capacity, kind)` and `Server(capacity, kind)` are type functions, named after the
    thing itself as Zig's std names `std.ArrayList(T)`. The kind is the second comptime
    argument, of type `enum { private, hosted }`. The enum has no public name, and the kind has
    no default.
  - A capacity holds comptime sizes alone. `ClientCapacity` holds `quic`, `tcp_connections` and
    `requests`. The first argument of `Server` stays a `server.Capacity`.
  - Never public: the Rotor adapter and its files, `RotorHost`, `ClientHandler`, `LoopIds`,
    `Host`, `ServerCapacity` and the hosted configuration types. A program writes each
    hosted configuration as a literal (decision 156 ruling 2).
- **The configuration.**
  - With `.private`, the configuration is `ClientConfig` or `ServerConfig`, which hold no
    `loop`, no `buffer_group` and no `scheduling_group`.
  - With `.hosted`, the configuration is `ClientConfig` or `ServerConfig` with the I/O fields
    removed. The server adds `sockets`, and the client adds `datagram`, with one `?Features`
    for each family. Each field has a default except `random`, which is the program's
    `std.Random`. `Features` names whether the host sends segments and whether it reads and
    sets ECN. Decision 159 gives each field.
  - The host binds before `init`, in its own API. A bind error is the host's error, at the
    host's call. `Server.port()` exists on `.private` alone.
  - colibri copies what it keeps, and keeps no pointer to the configuration after `init`
    (decision 158 ruling 2).
  - `ClientConfig.destination`, a `client.Destination`, replaces `host` and `port`. The program
    keeps `addresses` alive until the next `set_destination` or `deinit`. `HostInvalid` leaves
    the error set.
  - `ServerConfig.endpoint` becomes `ServerConfig.engine`, the name of the engine that it
    configures (decision 158 ruling 16). 44d changes the field, its examples and docs/usage.md.
  - `pool`, `random` and `unix_seconds` stay.
- **`init`.** `Client.init(config, handler)` and `Server.init(config, router, context)`.
  - `handler` is a pointer to the program's struct, or null for a client that only fetches.
    The struct declares `on_finished` and may declare `on_connected`.
  - colibri keeps the handler or the context as an `*anyopaque` and a trampoline that comptime
    makes. Both are private.
  - On `.private`, `init` binds, makes the loop and reserves its buffer group, in the adapter.
    On `.hosted`, `init` reads the sockets that the configuration names, and does no I/O.
- **The rules that bind a host.** Decision 159 states them, docs/usage.md states them, and
  colibri asserts each one that it can see:
  1. Each operation gets exactly one final completion, with `more = false`.
  2. colibri frees a socket's slot only after each operation on it had its final completion.
  3. One thread makes each call into an object. A `.hosted` object makes no thread check,
     because `gettid` is a system call on Linux.
  4. The host never calls `turn` or `complete` from inside `turn`. The `in_turn` flag of 44e
     makes such a call a halt.
  5. After a `complete`, or after a program call such as `request`, the host calls `turn`
     before it waits.
  6. `now_ns` never goes back. A completion with an id that colibri does not hold is a halt.
- **`turn`.** It does the steps of decision 156's poller, with no poller, in this order:
  1. Pass a `shutdown` to the pool or the engine.
  2. Call `on_instant` when a deadline is due.
  3. Drain the events, and call `on_finished` and `on_connected` of the handler. A `request`
     from the handler leaves in the same turn.
  4. Step each pending socket.
  5. Write the receives, the accept, the sends and the UDP batches into `operations`.
  6. Return `.now` while work is left or `operations` was full, `.at_ns` of the next deadline,
     or `.none` with neither. An idle colibri never makes the host spin.
  - `complete` records one result. It feeds a datagram to the engine or the pool at once,
    because the host lends the bytes for the call alone. It calls no handler and writes no
    operation.
- **The error sets.**
  - `.hosted`: `init` returns `server.StartError` or `client.StartError` alone. `.hosted` has
    no `RunError`.
  - `.private`: `InitError`, `RunError` and `FetchError` spell colibri's own members. The
    adapter maps Rotor's errors onto them.
  - `error.BufferGroupsFull` leaves `RunError` in 44c. The adapter writes
    `reserve_buffer_group() catch unreachable` on a loop that it just made, with a comptime
    assertion of the count. The test-only `udp.Endpoint` does the same.
  - `error.PollersFull` leaves `InitError`, because colibri adds no poller.
- **The Rotor adapter of `.private`.**
  - It is `src/colibri/rotor_host.zig`, with `rotor_host_udp.zig` and
    `rotor_host_entropy.zig` when the file passes 500 lines. Only these files of `colibri`
    import Rotor, and the root exports none of them.
  - It holds the `rotor.Loop` and its memory, `events[operations_max]`, a table of
    `rotor.Descriptor` for each `SocketId`, and a table of `rotor.Handle` for each operation
    that a `cancel` can name. It holds the buffer group of each UDP socket and its `Outbound`
    records too. The group of 16 × 66 KiB moves out of `DatagramSocket` into the adapter, so
    its size does not change.
  - `run` loops until `stopped()`. Each pass loads the stop flag with acquire order, calls
    `turn`, submits each operation, and ticks with a wait from `Wait`, capped at
    `stop_wait_ns_max`. Then it builds a `Completion` from each `rotor.Event`, calls
    `complete`, and gives back each datagram buffer.
  - `user_data` is the `OperationId`. No other code submits on this loop.
  - The adapter keeps the thread assertion of `shutdown` and of the other calls.
  - It uses Rotor's core alone: no `rotor.Completion` record, `Poller`, `Task`, `WaitLimit`,
    `SharedLoop`, scheduling group or `Registry`. Rotor's session was asked on 2026-11-08 to
    keep in its core each part that the adapter uses (decision 159, answer 8).
  - colibri exports no adapter for a shared Rotor loop. `examples/colibri_shared_rotor.zig`
    shows the program's own adapter.
- **Rotor is lazy** (decision 159, which amends decision 150 ruling 3).
  - `build.zig.zon` marks `rotor` with `.lazy = true`. `build/modules.zig` reads the build
    option `rotor`. Its default is true when colibri is the root package and false otherwise.
  - With the option true, the build calls `b.lazyDependency("rotor", ...)` and gives `colibri`
    the import. A `build_options` value tells `colibri` whether Rotor is present.
  - With the option false, `Client(_, .private)` and `Server(_, .private)` are a
    `@compileError`: "colibri: .private runs on Rotor; pass .rotor = true to
    b.dependency(\"colibri\", ...)".
  - A dependent that uses `.private` passes `.rotor = true`. A dependent of the protocol
    modules alone, or of `.hosted`, fetches chapulin and stdx, and no Rotor.
  - The module of the examples keeps its import of Rotor (decision 96).
- **The lint rule `rotor-import`**, in `tools/lint/` (decision 36):
  1. The build. Each `<receiver>.addImport("rotor", ...)` names `colibri`, `testing`,
     `testing_client`, `testing_udp` or the module of the examples. Each
     `dependency("rotor", ...)` is `lazyDependency`.
  2. The source. A file under `src/` that holds `@import("rotor")` is in `src/testing/` or is
     `src/colibri/rotor_host*.zig`.
  3. The compile proof. `zig build colibri-hosted-check` builds `colibri` with `rotor = false`.
     A fixture of `.hosted` must compile, and a fixture of `.private` must fail with colibri's
     message.
  - The `io` rule narrows its exemption from `src/colibri/` to `src/colibri/rotor_host*.zig`.
  - `build/lint.zig` gets one canary for each part.
- **The Rotor bump.** Commit 44b runs `zig fetch --save=rotor
  git+https://github.com/c4milo/rotor#v0.10.0`. Rotor main holds the code of Rotor's decision 26
  at d1657ce, of decision 27 at a03d95d, and b5a7804 (`release_buffers`). The owner accepted
  Rotor's decisions 28 and 29 on 2026-11-06, at 1dfccaf, and decisions 30 and 32 on 2026-11-07,
  at e57019e.
  - colibri pins Rotor's `v0.10.0`. Rotor's session reported on 2026-11-07 that the tag carries
    Rotor's decisions 28, 29, 30 and 32, and not decision 31 (decision 156, fifth amendment).
    Decisions 26 and 27 came after Rotor's `v0.9.0`, so the tag carries them too.
    Rotor's build order is W3 (the fair tick order), decision 29, decision 30, then decision 32.
  - On 2026-11-07 Rotor had no such tag. Decision 28 was on Rotor's main, and decisions 29, 30
    and 32 were not built.
  - Rotor's `v0.10.0` is the tag on 933985882d693e4d8b876e1403618a3fc6d989ef, and Rotor's CI
    passed on it (decision 156, seventh amendment). It carries the nine renames of Rotor's API
    audit. 44b changes each call site in `src/colibri/`, `src/testing/` and `examples/`.
  - The calls on main that change:
    - Each call that names a buffer group takes a `rotor.BufferGroup`, and a `u16` fails to
      compile. The calls are in `src/colibri/datagram_socket.zig` and `src/testing/udp.zig`.
      44b gets each group from `reserve_buffer_group` at init, and handles
      `error.BufferGroupsFull`.
    - Main adds no poller and no task. Decision 159 adds none either: the adapter of `.private`
      uses Rotor's core alone.
  - What the programs in colibri's tree add:
    - `examples/link.zig` makes a `rotor.Registry`. Since Rotor's cee1474 the registry keeps
      each loop's wake descriptor until `Registry.deinit`, which `v0.10.0` renames from
      `close_wakes`. 44b makes `Loops.deinit` call `registry.deinit()` after both loops end.
      No other program in colibri's tree makes a registry: colibri's private loop,
      `src/testing/` and `tools/consumer/` make none.
    - No program in colibri's tree declares `rotor_scheduling_groups`. A program declares it only
      to name a group by name (Rotor's decision 30). Decision 159 names no scheduling group.
  - Decision 32 changes no colibri call: colibri makes no cross-core call. Its post room of 224
    and its `message_tag_max` of `0x7fff_effd` apply to `examples/link.zig`, which posts tag 1.
    `zig build examples` shows whether the lower room changes a result.
  - Rotor's 782d6de makes a `close` wait for each offloaded file operation on its descriptor.
    colibri uses no offload, so no colibri close changes.
  - 44b keeps Rotor a package that is not lazy, because the `colibri` module imports it. 44j
    makes it lazy (decision 159).
  - Run `zig build bench-memory` and update the table of `docs/performance.md`.
- **The commits.** Each commit passes `zig build test-colibri`. A mutation that only fires an
  assertion or a Rotor halt is recorded as **NOT CAUGHT**, with the reason.
  1. 44a `docs`: decision 159, the amendments of decisions 150, 156 and 158, and this entry.
     - Check: `zig build lint` (the Markdown rule) and `tools/doc_snippets.sh`.
  2. 44b `build(colibri)`: the Rotor bump and the memory table, with no change of behaviour.
     `src/colibri/` and `src/testing/` get each buffer group from `reserve_buffer_group`, and
     pass a `rotor.BufferGroup` to each call that names a group. `examples/link.zig` calls
     `registry.deinit()` after its loops end. Each call site takes the nine renames of Rotor's
     `v0.10.0`.
     - Done on 2026-11-08. `build.zig.zon` names Rotor's 933985882d693e4d8b876e1403618a3fc6d989ef,
       and Rotor stays a package that is not lazy.
     - Three renames applied in colibri's tree: `Operation.accept` with no flag, `Loop.init` and
       `Loop.memory_bytes` with `*const Options`, and `Registry.deinit`. No call site named the
       other six.
     - `DatagramSocket.start` and the test-only `udp.Endpoint` reserve their group at each new
       loop. So `RunError` gains `error.BufferGroupsFull`, which a loop that colibri owns never
       returns.
     - `zig build bench-memory` printed the table of `docs/performance.md` with no change: no
       struct it sizes holds a Rotor type.
     - On macOS arm64 (kqueue), each check returned 0: `zig fmt --check`, `zig build lint`,
       `zig build test`, `zig build examples`, `tools/doc_snippets.sh` and
       `tools/consumer_check.sh`.
     - Its `error.BufferGroupsFull` in `RunError` leaves in 44c.
  3. 44c `refactor(colibri)`: the driver and `rotor_host.zig` behind `.private`, with no change
     of behaviour. `OperationId` replaces the tags of `socket.zig` and `datagram_socket.zig`.
     Only `rotor_host*.zig` imports Rotor.
     - Checks: the loopback tests of steps 37 to 42 pass unchanged. A fake host drives the
       driver: a deadline fires on time with a host that waits 1 s, and `turn` returns `.now`
       only while work is left.
     - Mutations: no final completion counted (a hang under the watchdog); a completion with a
       stale generation accepted; `turn` returns `.now` when idle (the bench alone); `.at_ns`
       one deadline late; a datagram fed after `complete` returns.
     - Bench: `bench/run.sh --base` for `h2-many` and `h3-many` on the judge. Record the
       instructions and the system calls for each request. The design estimates 20 to 40
       more instructions for each operation, under 1% of `h2-many`.
     - Done on 2026-11-08, with no change that a program sees.
       - The drivers are `server_loop.zig` and `client_loop.zig`. Each `turn` writes the
         operations into the host's storage, and each `complete` takes one completion.
         `host.zig` holds decision 159's seven types, and `operation_table.zig` holds the ids and
         their generation byte. The root exports none of them before 44d.
       - The host is `rotor_host.zig`, `rotor_host_submit.zig`, `rotor_host_udp.zig`,
         `rotor_host_end.zig` and `rotor_host_entropy.zig`, which was `entropy.zig`. These files
         and the two test files `rotor_host_server_test.zig` and `rotor_host_client_test.zig`
         are the only files of `colibri` that import Rotor.
       - The low 32 bits of each `user_data` are the `OperationId`. The high 32 bits are the
         host's own tag: the kind, the `SocketId` and the `Outbound` record of a send.
       - `InitError` is `LoadError` and colibri's `BindError`. `RunError` is
         `server.StartError` and `Unsupported`, `PermissionDenied`, `SystemResources` and
         `Unexpected`. `BufferGroupsFull`, `StillInFlight` and `TasksStillQueued` left it.
         `PollersFull` was in no set on this branch. The test-only `udp.Endpoint` reserves its
         group with `catch unreachable`.
       - Three mechanisms changed. The driver cancels a connect at its deadline, so Rotor
         gets no deadline. A run ends after each operation's final completion: the server
         cancels its accept and its receive of datagrams at shutdown, and the client cancels its
         receive once the pool closed. A connect whose socket the system refuses completes in
         the same pass, and its close completes with no descriptor.
       - Three points of decision 159's text differ from the code, for the owner to rule:
         - `Completion.datagram.bytes` is `[]u8`, because QUIC unprotects in place (RFC 9001
           §5).
         - A `cancel` has the id of its target, and gets no completion of its own.
         - `complete` still routes the events that the engine or the pool reports while it
           takes a datagram, as before. 44d must decide where those events wait.
       - Decision 160's staged close came to main while step 44 waited. The replay of
         2026-11-10 keeps it on `.private`. The host contract has no operation for a half-close
         yet, so colibri's own Rotor host does it:
         - After each turn, it takes each socket whose write side closes from
           `server_loop.take_half_close`, and submits Rotor's `shutdown` of the send side.
         - It gives the end of each shutdown to `server_loop.half_closed`.
         - It holds one more operation for each TCP socket.

         A hosted server, which 44d adds, did no half-close until the owner's ruling 9 of
         2026-11-10. Its connection closed in one step at the bound of `half_close_ns`, or when
         the peer closed. Ruling 9 replaces this bridge with the operation `shutdown_send` (the
         rulings of 2026-11-10, below).
       - Mutations of that half-close, each against `zig build test-colibri`, all CAUGHT: no
         shutdown taken; its end not given to the socket; the pump drops `half_close`; no
         receive after the half-close; the end of a run reads the shutdown's tag as an
         operation's; `finished` ignores a shutdown in flight; a shutdown due before the send
         ends; no step after the shutdown's end; a due socket not marked; one shutdown taken
         twice.
       - On macOS arm64 (kqueue), each check returned 0: `zig fmt --check`, `zig build lint`,
         `zig build test`, `zig build examples`, `tools/doc_snippets.sh` and
         `tools/consumer_check.sh`. `zig build test-colibri -Dtarget=aarch64-linux-gnu`
         compiled.
       - Mutations, each against `zig build test-colibri`:
         - No final completion counted: CAUGHT by the test of `operation_table.zig`. The
           run of the loopback tests also does not return.
         - A completion with a stale generation accepted: CAUGHT by the same test.
         - `turn` returns `.now` when idle: CAUGHT by the fake host's deadline test.
         - `.at_ns` one deadline late: CAUGHT by the fake host's deadline tests of the server
           and of the client.
         - A datagram fed after `complete` returns: CAUGHT by `server_udp_test.zig` and four
           h3 tests of the client.
       - The bench on the judge is not run yet.
  4. 44d `feat(colibri)!`: `Client` and `Server` as type functions of a capacity and a kind;
     `ClientOf` and `ServerOf` gone; the handler and the router at `init`; `.hosted` with
     `turn`, `complete`, `stopped`, `operations_max` and `sockets_max`; `engine` in place of
     `endpoint` (decision 158 ruling 16).
     - Checks: `zig build colibri-loop-check` compiles each case. `run` and `fetch` on
       `.hosted`, and `turn` and `complete` on `.private`, fail with colibri's message. A
       `.hosted` client and server that call `init` compile.
     - Tests on a fake host: a `request` from `on_finished` leaves in the same turn; a stray
       completion halts; `deinit` on `.hosted` before `stopped()` halts; a family with no
       socket falls back to TCP.
     - Test of the names: the root's list holds the seven new names, and no `ClientOf`,
       `ServerOf` or `ServerCapacity`.
     - Done on 2026-11-08.
       - `Server(capacity, kind)` and `Client(capacity, kind)` replace `ServerOf` and
         `ClientOf`. The kind is `host.ObjectKind`, which the root does not export.
         `server_kinds.zig` and `client_kinds.zig` hold what each kind does at `init` and
         `deinit`, so each type function stays at complexity 15 or less.
       - `init` takes `*const` configuration and the router and context, or the handler.
         `erased.zig` keeps each one as an `*anyopaque` and a function that comptime makes.
         `run` takes no argument.
       - The root adds the seven names. `Server` lists `operations_max`, `sockets_max`,
         `listener`, `datagram` and its eight calls. `Client` lists `InitError`, `RunError`,
         `operations_max`, `sockets_max`, `datagram_ipv4`, `datagram_ipv6` and its eight calls.
       - The client's socket table has one UDP socket id for each family. The client uses the
         one of its destination's family. 44f adds the second `DatagramSocket`.
       - A stray completion and `deinit` of `.hosted` before `stopped()` halt with colibri's
         message. `zig build colibri-loop-check` runs each halt as a program, because a test
         binary does not live through its own halt. It also proves the seven compile errors
         and runs a hosted server and client with no socket.
       - Points for the owner to rule:
         - A hosted `init` takes no instant. The hosted engine starts at instant 0, which
           bases only the seconds of tickets that a `colibri.Server` never issues. A hosted
           client counts `unix_seconds` from its first `turn`.
         - A hosted server keeps `identity`, so its `init` also returns
           `error.IdentityInvalid`. A hosted client keeps `host` until 44g, so its `init` also
           returns `error.HostInvalid`.
         - `cpu`, `host`, `pool` and `unix_seconds` keep no default, as in the `.private`
           configurations.
         - A hosted server cannot know its port, so the program names the h3 alternative in
           `engine.h3_alternative`.
         - `Client.RunError` of `.hosted` is the empty set, so both kinds list one name.
         - The private loop is still made in `run`, on the thread that runs it.
       - Checks and mutations: see the commit body of 44d.
  5. 44e `feat(colibri)`: the `in_turn` flag, which now also guards `turn` and `complete`.
     - Test: a `fetch` from `on_finished` on `.private`, and a `turn` from the handler on
       `.hosted`, halt under the halt harness.
     - Done on 2026-11-08.
       - Each `turn` and each `complete` of the driver sets `in_turn`, and halts when it is
         already set. `run` of `.private` halts when it is set. The flag is set in `complete`
         too, because `complete` still calls the handler for the events of a datagram (44c).
       - `fetch` comes in 44h, so 44e halts `run` from `on_finished` on `.private`. 44h adds
         `fetch` to the guard and its halt case.
       - `zig build colibri-loop-check` runs six new halt cases. A client's handler calls
         `turn`, `complete` or `run`, and a server's route does the same.
       - The test of h3 in `client_udp_test.zig` requires each call of the handler and of the
         route to come while `in_turn` is set.
       - Checks and mutations: see the commit body of 44e.
  6. 44f `feat(colibri)`: one UDP socket for each family. On `.hosted`, each family is a field
     of the configuration.
     - Mutations: a send's socket not chosen by family; the second receive not written.
     - Done on 2026-11-08.
       - `datagram_socket.zig` holds `DatagramSockets(count)`: one UDP socket for a server, and
         one for each family for a client. The sockets of one object share one set of batches,
         so the client's memory grows by one receive alone. A send leaves from the socket of
         its peer's family.
       - A client's operation table holds one more slot, for the second receive, so its
         `operations_max` grows by 1. A server's stays as it was.
       - `.private` binds both families on Rotor's one buffer group (decision 156 ruling 13).
         The bind of the destination's family must succeed, as before. A bind of the other
         family that the system refuses leaves that socket closed.
       - `.hosted` takes each family whose `Features` the configuration names. The pool's ECN
         and the segments follow the destination's family. 44g decides what a destination of a
         family with no socket does.
       - Checks and mutations: see the commit body of 44f.
  7. 44g `feat(colibri)!`: `destination` and `set_destination`.
     - Done on 2026-11-08.
       - `ClientConfig.destination`, a `client.Destination`, replaces `host` and `port`, on both
         kinds. `HostInvalid` leaves each client's `InitError`, so a hosted client's `init`
         returns `client.StartError` alone. The server's `BindError` keeps it.
       - `set_destination` passes the new addresses to the pool. It does not set `undrained`:
         the pool reports no event for the call, and each turn reads the pool's events first.
       - An open of QUIC to a family with no UDP socket ends through `transport_closed`, and the
         pool opens TCP (decision 156 ruling 13). This settles the point that 44f left open.
       - A hosted client offers h3 when the host opened a UDP socket of either family. The
         pool's ECN and the segments hold only when each socket that the host opened has them,
         because `set_destination` can change the family.
       - `.private` binds both families. The bind of the first address's family must succeed.
       - Tests on the fake host: a connection that opens after `set_destination` goes to the
         new address; an open connection keeps its exchange; after `set_destination` to a family
         with no socket, the TCP connect is the one operation of a turn with room for one.
       - Mutations, each against `zig build test-colibri`:
         - The old address list read after the call: CAUGHT by two fake-host tests.
         - The open of QUIC to a family with no socket not ended: CAUGHT by the test of a turn
           with room for one. A second test halts on the assertion in `datagram_socket.zig`.
         - The `Features` of the first family alone: CAUGHT by a fake-host test.
         - `undrained` not set: NOT CAUGHT, and no test can catch it, because each turn reads
           the pool's events first. So the call does not set it.
  8. 44h `feat(colibri)`: `fetch` and `cancel`. Its tests on a shared loop become tests on the
     fake host.
     - Done on 2026-11-10.
       - `fetch` hands the pool one request, and runs the loop of `.private` until that
         exchange has ended. `FetchOptions`, `FetchResult` and `FetchError` join the list of
         `Client`. `FetchError` holds colibri's `LoopError`, `client.RequestError` and
         `ShutDown`. On `.hosted` it is the empty set, and `fetch` is a compile error.
       - The first `fetch` or `run` makes the loop, and it stays made between fetches. `deinit`
         of `.private` calls `shutdown`, and runs the loop until each connection has closed
         (decision 156 ruling 10).
       - The handler gets each exchange that ends, except the one of the fetch. A `fetch` from a
         handler halts, as 44e planned.
       - When the loop fails, `fetch` cancels its exchange in the pool before it returns the
         error. So the pool keeps no pointer into the memory that `FetchOptions` names.
       - `cancel(id)` takes no instant, so it passes the pool the instant of the last `turn` or
         `complete`. An h11 drop counts its time from that instant (decision 146 ruling 3). The
         call does not set `undrained`, as 44g found for `set_destination`.
       - `init` now empties what a run holds. Before, `stopped()` read what only the first turn
         set, so a hosted client that `init` started again had already stopped. A `.private`
         server had the same fault with its `over` flag.
       - Tests on `.private`, on loopback: a GET and a POST over h11, h2 and h3, each pair on one
         connection; a body longer than `response_body`; a fetch beside an exchange of
         `request`; a `cancel` that gives no `finished`; a fetch after `shutdown`.
       - Tests on the fake host. `fake_host_pair_test.zig` is the host of a `.hosted` client and
         a `.hosted` server at once. It carries each send and each datagram between them in
         its own memory. So a GET and a POST run over h11, h2 and h3 through `request` and the
         handler, with no socket and no thread. Three more tests cancel an exchange: before its
         request left, on an open connection, and from `on_finished`. Two tests of
         `fake_host_test.zig` check the instant of an h11 drop.
       - `zig build colibri-loop-check` has two more cases: `fetch` on `.hosted` fails to
         compile, and a handler that calls `fetch` halts.
       - Decision 159 and this entry now name v0.16.0, because the owner cut v0.15.0 from main
         without step 44.
       - Points for the owner to rule:
         - `cancel` of a `.hosted` client between two turns uses the instant of the last turn.
           When the host waited long before the cancel, an h11 drop has less than `drop_ns`
           left, and the connection closes. A `cancel(id, now_ns)` on `.hosted` would end this.
         - `deinit` of `.private` after a `fetch` returns only when each exchange of `request`
           has ended, as decision 156 ruling 10 rules. No deadline bounds it.
         - The private loop is made at the first `fetch` or `run`, as 44d left it. So a program
           calls `fetch`, `run` and `deinit` on one thread, and `init` on any thread.
       - Mutations, each against `zig build test-colibri` unless stated:
         - The five that the first plan named. The fetch's `finished` sent to the handler:
           CAUGHT. The wrong default method: CAUGHT. `body_len` not copied: CAUGHT. `cancel`
           not passed to the pool: CAUGHT by six tests. A fetch loop that returns early:
           CAUGHT by the test of `client_fetch.zig`.
         - Any `finished` ends the fetch: NOT CAUGHT at first, because the handler then got the
           fetch's exchange in place of its own. The test now compares the id, and the mutation
           is CAUGHT.
         - No cancel in the pool after a failed loop, and `fetching` kept after it: each CAUGHT
           by the test of `client_fetch.zig`.
         - The last instant not kept in `complete`, and not kept in `turn`: each CAUGHT by its
           drop test.
         - `deinit` that does not stop the loop: CAUGHT. `closed` kept by `init`: CAUGHT by 28
           tests. Under it one older test of `client_tcp_test.zig` does not return, because
           its peer waits for a connection that never comes. The server's `init` with no
           reset: CAUGHT.
         - The response's header buffer not passed, and the request body not sent: each CAUGHT.
         - `stop` with no `shutdown`: CAUGHT by the watchdog of five tests alone, as a run that
           does not return.
         - A loop made twice: NOT CAUGHT. The assertion in `client_loop.start` fires first, so
           no test can read a result.
         - Against `zig build colibri-loop-check`: no guard in `fetch`, CAUGHT, and no compile
           error of `fetch` on `.hosted`, CAUGHT.
  9. 44i `feat(colibri)!`: the root re-exports `client` and `server`, and the tests of the
     names lists run again.
     - Done on 2026-11-10.
       - The root of `colibri` exports `client` and `server`, each the module itself, before
         `constants` (decision 115's order). The root's list holds 18 names, as "The public
         names" above states them.
       - A program that imports `colibri` needs no import of `client` or `server`. So
         `examples/colibri_server.zig` takes both from `colibri`, and `tools/consumer/` builds
         its router from `colibri.server`. docs/usage.md shows the two lines.
       - The lists of `Server` and of `Client` did not change in this commit. The test checks
         each list for `.private` and for `.hosted`, and checks that a type has one identity
         by either path.
       - The commit keeps the `!` of the plan. No name left a list and no signature changed,
         so a program that builds against 44h builds against 44i.
       - A point for the owner to rule: decision 156 ruling 14 says that the examples name the
         variable `client`. `examples/colibri_server.zig` keeps `http_client`, because this
         plan names no such change. 44l can name the variable in its two new examples.
       - Mutations, each against `zig build test-colibri`:
         - No `client` at the root, and no `server` at the root: each CAUGHT. The test of the
           names does not compile.
         - `client` that names the module `server`: CAUGHT by the test of the names.
  10. 44j `build`: Rotor lazy, the option `rotor`, `build_options`, and the compile error of
      `.private` with no Rotor. `tools/consumer/` passes `.rotor = true`.
      - Check: `tools/consumer_check.sh` builds a second consumer, of the protocol modules and
        `.hosted` alone, with an empty `--global-cache-dir`. No `rotor-*` folder may appear
        under `p/`. `zig build --fetch` must not fetch Rotor for it.
      - Done on 2026-11-10, as `8d858242`.
        - `build.zig.zon` marks Rotor lazy. `build/modules.zig` reads the option `rotor`, true
          at colibri's root and false for a dependent, and gives `colibri` a `build_options`
          value. The root imports `rotor_host*.zig` only when it is true.
        - `colibri.Server(_, .private)` and `colibri.Client(_, .private)` call
          `host.require_rotor`, which stops the compile with decision 159's message.
        - colibri's own build asks for Rotor whatever the option says, for `src/testing/` and
          `examples/`.
        - `tools/consumer/` passes `.rotor = true`. `tools/consumer_hosted/` is a second project
          of `h11` and the `.hosted` kind. `tools/consumer_check.sh` builds and runs it with a
          global cache that starts empty. It requires that neither the cache's `p/` nor the
          project's `zig-pkg/` holds Rotor, pepegrillo or `qifs`. A program of the project that
          names `.private` must fail with the message once for each type.
        - The first project is the control: its `zig-pkg/` must hold `rotor-*`.
        - Mutations, each against `tools/consumer_check.sh`, each CAUGHT: the option true for a
          dependent, and `.lazy` removed (each fetched Rotor); `require_rotor` removed (the
          program compiled); `tools/consumer/` with no option (colibri's message).
  11. 44k `test(lint)`: the rule `rotor-import`, the narrower `io` exemption,
      `colibri-hosted-check` and the canaries.
      - Check: `zig build lint` passes on the tree, and each canary gives its one finding.
      - Done on 2026-11-10, as `da27c89e`.
        - `tools/lint/rotor_import.zig` reads the parsed tree. In `build.zig` and `build/`, an
          `addImport("rotor", ...)` must name `colibri`, `testing`, `testing_client`,
          `testing_udp` or `example`, and a `dependency("rotor", ...)` is a finding. The
          examples' module and the UDP endpoint's module took those names.
        - Under `src/`, an `@import("rotor")` must be in `src/testing/` or in a file of
          `src/colibri/` whose name starts with `rotor_host`. The rule reads the import through
          pepegrillo's `imported_path`, not `forbidden_references`. That rule reads chains, so
          an import under another name would pass it.
        - The `io` rule exempts eleven paths of `src/colibri/` in place of the directory: the
          five files of the adapter, its two test files, and four loopback tests of
          `.private`, which run a peer on a thread. Decision 159 names the adapter alone.
        - `build/lint.zig` adds three canaries, each with its one finding and its place. A
          third run over the files the rule allows must exit 0.
        - `zig build colibri-hosted-check` builds `colibri` with no Rotor through
          `modules_colibri.add_without_rotor`. `hosted_init` of
          `src/colibri/loop_check_test.zig` runs, and `private_server_turn` and
          `private_client_turn` fail with colibri's message.
        - Mutations, each CAUGHT: `quic` allowed, `src/colibri/` exempt whole and the source
          part removed (each by a canary of `zig build lint`); a wrong prefix of the adapter
          (`zig build lint` on the tree); an eager fetch allowed and `io` exempting
          `src/colibri/` (each by `zig build test-tools`); `require_rotor` removed
          (`zig build colibri-hosted-check`).
  12. 44l `docs(colibri)`: two examples and docs/usage.md's section "Host colibri on your own
      loop".
      - `examples/colibri_hosted.zig` joins a hosted Server and a hosted Client through an
        in-memory host over `examples/link.zig`. It opens no socket and runs one seed.
      - `examples/colibri_shared_rotor.zig` is the program's adapter on one Rotor core loop,
        with a program timer that calls `set_destination` from 127.0.0.1 to `::1`. It binds
        loopback, as decision 96 as amended permits.
      - The sketches for `std.Io` and libxev go in docs/usage.md as `text` blocks.
        `tools/doc_snippets.sh` requires each Zig block to be an excerpt of an example.
      - docs/usage.md states the rule of one thread. docs/performance.md states that only
        `.private` has numbers (decision 32).
      - Checks: `zig build examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh`.
        Mutation: `set_destination` ignored, measured with `zig build
        example-colibri_shared_rotor`.
      - Done on 2026-11-10, as `cfd1fea6`.
        - `examples/colibri_hosted.zig` hosts a server and a client in memory over
          `link.zig`, with one seed. Two GETs run over h2 with TLS. The host opened no UDP
          socket, so neither object speaks h3.
        - `examples/colibri_shared_rotor.zig` has its adapter in about 140 lines. The program
          binds `::` before `init`, and the server's idle deadline of 20 ms closes the first
          connection. The program's timer then calls `set_destination` with ::1. The
          program requires the first connect to name an IPv4 address and the second an IPv6
          address.
        - The client's `connection: close` was the first plan, and the pool refuses that
          header (`error.FieldReserved`). So the idle deadline closes the connection.
        - docs/usage.md has the section "Host colibri on your own loop", with the rules of the
          host and the sketches for `std.Io` and libxev as `text` blocks. docs/performance.md
          states that only `.private` has numbers. README.md shows the `.hosted` types.
        - The examples name the variable `hosted_client`, not `client`, because `client` names
          the module that the root re-exports (decision 156 ruling 14).
        - Mutation: `set_destination` ignored, CAUGHT by `zig build
          example-colibri_shared_rotor` (`error.DestinationWrong`).
- **The checks.** `zig build test-colibri` for each commit, `zig build examples`,
  `tools/doc_snippets.sh`, `tools/consumer_check.sh`, `zig build colibri-loop-check`, `zig
  build colibri-hosted-check`, and the bench of 44c on the judge.
  The branch goes to main once, after 44l.
- **The run of step 44**, on macOS arm64 (kqueue) with Zig 0.16.0, on 2026-11-10. Before
  each of 44j, 44k and 44l, each of these returned 0: `zig fmt --check build.zig bench build
  examples src tools`, `zig build lint`, `zig build test`, `zig build examples`,
  `tools/doc_snippets.sh`, `tools/consumer_check.sh`, `zig build colibri-loop-check` and,
  from 44k, `zig build colibri-hosted-check`. `zig build lint-commits` returned 0 after each
  commit.
  - The mutations of 44c to 44l are in each entry above. Each NOT CAUGHT has its reason:
    `undrained` in 44g, and a loop made twice in 44h.
  - Not run: the bench on the judge, which owes `h2-many` and `h3-many` for 44c to 44h; the
    checks of `tools/ci.sh` that need Linux, Docker or the judge; and the TLA+ models.
- **The owner's rulings of 2026-11-10**, after the two reviews of step 44. Decision 159 as
  amended on that day lists them, with the session's decisions on the rest of the reviews'
  list. They replace these sentences of this entry:
  - "Each field has a default except `random`": `cpu`, `now`, and a client's `destination`
    and `pool` have none too (ruling 3).
  - "`pool`, `random` and `unix_seconds` stay": a hosted client takes `now`, a
    `server.Timestamp`, in place of `unix_seconds` (ruling 1).
  - "On `.private`, `init` binds, makes the loop": the loop is made at the first `run` or
    `fetch` (ruling 5).
  - "It calls no handler and writes no operation": a handler or a route may run inside a
    `complete` that gives a datagram (ruling 6).
  - "`.hosted`: `init` returns `server.StartError`": a hosted server returns
    `identity.LoadError || server.StartError`, and names it `InitError` (ruling 7).
  - "`.hosted` has no `RunError`": a hosted client names `RunError` and `FetchError`, and each
    is `error{}`.
  - "The `io` rule narrows its exemption from `src/colibri/` to `src/colibri/rotor_host*.zig`":
    the exemption covers 11 exact paths: the five files of the adapter, its two test files,
    and four loopback tests of `.private`.
  - "`user_data` is the `OperationId`": the adapter puts its own tag in the high 32 bits.
  - "A hosted server, which 44d adds, does no half-close" (44c): ruling 9 replaces the bridge.
- **The commits of the rulings**, on the replay of step 44 onto main, on macOS arm64 (kqueue)
  with Zig 0.16.0, on 2026-11-10:
  - `46848f28` `feat(colibri)!` (ruling 9): `Operation.Kind` gains `shutdown_send` and
    `Completion.Result` gains `shut_down`. The driver writes `shutdown_send` once a staged
    close has sent its response, keeps its receive, and closes at the engine's close. The
    Rotor adapter submits Rotor's shutdown of the send side, and the bridge of the replay
    goes: the adapter's own tag kind, `take_half_close`, `half_closed`, and the operations
    that the adapter held beside the driver's. The fake hosts and both examples handle the
    operation.
    - Mutations, against `zig build test-colibri`, each CAUGHT: `close` in place of
      `shutdown_send` (the loopback test over the Rotor adapter and three fake-host tests);
      no receive after it; Rotor's shutdown of both sides; its completion dropped;
      `finished()` ignores it.
    - `tools/h11_server_interop.sh`, in cleartext and with `--tls`, returned 0 on `46848f28`
      and on `a3a78431`. It runs `zig-out/bin/http-server`, the test-only server of
      `src/testing/`, whose own Rotor loop does the half-close. That server does not run
      colibri's driver, so a mutation of the driver cannot fail the script. The loopback test
      of `server_tcp_test.zig` is the check of the driver over a real socket.
  - `469538e4` `feat(server)!`
    ([#131](https://github.com/c4milo/colibri/issues/131)): `server.Instant{ ns,
    unix_seconds }` becomes `server.Timestamp{ unix_seconds, monotonic_ns }`, on the `server`
    root's list. Decision 158's amendment 19 records it. The rename adds no check, so no
    mutation ran.
  - `97d409c6` `feat(colibri)!` (ruling 1): a hosted `init` takes `now`, a `server.Timestamp`,
    and a hosted `cancel` takes `now_ns`. The client's run starts at `init` on `.hosted`, so
    its first `turn` no longer starts it.
    - Mutations, against `zig build test-colibri`, each CAUGHT: the server's engine started at
      0; the client's run started at 0; its Unix seconds 0; a hosted cancel at the instant of
      the last turn; a `.private` cancel at instant 0. The last one needed a new test, which
      drives a `.private` client's driver from a fake host.
  - `91cefc09` `feat(colibri)` (ruling 7): `Server.InitError`, on the `Server` list of both
    kinds.
    - Mutations, against `zig build test-colibri`, each CAUGHT: `InitError` removed (the
      compile of its test); the hosted set as `server.StartError` alone.
  - `a3a78431` `feat(client)!` (ruling 8): `colibri.Client.set_destination` and
    `client.ConnectionPool.set_destination` take `*const client.Destination`. The change adds
    no check. Mutation, against `zig build test-client`: the pool's call by value, CAUGHT by
    the compile of each caller.
  - This commit, `docs`: decision 159's amendment, decision 150's item 14, decision 156's
    ninth amendment, this record, and docs/usage.md's rules of the host.
  - Before each code commit, each of these returned 0: `zig fmt --check build.zig bench build
    examples src tools`, `zig build lint`, `zig build test`, `zig build examples`,
    `tools/doc_snippets.sh`, `tools/consumer_check.sh`, `zig build colibri-hosted-check`,
    `zig build colibri-loop-check` and `zig build bench-memory`, whose table did not change.
    `zig build lint-commits` returned 0 after each commit.
  - Not run: the bench on the judge, which still owes `h2-many` and `h3-many` for 44c to 44h;
    the checks of `tools/ci.sh` that need Linux or the judge; and the TLA+ models.
- **The reviews of the rulings**: two reviews of `0a57459a`, on main's `666d26db`, on
  2026-11-10. Each finding was checked against the code. The commits, on macOS arm64 (kqueue)
  with Zig 0.16.0:
  - `293b5990` `fix(colibri)`: a failed TCP socket of a server drained the engine inside its
    `complete`, so a route's `on_finished` ran there, against ruling 6. The engine's events
    now wait for the next turn. Two tests cover a failed shutdown, which ends the connection in
    the next turn, and the next connection of a socket, which takes no `half_closing` from the
    last one.
    - Mutations, against `zig build test-colibri`, each CAUGHT: the drain inside `complete`;
      no drain owed; a failed shutdown not passed to the engine; a reused entry that keeps
      `half_closing`.
  - `c30da7af` `fix(colibri)`: colibri halts with its message when the host's instant goes
    back: in `turn`, in `complete`, in a hosted `cancel`, and from the `now` of `init` (rule
    6). `zig build colibri-loop-check` gains five halt cases.
    - Mutations, against `zig build colibri-loop-check`, each CAUGHT: no halt; no check in the
      server's `turn` or `complete`, in the client's `turn` or `complete`, or in a hosted
      `cancel`; no `now` kept at a hosted client's `init`; a server's start that keeps
      instant 0.
  - `4c15a14a` `fix(colibri)`: the close of `examples/colibri_hosted.zig` ends a send that
    waits for room on the link (rule 1).
    - Mutation: the send not ended, NOT CAUGHT by `zig build example-colibri_hosted`. The
      example's two GETs never hold a send when a socket closes, and an example has no test.
      The driver's side, a close while a send is in flight, has its test in `socket.zig`.
  - This commit, `docs`: decision 158's amendment 20, decision 159's amendment, decision 160's
    item 6, the module graph of design §3, INV-2, the two sentences above, and the sketches
    of a host in docs/usage.md, which now do `shutdown_send`.
  - Not a gap: m11 of the first review, a half-close owed before the close_notify, is NOT
    CAUGHT by `zig build test-colibri`, because the driver steps the engine whole before it
    writes the shutdown. `zig build test-server` catches it in `engine_staged_close_test`.
  - For the owner: `client.ConnectionPool.init` takes its destination by value, which is over
    16 bytes. Ruling 8 names `set_destination` alone. Rotor's session does not know yet that
    the adapter uses Rotor's `Operation.shutdown`.
  - Before each code commit, each of these returned 0: `zig fmt --check build.zig bench build
    examples src tools`, `zig build lint`, `zig build test`, `zig build examples`,
    `tools/doc_snippets.sh`, `tools/consumer_check.sh`, `zig build colibri-hosted-check`,
    `zig build colibri-loop-check` and `zig build bench-memory`, whose table did not change.
    `zig build lint-commits` returned 0 after each commit.
  - Not run: the bench on the judge, which still owes `h2-many` and `h3-many` for 44c to 44h;
    the checks of `tools/ci.sh` that need Linux or the judge; and the TLA+ models.
