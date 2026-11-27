# Decision 159: `colibri.Client` and `colibri.Server` take a host interface in colibri's own terms, and Rotor is one host

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-08 (design §8 step 44), for v0.16.0. The owner accepted this text on
the same day, with the answers at its end. This decision amends decisions 150 (rulings 3, 9 and 12),
156 and 158 (ruling 6). The owner cut v0.15.0 from main without step 44 on the same day, so this
decision ships in v0.16.0.

Context:
- Decision 156 put `*rotor.SharedLoop`, `rotor.BufferGroup` and `rotor.NamedSchedulingGroup`
  in the configuration of `.shared`. Its handler runs from a `rotor.Task`, and its work runs
  in a `rotor.Poller`.
- A program on libuv, libxev or `std.Io` cannot host such a type. A program that pins a
  second Rotor gets a second `SharedLoop` type, and the compiler refuses it.
- On the branch `step-44-rotor10` (32dd1b7a), 13 files of `src/colibri/` import Rotor. Rotor's
  `user_data` tags, `rotor.Operation` and `rotor.Event` go through `socket.zig`,
  `datagram_socket.zig`, `client_loop.zig` and `server_loop.zig`.
- Commit 44b put `error.BufferGroupsFull` in `RunError`. A loop that colibri owns never
  returns it.
- `server.Engine(capacity)` and `client.ConnectionPool(capacity)` are sans-I/O already. A
  program can host them today. `colibri.Server` and `colibri.Client` add about 1,700 lines
  of socket glue above them, where steps 37 to 42 found most of their defects.

The owner's rulings of 2026-11-08:
1. A `.shared` Client or Server takes a small interface in colibri's own terms: the
   operations that it needs, the completions in, and its next deadline. Rotor's loop is one
   adapter over it. A program on libuv, libxev or `std.Io` must be able to host
   `colibri.Client`. No Rotor type is in that public API. `.private` on Rotor stays the
   convenience of one call: `init`, `run` and `fetch`.
2. Rotor becomes a lazy dependency. A build fetches it only when a program uses the
   `colibri` module or the test endpoints. This amends decision 150.
3. A decision and a lint rule: `server`, `client`, `http`, `h11`, `h2`, `h3`, `quic` and
   `tls` never import Rotor. Only the `colibri` module and `src/testing/` may.
4. Rotor's core stays a library of a loop and its I/O. Its Seastar parts (tasks, pollers,
   scheduling, and completion records with callbacks) move to an optional layer in a later
   Rotor release. colibri's public API does not depend on those parts.
- The rules of decision 158 still apply: TigerStyle first, then Zig 0.16's std. No I/O
  outside `src/colibri/` and `src/testing/`. Time is a parameter (non-negotiable 3). One seed
  replays (non-negotiable 5).

The decision:
1. Each object of `colibri` has two parts:
   - The driver. It holds the socket glue, the engine or the pool, and the handler. It does
     no I/O, reads no clock and imports no Rotor. It writes the operations that it needs
     into storage that the caller owns, and takes their completions.
   - The host. It does each operation on its own loop, gives back each completion, and
     calls the driver again at the driver's deadline.
2. The kind `.shared` becomes `.hosted`. The program hosts colibri, and no loop is shared
   with colibri. The kind is still the second comptime argument, with no public name:
   `Client(capacity, kind)` and `Server(capacity, kind)` (decision 156 ruling 1).
3. `.private` is the driver plus colibri's own Rotor adapter, in a file that the root does
   not export. So both kinds run one code path, and the simulator and a fake host test the
   code that `.private` runs.
4. The interface is a value contract, not a vtable and not a type parameter. colibri never
   calls the host. The host calls colibri. So colibri holds no function pointer of the host,
   and a call never goes back into colibri from inside colibri.

The public API. The root adds seven names, in decision 115's order after `ClientConfig`:
`SocketId`, `OperationId`, `Operation`, `Completion`, `Failure`, `Wait` and `Turn`. Client
and Server share them, so they are top-level names (decision 158 ruling 6). No name holds a
Rotor type. A peer address is `server.Address`, the same type as `client.Address`
(`quic.PeerAddress`). The ECN codepoint is `server.Ecn` (`quic.Ecn`).

```zig
/// A socket in colibri's table. The host maps it to its own handle.
pub const SocketId = enum(u16) { _ };

/// Names one operation in flight. It uses the low 32 bits of a host's tag alone, so a
/// program that shares its loop keeps the high bits for its own tags. A generation byte
/// makes a completion that colibri does not hold a halt.
pub const OperationId = enum(u32) { _ };

pub const Operation = struct {
    id: OperationId,
    kind: Kind,

    pub const Kind = union(enum) {
        /// Open a TCP socket of the address's family, set TCP_NODELAY, and connect it.
        connect: struct { socket: SocketId, address: server.Address },
        /// Take one connection from `listener` into `into`, and set TCP_NODELAY.
        accept: struct { listener: SocketId, into: SocketId },
        /// Read into colibri's buffer. A read of 0 bytes means that the peer closed its side.
        receive: struct { socket: SocketId, buffer: []u8 },
        send: struct { socket: SocketId, bytes: []const u8 },
        /// Datagrams into the host's own memory. The host may complete it many times.
        receive_datagram: struct { socket: SocketId },
        /// `segment_bytes` of 0 is one datagram. Otherwise each segment is one datagram,
        /// which the host may send in one call (UDP_SEGMENT, design §8 step 13f.6).
        send_datagram: struct {
            socket: SocketId,
            bytes: []const u8,
            to: server.Address,
            ecn: server.Ecn,
            segment_bytes: u16,
        },
        close: struct { socket: SocketId },
        cancel: struct { target: OperationId },
    };
};

pub const Completion = struct {
    id: OperationId,
    /// True while a `receive_datagram` stays in flight. The last completion has false.
    more: bool = false,
    result: Result,

    pub const Result = union(enum) {
        connected,
        accepted,
        received: u32,
        sent: u32,
        /// The host's bytes. colibri reads them during `complete` and keeps no pointer.
        datagram: struct {
            bytes: []const u8,
            from: server.Address,
            ecn: server.Ecn = .not_ect,
        },
        datagram_sent: u32,
        closed,
        canceled,
        failed: Failure,
    };
};

/// colibri's words for an I/O failure. The host maps its own errors onto them.
pub const Failure = enum { refused, reset, unreachable_address, family_unsupported, closed, other };

/// The same three cases as `rotor.WaitLimit`, in colibri's terms.
pub const Wait = union(enum) { now, at_ns: u64, none };

/// What `turn` wrote and when the host calls it next.
pub const Turn = struct { operations: u32, wait: Wait };
```

`Server(capacity, .hosted)`:

```zig
pub const operations_max: u32; // the most operations in flight; a host sizes its table
pub const sockets_max: u16; // the size of the host's table of sockets
pub const listener: SocketId; // the TCP socket that the host opened before init
pub const datagram: SocketId; // the UDP socket that the host opened before init

pub fn init(self: *Self, config: *const HostedServerConfig, router: anytype, context: anytype) server.StartError!void;
/// Does the work of one turn and writes up to `operations.len` operations.
pub fn turn(self: *Self, now_ns: u64, operations: []Operation) Turn;
/// Records one result. It feeds a datagram to the engine at once, because the bytes are
/// borrowed. It calls no handler and writes no operation.
pub fn complete(self: *Self, completion: *const Completion, now_ns: u64) void;
pub fn shutdown(self: *Self) void;
pub fn stopped(self: *const Self) bool;
/// Asserts stopped(): each operation had its final completion. Wipes the keys.
pub fn deinit(self: *Self) void;
// run and port: a @compileError with colibri's message.
```

`Client(capacity, .hosted)` has the same `turn`, `complete`, `shutdown`, `stopped`,
`deinit`, `operations_max` and `sockets_max`, plus `request`, `cancel` and
`set_destination`. Its `datagram_ipv4` and `datagram_ipv6` are comptime `SocketId` values.
`run` and `fetch` are a `@compileError` with colibri's message.

The hosted configuration is a private type, which a program writes as a literal (decision
156 ruling 2). It is `ServerConfig` or `ClientConfig` with the I/O fields removed, plus:

```zig
// Server: the sockets that the host opened before init, and what the host can do on each.
sockets: struct {
    listener: bool = true,
    datagram: ?Features = null,
} = .{},
// Client: one UDP socket for each family. A family that the host could not open stays
// null, and the pool falls back to TCP for it (decision 156 ruling 13).
datagram: struct { ipv4: ?Features = null, ipv6: ?Features = null } = .{},
// Both: the program's source of randomness. It has no default on .hosted.
random: std.Random,

const Features = struct {
    /// The host sends a batch of equal segments in one call.
    segments: bool = false,
    /// The host reads and sets each datagram's ECN codepoint. When false, colibri sets the
    /// pool's `ecn` to false, so a host that cannot read the codepoint never halts on
    /// ECT(0) (this amends decision 68 for such a host).
    ecn: bool = false,
};
```

- Each field has a default except `random`. colibri copies what it keeps, and keeps no
  pointer to the configuration after `init` (decision 158 ruling 2).
- `buffer_group`, `scheduling_group` and `loop` leave the configuration.
- The host binds before `init`, in its own API. So a bind error is the host's error, at the
  host's call. `Server.port()` exists on `.private` alone, because a host knows its port.

The rules that bind a host. docs/usage.md states them, and colibri asserts each one that it
can see:
1. Each operation gets exactly one final completion, with `more = false`. An operation that
   a `cancel` or a `close` ends gets one too, with `.canceled` or its own result.
2. colibri frees a socket's slot only after each operation on it had its final completion.
3. One thread makes each call into an object. A completion from another thread goes through
   a queue that gives the order of happens-before. A `.hosted` object makes no thread check,
   because `gettid` is a system call on Linux. docs/usage.md states the rule.
4. The host never calls `turn` or `complete` from inside `turn`. The handler runs inside
   `turn`, so the `in_turn` flag of 44e makes such a call a halt.
5. After a `complete`, or after a program call such as `request`, `cancel`,
   `set_destination` or `shutdown`, the host calls `turn` before it waits.
6. `now_ns` never goes back. A completion with an id that colibri does not hold is a halt.

What `turn` does, in this order. These are the steps of decision 156's poller, with no
poller:
1. Pass a `shutdown` to the pool or the engine.
2. Call `on_instant` when a deadline is due.
3. Drain the events, and call `on_finished` and `on_connected` of the handler. A `request`
   from the handler leaves in the same turn.
4. Step each pending socket.
5. Write the receives, the accept, the sends and the UDP batches into `operations`.
6. Return `.now` while work is left or `operations` was full, `.at_ns` of the next deadline,
   or `.none` with neither. An idle colibri never makes the host spin.

The error sets:
- `.hosted`: `init` returns `server.StartError` or `client.StartError` alone. `.hosted` has
  no `RunError`.
- `.private`: `InitError`, `RunError` and `FetchError` spell colibri's own members, and the
  adapter maps Rotor's errors onto them. A change of a name in Rotor then breaks no
  dependent.
- `error.BufferGroupsFull` leaves `RunError`. The private adapter reserves its group on a loop
  that it just made, and uses 1 or 2 of Rotor's 16 ids. It writes
  `reserve_buffer_group() catch unreachable`, with a comptime assertion of the count. The
  test-only `udp.Endpoint` does the same.
- `error.PollersFull` leaves `InitError`, because colibri adds no poller.

The Rotor adapter of `.private`:
- It is `src/colibri/rotor_host.zig`, with `rotor_host_udp.zig` and `rotor_host_entropy.zig`
  when the file passes 500 lines. These are the only files of `colibri` that import Rotor.
  The root does not export them.
- It holds the `rotor.Loop` and its memory, `events[operations_max]`, a table of
  `rotor.Descriptor` for each `SocketId`, a table of `rotor.Handle` for each operation that
  a `cancel` can name, the buffer group of each UDP socket and its `Outbound` records. The
  group of 16 × 66 KiB moves out of `DatagramSocket` into the adapter, so its size does not
  change.
- `init` binds through `rotor.sync`, reserves and provides the group, and calls the
  driver's `init`. The entropy default of decision 150 ruling 9 lives here.
- `run` loops until `stopped()`. Each pass loads the stop flag with acquire order, calls
  `turn`, submits each operation, and ticks with a wait from `Wait`, capped at
  `stop_wait_ns_max`. Then it builds a `Completion` from each `rotor.Event`, calls
  `complete`, and gives back each datagram buffer.
- `user_data` is the `OperationId`. No other code submits on this loop.
- The adapter keeps the thread assertion of `shutdown` and of the other calls. The driver
  reads no thread id, because `gettid` is a system call on Linux.
- The Rotor calls that it uses are all in v0.10.0's core: `Loop.init`, `deinit`,
  `memory_bytes`, `submit`, `cancel`, `tick`, `now_ns`, `in_flight`, `cancel_all`, `drain`,
  `reserve_buffer_group`, `provide_datagram_buffers`, `datagram`, `give_back_buffer`,
  `release_buffers` and `rotor.sync.*`.
- It uses no `rotor.Completion` record, `Poller`, `Task`, `WaitLimit`, `SharedLoop`,
  scheduling group or `Registry`. So ruling 4's split of Rotor does not touch it, if Rotor's
  core keeps `BufferGroup`, `reserve_buffer_group`, `provide_datagram_buffers`, `datagram`,
  `give_back_buffer` and `Operation.receive_from`. Rotor's session was asked on 2026-11-08 to
  keep these in its core (answer 8 below).
- colibri exports no adapter for a shared Rotor loop. Such an export would put
  `*rotor.Loop` in colibri's API. `examples/colibri_shared_rotor.zig` shows the program's
  own adapter of about 120 lines. It puts its own tag in the high 32 bits of `user_data`,
  and sends each event of `tick` to colibri or to its other library by that tag.

Rotor is lazy. This amends decision 150 ruling 3.
- `build.zig.zon` marks `rotor` with `.lazy = true`. Its comment names the `.private` kind of
  `colibri`, `src/testing/` and `examples/`.
- Zig 0.16 decides each lazy fetch while the dependency's `build()` runs, before the
  dependent names a module. `b.lazyDependency` marks the package as needed and returns
  null, and the build runner fetches it and runs again. So a build option is the only signal
  that a dependent can give.
- `build/modules.zig` reads `b.option(bool, "rotor", ...)`. Its default is true when colibri
  is the root package (`b.pkg_hash.len == 0`) and false otherwise. Only when it is true
  does the build call `b.lazyDependency("rotor", ...)` and give `colibri` the import.
- A `build_options` value tells `colibri` whether Rotor is present. The root imports
  `rotor_host.zig` under a comptime condition, and Zig does not analyse a branch that it
  does not take. Without Rotor, `Client(_, .private)` and `Server(_, .private)` are a
  `@compileError`: "colibri: .private runs on Rotor; pass .rotor = true to
  b.dependency(\"colibri\", ...)".
- What a dependent fetches:
  - The protocol modules alone, or `colibri` with `.hosted`: chapulin and stdx. It fetches
    no Rotor, no pepegrillo and no `qifs`.
  - `colibri` with `.private`: chapulin, stdx and Rotor. The dependent passes `.rotor =
    true`.
  - colibri as the root package: Rotor too, for `src/testing/` and `examples/`.
- This breaks each build script that uses `.private` and passes no option: stompy, cocuyo
  and `tools/consumer/`. The release notes of v0.16.0 state the one line that each one adds.

The lint rule `rotor-import`, in `tools/lint/`, as decision 36 requires for colibri's own
rules. It has three parts:
1. The build. Over `build.zig` and `build/*.zig`, each `<receiver>.addImport("rotor", ...)`
   must name a receiver from a list that the rule spells out: `colibri`, `testing`,
   `testing_client`, `testing_udp` and the module of the examples. Each
   `dependency("rotor", ...)` must be `lazyDependency`. The rule reads the parsed tree, as
   `module_graph.zig` reads the imports of `quic`. A module with no import cannot compile
   `@import("rotor")`, so for `server`, `client`, `http`, `h11`, `h2`, `h3`, `quic` and `tls`
   the build is the proof.
2. The source. A file under `src/` that holds `@import("rotor")` must be in `src/testing/` or
   be `src/colibri/rotor_host*.zig`. This is stricter than ruling 3. The compiler cannot
   limit an import to some files of one module, so the rule does it. It keeps each Rotor
   type out of the driver. It uses pepegrillo's `forbidden_references` with a list of
   allowed paths.
3. The compile proof. `zig build colibri-hosted-check` builds `colibri` with `rotor =
   false`. A fixture of `Client(.{}, .hosted)` and `Server(.{}, .hosted)` must compile. A
   fixture of `.private` must fail with colibri's message. The name ends in `-check`, so
   `zig build test` runs it (`build/check_steps.zig`).
- The `io` rule narrows its exemption from `src/colibri/` to `src/colibri/rotor_host*.zig`.
  So the driver is sans-I/O again, and the `determinism` rule covers it.
- `build/lint.zig` gets one canary for each part: `quic.addImport("rotor", ...)`, an
  `@import("rotor")` in `src/server/`, and one in `src/colibri/client.zig`. A file
  `src/colibri/rotor_host.zig` with the import gives no finding.
- CLAUDE.md's list of lint rules names `rotor-import`.

What this decision amends:
- Decision 150:
  - Ruling 3: Rotor is a lazy dependency of `colibri`, fetched only for `.private`, the test
    endpoints and the examples.
  - Ruling 9: the entropy default applies to `.private` alone. `.hosted` takes the program's
    `std.Random`, with no default.
  - Ruling 12 is superseded. No configuration holds a `*rotor.SharedLoop`. The private loop is
    still made at `init`.
  - Ruling 7 stays for `.private`. The tests of `.hosted` run on an in-memory host and bind
    no socket.
- Decision 156:
  - Ruling 1 stays, with `enum { private, hosted }`. Its reason for no Loop type changes: the
    interface is colibri's own contract, so a fake host tests colibri and not a stand-in for
    Rotor.
  - Ruling 2: the field `loop` and the sixth amendment's `scheduling_group` go. The hosted
    configuration holds the sockets and their `Features`.
  - Ruling 3: colibri never waits on a hosted object. The host owns the wait.
  - Ruling 4 stays, and `turn` and `complete` on `.private` are a compile error too.
  - Ruling 5 stays.
  - Rulings 6, 7 and 8 are superseded. No record, no poller and no task. `turn` does the
    work and calls the handler. `turn` returns the `Wait`.
  - Ruling 9 stays, with the thread assertion on `.private` alone.
  - Ruling 10 is superseded. colibri counts its own operations, and `deinit` on `.hosted`
    asserts `stopped()`. No `release_buffers` and no `remove_poller` on `.hosted`.
  - Rulings 11, 12 and 13 stay.
  - Ruling 14: `loop_operations` becomes `operations_max`, and `sockets_max` joins it.
  - Ruling 15: colibri pins Rotor `v0.10.0` and uses its core alone.
  - The third and fifth amendments' group ids, and the limit of 16 objects on one loop, no
    longer apply to colibri.
- Decision 158 ruling 6: the error sets of `.hosted` and `.private` are as above.

This decision reverses two alternatives that decision 156 refused:
- "`start`, `on_events` and `wait_ns`. Every program would write the loop by hand." The
  owner's ruling 1 asks for this shape. A host now writes about 100 to 150 lines, once for
  each loop library, and `.private` keeps the one call.
- "Tags in `user_data`". colibri takes no range of bits. The program that shares a loop
  owns its tags, and the generation byte of `OperationId` makes a wrong route a halt.

Alternatives that lost:
- A vtable `LoopProvider`, in a new module, that colibri calls (design 2 of 2026-11-08).
  - A public module `colibri_rotor` would import Rotor, against ruling 3.
  - `loop_provider` adds a module and an edge to the graph.
  - Calls in both directions need re-entry rules, and each operation pays an indirect call
    on a hosted object.
  - Its shared Rotor adapter found colibri's events by the address of a slot and a magic
    word, so a program's pointer could take colibri's event.
- The pull shape with `operations`, `on_completion`, `on_datagram`, `next_deadline` and
  `on_deadline` (design 1 of 2026-11-08).
  - Five calls where two do the same work.
  - Its rule of one operation for each pair of socket and kind fails for UDP. A socket has up
    to `udp_batches` (16) sends in flight.
  - The host does `listen`, `bind` and `connect` as operations, so `done` mixes a port, a
    count and a descriptor in one `u32`.
  - Its names `on_*` read as callbacks, which colibri does not have.
- Keep decision 156's `.shared` on `*rotor.SharedLoop`. It breaks rulings 1 and 4.
- Drop the hosted kind from the release, and document how to host the engines. Each such
  program writes the 1,700 lines of socket glue again, where steps 37 to 42 found most
  defects.
- colibri asks the host to bind and to listen. The host then reports the bound port through
  a completion. The host already binds in its own API, and its errors are its own.
- An option that a dependent passes to get the `colibri` module at all, with a refusal module
  otherwise. A program on libxev that uses `.hosted` alone then still fetches Rotor.
- Rotor fetched for each dependent that names `colibri`. It needs no option, but a hosted
  program fetches a loop that it never runs.
- An export of colibri's Rotor adapter, `colibri.RotorHost`. It puts `*rotor.Loop` in the
  API, and ties the API to the Rotor pin.
- Datagram buffers that the host gets back from a call, as Rotor's `give_back_buffer` does.
  Each host then needs a pool of buffers. The bytes are valid during `complete` alone.

The new plan of design §8 step 44. Each commit passes `zig build test-colibri`. A mutation
that only fires an assertion is recorded as **NOT CAUGHT**, with the reason.
1. 44a `docs`: this decision, the amendments of decisions 150, 156 and 158, and a new entry
   for step 44.
   - Check: `zig build lint` (the Markdown rule) and `tools/doc_snippets.sh`.
2. 44b `build(colibri)`: the bump to Rotor `v0.10.0`. Done on 2026-11-08, and it stays.
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
5. 44e `feat(colibri)`: the `in_turn` flag, which now also guards `turn` and `complete`.
   - Test: a `fetch` from `on_finished` on `.private`, and a `turn` from the handler on
     `.hosted`, halt under the halt harness.
6. 44f `feat(colibri)`: one UDP socket for each family. On `.hosted`, each family is a field
   of the configuration.
   - Mutations: a send's socket not chosen by family; the second receive not written.
7. 44g `feat(colibri)!`: `destination` and `set_destination`. It stays.
8. 44h `feat(colibri)`: `fetch` and `cancel`. Its shared-loop tests become tests on the fake
   host.
9. 44i `feat(colibri)!`: the root re-exports `client` and `server`, and the lists of names
   run again.
10. 44j `build`: Rotor lazy, the option `rotor`, `build_options`, and the compile error of
    `.private` with no Rotor. `tools/consumer/` passes `.rotor = true`.
    - Check: `tools/consumer_check.sh` builds a second consumer, of the protocol modules and
      `.hosted` alone, with an empty `--global-cache-dir`. No `rotor-*` folder may appear
      under `p/`. `zig build --fetch` must not fetch Rotor for it.
11. 44k `test(lint)`: the rule `rotor-import`, the narrower `io` exemption,
    `colibri-hosted-check` and the canaries.
    - Check: `zig build lint` passes on the tree, and each canary gives its one finding.
12. 44l `docs(colibri)`: two examples and docs/usage.md's section "Host colibri on your own
    loop".
    - `examples/colibri_hosted.zig` joins a hosted Server and a hosted Client through an
      in-memory host over `examples/link.zig`. It opens no socket and runs one seed.
    - `examples/colibri_shared_rotor.zig` is the program's adapter on one Rotor core loop,
      with a program timer that calls `set_destination` from 127.0.0.1 to `::1`. It binds
      loopback, as decision 96 as amended permits.
    - The sketches for `std.Io` and libxev go in docs/usage.md as `text` blocks.
      `tools/doc_snippets.sh` requires each Zig block to be an excerpt of an example.
    - docs/usage.md states the rule of one thread (answer 6 below). docs/performance.md
      states that only `.private` has numbers (answer 9 below, decision 32).
    - Checks: `zig build examples`, `tools/doc_snippets.sh` and `tools/consumer_check.sh`.
      Mutation: `set_destination` ignored, measured with `zig build
      example-colibri_shared_rotor`.
- The branch goes to main once, after 44l.

The owner's answers of 2026-11-08. They replace the questions of the draft:
1. The kind is `.hosted`, not `.shared`. The name `.shared` never shipped.
2. The host opens the listener and the UDP sockets before `init`, in its own API.
   `Server.port()` exists on `.private` alone.
3. A build fetches Rotor only for `.private`. The build option `rotor` has a default of false
   for a dependent, and of true at colibri's own root. With the option false, `.private` is
   a `@compileError` with colibri's message. A program that uses `.private` passes
   `.rotor = true`.
4. Step 44 ships whole, not in parts after 44d. The owner first tied v0.15.0 to it. Later
   on 2026-11-08 the owner cut v0.15.0 from main without step 44, which ships in v0.16.0.
5. The module of the examples keeps its import of Rotor (decision 96).
6. A `.hosted` object makes no thread check, because `gettid` is a system call. The host
   passes no thread id. docs/usage.md states the rule of one thread.
7. The error sets of `.private` spell colibri's own members, not Rotor's sets.
8. Rotor's session was asked to keep these in Rotor's core: `Loop`, `tick`, `Event`,
   `Operation` with `accept`, `accept_multishot`, `connect`, `receive`, `send`, `close`,
   `receive_from` and the UDP send with segments and ECN, `BufferGroup`,
   `reserve_buffer_group`, `provide_datagram_buffers`, the datagram view and
   `give_back_buffer`.
9. docs/performance.md states that only `.private` has numbers (decision 32). A host with no
   GSO, GRO or ECN serves h3 at a lower rate.

Amended by the owner on 2026-11-10, after the two reviews of step 44. The owner's rulings:
1. Time on `.hosted` is a value that the host passes (non-negotiable 3).
   - A hosted `init` takes `now`, a `server.Timestamp`, in its configuration. A server's
     engine starts at it. A client's Unix seconds count from it, and its run starts at it.
   - A hosted `Client.cancel(id, now_ns)` takes the host's instant. `.private` keeps
     `cancel(id)`, at the instant of the last turn of colibri's loop.
2. `Completion.datagram.bytes` is `[]u8`, not `[]const u8`. The host lends its buffer for
   one `complete`, and colibri may write into it, because QUIC removes its packet
   protection in place (RFC 9001 §5). docs/usage.md tells hosts.
3. Some fields of the hosted configurations have no default, and they stay so: `cpu`
   (decision 97), `random`, `destination`, `pool` and `now`. No value is right to assume
   for any of them. They are the exceptions to "Each field has a default except `random`"
   above. The ruling names `cpu`, `host`, `pool` and `unix_seconds`: no hosted
   configuration has a field `host`, and ruling 1 puts `unix_seconds` into `now`. Decision
   161 adds `colibri.ServerConfig.unix_seconds` to the fields with no default, for the same
   reason.
4. `Client.deinit` after a `fetch` waits for each exchange of `request` to end. Only the
   pool's deadlines bound the wait, and colibri adds no limit. docs/usage.md says so.
5. The `.private` loop is made at the first `run` or `fetch`, not at `init`. So `init` may
   run on another thread than `run`. This amends decision 150 ruling 12, as decisions 156
   and 159 amended it, and the sentence "The private loop is still made at `init`" above.
6. A handler or a route may run inside a `complete` that gives colibri a datagram, while
   the host lends the bytes. Neither may call `turn` or `complete`. This replaces "It calls
   no handler and writes no operation" in the API above.
7. `Server` exports `InitError` on both kinds, on its names list. A hosted server's `init`
   returns `identity.LoadError || server.StartError`, in place of "`server.StartError`
   alone" in the error sets above. `Client` names its `InitError` on both kinds already.
8. `colibri.Client.set_destination` and `client.ConnectionPool.set_destination` take
   `*const client.Destination`, because the argument is over 16 bytes (TigerStyle). The
   change breaks each caller, in v0.16.0. The owner ruled later the same day that
   `client.ConnectionPool.init` takes its destination as `*const client.Destination` too.
9. The host contract closes a write side, so a hosted server closes an h11 connection in
   stages too (decision 160).
   - `Operation.Kind` gains `shutdown_send: struct { socket: SocketId }`. The host shuts
     down the write side of the socket, as shutdown(2) with SHUT_WR does. The receive on
     that socket goes on, and a `close` follows.
   - `Completion.Result` gains `shut_down`.
   - colibri's Rotor adapter does it with Rotor's shutdown of the send side. The bridge of
     the replay of 2026-11-10 goes: the adapter's own tag kind, `take_half_close`,
     `half_closed`, and the operations that the adapter held beside the driver's.

The session's decisions of 2026-11-10 on the rest of the reviews' list:
- A failure or a cancel of a `receive_datagram` ends it with `more = false`. Only a
  `.datagram` result may carry `more = true`. The driver asserts it, and host.zig and
  docs/usage.md state it.
- colibri's adapter puts its own tag in the high 32 bits of `user_data`, and the
  `OperationId` in the low 32 bits. A host may do the same. This replaces "`user_data` is
  the `OperationId`" above.
- The source part of `rotor-import` reads the import with pepegrillo's `imported_path`, not
  with `forbidden_references`. `const r = @import("rotor")` passes `forbidden_references`,
  which reads chains such as `rotor.Loop`. This replaces "It uses pepegrillo's
  `forbidden_references`" in the lint rule above.
- The `io` exemption covers 11 exact paths: the five files of the adapter, its two test
  files, and four loopback tests of `.private` that open sockets. pepegrillo's `Scope`
  names exact paths, so a new file of the adapter joins the list. This replaces the
  exemption of `src/colibri/rotor_host*.zig` alone in the lint rule above.
- The adapter of `examples/colibri_shared_rotor.zig` is about 140 lines, not 120. The
  generic type scored 41 on cognitive complexity, so it became free functions.
- The examples name the variable `hosted_client`, because `client` names the module that
  the root re-exports. `examples/colibri_server.zig` names it `http_client`. This amends
  decision 156 ruling 14.
- A hosted server's `init` returns `error.IdentityInvalid` too, through
  `identity.LoadError` (ruling 7). A hosted client's `init` returns `client.StartError`
  alone: 44g gave it a `client.Destination`, so it parses no host.
- A hosted server names its h3 alternative in `engine.h3_alternative` itself, because its
  host knows the port and colibri does not (RFC 7838 §3).
- A hosted client's `RunError` and `FetchError` are `error{}`. This replaces "`.hosted` has
  no `RunError`" in the error sets above.
- A `cancel` operation carries its target's id and gets no completion of its own.
- `.private` keeps the error at `init` when the system refuses the UDP socket of the
  destination's family. The socket of the other family may fail with no error, and an
  open of QUIC to that family falls back to TCP (decision 156 ruling 13).
- On `.hosted`, the pool's ECN and segments hold only when each UDP socket that the host
  opened has them, because `set_destination` can change the family. The session's first
  text said the `Features` of the destination's family.
- Rotor's decision 33, proposed, adds a call `wait_until` to Rotor's core. colibri does
  not use it.

The two reviews of these rulings, on 2026-11-10, found these. The code and the records now
agree with this decision:
- A failed TCP socket of a server ended its connection inside its `complete`, so a route's
  `on_finished` ran there, against ruling 6. The engine's events now wait for the next
  turn. Only a `complete` that gives a datagram runs a handler or a route.
- colibri halts with its message when the host's instant goes back: in `turn`, in
  `complete`, in a hosted `cancel`, and from the `now` of `init` (rule 6). Only a hosted
  `cancel` asserted it before.
- colibri's Rotor adapter submits Rotor's `Operation.shutdown` of the send side for
  `shutdown_send` (ruling 9). It is in Rotor v0.10.0's core. It joins the Rotor calls that
  the adapter uses, and the parts of answer 8 that Rotor's core must keep.
