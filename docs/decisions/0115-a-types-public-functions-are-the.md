# Decision 115: A type's public functions are the calls a program makes, and a module's root exports the types a program names

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-04, who asked why so much of `server` and `client` was public, for
design §8 step 17f. It trims the types of decisions 100 and 103 and changes none of the calls a
program makes.
- Zig lets one file call another's function only when the function is `pub`. Each of the six
  types is split over several files to stay under 500 lines, so the calls its own files make
  of each other had become public methods beside the calls a program makes.
- A call that only the module's other files make is a free function that takes the type's
  pointer, in a file the root does not export: `connection_internal.zig` for each TCP
  connection, `quic_connection_internal.zig` for each QUIC connection, and
  `channel_events.zig` for the channel. `Endpoint` calls a connection through the server's
  `quic_connection_internal.zig`.
- A test beside each type lists its public functions by name, and a test beside each root
  lists what the root exports. A function made public, or a file exported, fails its test
  until the list names it.
- Each root exports `constants` whole (decision 35), and an alias for every type a program
  names: those its calls take and return, and those its configurations hold. It exports no
  other file. `server` exported nine files and `client` six.
- The public functions, before and after: `server.Connection` 25 and 16,
  `server.QuicConnection` 18 and 8, `server.Endpoint` 7 and 6, `client.Connection` 23 and
  11, `client.QuicConnection` 15 and 12, `client.Channel` 18 and 15.
- One call stays public for the simulator alone, and says so: `Channel.phase`, with the
  `ChannelPhase` and `ChannelEntry` the client trace reads (decision 105). The TCP trace
  called `write_owed` on the two TCP connections, and now calls `send` with no room, which
  writes what a connection owes and hands out nothing.

- Amended on 2026-10-04, when the owner asked for `quic` too. Its calls are functions of its
  files and not methods, and h3, `server`, `client`, the simulator, the corpus and the test
  endpoints name 121 of its declarations. `quic.zig` exports each of those under the
  namespace of the file that declares it, so `quic.connection_send.send` reads as before
  and no caller changed. It exports no file but `constants` and `error_code`. The root had
  58 names and has 40: the 18 files nothing outside named are gone from it, and so is every
  function only the module's own files call. `quic.Connection` keeps `init` and
  `addressed_by` as methods, and its six others became functions of `connection.zig`. The
  root's tests list its 40 names and resolve every name under them.
- Amended again on 2026-10-04, when the owner asked how to avoid a refactor of this size.
  The lists come first from now on: a step names a type's public functions and its root's
  exports before it writes them, starts with their tests, and shows each call in an example.
  CLAUDE.md holds the rules, under "The public API is written first".
- Amended a third time on 2026-10-04, when the owner asked for one convention in every
  module and for no name that repeats its file's, such as `http.field.Field`. The twelve
  other roots follow the rules now: they exported 72 whole files beside `constants` and
  export none. A script lists each name code outside a module uses, with aliases and
  re-exports followed, and each root is that list. A type named after its file is exported
  under its own name, so `http.Field`, `h2.Connection` and `quic.PeerAddress` replace
  `http.field.Field` and its like. A function or a constant keeps its file's namespace. A
  test variable two modules share is reached through a function, because a root cannot
  alias a `threadlocal`. The connections of h11, h2 and h3 keep as methods the calls made
  from outside their module: 13 of 16, 20 of 22 and 15 of 16.
- The lint rule `root-exports` refuses a root that exports a file whole, or that has no
  test listing its exports (`tools/lint/root_exports.zig`).
- The root is the module's API file. Zig has file-private and `pub` and nothing between, so
  a package's root file is where the Zig community draws the line: `zig init` calls it "the
  root source file when making a package". `std.zig` exports whole files, which works there
  because std keeps a type in one file, 1,867 lines for `http/Client.zig`, and its
  internals stay file-private. colibri's files stop at 500 lines, so its roots list names,
  as `std.crypto`'s does.

The alternatives refused:
- Leave the calls public and say in each comment who makes it. A reader of the type still
  sees twice the calls, and nothing stops a program from making one.
- For `quic`, methods on `quic.Connection`, as on `server` and `client`. About 600 call
  sites would change in five modules and the guide, for the same reachable names.
- For `quic`, dropping only the 18 unused files. The other files would stay exported whole,
  with each function their neighbours call.
- A file beside the root for the API, such as `server_api.zig`, which the owner asked
  about. The build needs the root, so the API would be written in two files that must agree.
- A file named after its type, `Connection.zig`, as the standard library has, which removes
  the repeated name inside the module too. It renames 57 files and moves each file's other
  declarations, and no dependent sees a difference.
- Stop at the two TCP connections. `server.QuicConnection` showed a program the ten calls
  its endpoint makes.
- One file for each type, which needs no `pub` between files. Each type passes 500 lines
  with its tests.
- Fewer calls, such as `should_close` folded into what `send` returns. It changes the loop a
  program writes, and the owner chose to keep the calls.
