# Decision 156: `colibri.Client` and `colibri.Server` run on a Rotor loop that the program may share

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-06 (design §8 step 44), for v0.15.0, and amended by the owner the same
day. On 2026-11-08 the owner cut v0.15.0 from main without step 44, so this decision ships in
v0.16.0, and each "v0.15.0" below reads as v0.16.0. A program that runs colibri beside another
library, such as a resolver, needs one Rotor loop on one thread for both. Rotor's decision 26
(`docs/decisions/0026-a-shared-loop.md` in https://github.com/c4milo/rotor) gives each operation a
completion record, which the tick calls. Rotor's decision 27 adds `rotor.Task`, and rules that only
the program ticks a shared loop. It answers [rotor#14](https://github.com/c4milo/rotor/issues/14).
Rotor's b5a7804 adds `release_buffers`, which takes a buffer group's buffers back
([rotor#13](https://github.com/c4milo/rotor/issues/13)). This decision amends decisions 96, 150
(rulings 6 and 7) and 153 (rulings 8 and 9).

The rulings:
1. A generic type takes the name of the thing itself, as Zig's std names `std.ArrayList(T)`
   and `std.BoundedArray(T, n)`. `colibri.Client(capacity, loop)` and
   `colibri.Server(capacity, loop)` are type functions, and a program writes
   `colibri.Client(.{}, .private)`.
   - `ClientOf` and `ServerOf` shipped in v0.14.0, and v0.15.0 removes them from the root's
     list. `Client` and `Server` were the types of the default capacity in v0.14.0, and
     v0.15.0 makes them the type functions.
   - The second comptime argument, `loop`, names the owner of the loop. Its type is
     `enum { private, shared }`, with no public name.
   - A capacity holds comptime sizes alone. `ClientCapacity` holds `quic`, `tcp_connections`
     and `requests`. The first argument of `Server` stays a `server.Capacity`.
   - colibri takes no Loop type parameter, for the reasons that follow.
   - The completion records, the pollers, the tasks and their dispatch are Rotor's
     behaviour. A stand-in loop must copy them, so its tests prove the stand-in and not
     Rotor.
   - `src/colibri/` binds loopback (decision 150 ruling 7), so each test runs a real
     `rotor.Loop`.
   - A Loop type can come later as a third argument.
2. The configuration follows the capacity.
   - With `.shared`, the configuration that `init` takes requires the field
     `loop: struct { rotor: *rotor.SharedLoop, buffer_group: ?rotor.BufferGroup = null }`.
     `rotor` has no default. The program gets it from `loop.shared()` (Rotor's decision 28).
   - A program may pass a `buffer_group` that it reserved with `reserve_buffer_group`. When
     the field is null, colibri calls `reserve_buffer_group` at `init`. A literal id fails to
     compile (Rotor's decision 29, with the names of Rotor's decision 30).
   - Each Client and each Server on a shared loop holds one of the loop's 16 group ids until
     the loop's `deinit`. Past 16, `init` returns `error.BufferGroupsFull`.
   - With `.private`, the configuration has no `loop` field. colibri makes the loop at `init`,
     owns it and reserves its own group.
   - The configuration of `.shared` is a private type. A program writes it as a literal, so
     it needs no new public name. `ClientConfig` and `ServerConfig` stay the configurations
     of `.private`.
   - The `server` module owns no I/O and knows no loop, so `server.Capacity` holds no loop
     kind. The kind is the second argument of `colibri.Server`.
3. Only the program ticks a shared loop. colibri never calls `tick` on a loop that it does
   not own (Rotor's decision 27). `rotor.SharedLoop` refuses `tick` at compile time (Rotor's
   decision 28). On a shared loop, colibri submits its operations and
   returns. It does its work in its completion records, its poller and its Rotor task.
4. `run` and `fetch` exist only for an object whose loop colibri owns. On a type whose
   `loop` is `.shared`, a call of `Client.run`, `Client.fetch` or `Server.run` is a
   compile error with colibri's message. The names stay on each type's list. On a private
   loop, `run`, `fetch` and `deinit` tick the loop, and an event with no completion record
   halts with a message.
5. `init` takes the handler or the router, so no event comes before one exists.
   - `Client.init(config, handler)` takes a pointer to the program's struct, or null for a
     client that only fetches. The struct declares `on_finished` and may declare
     `on_connected`.
   - `Server.init(config, router, context)` and `Server.run()` replace v0.14.0's
     `Server.init(config)` and `Server.run(router, context)`. `Client.run()` takes no handler.
6. `init` binds, reserves a buffer group when the configuration names none, provides the
   group, arms the receives and the accept, and adds one `rotor.Poller`. Each operation names
   a `rotor.Completion` in colibri's own struct. A callback only records the result. The
   poller does the work of a turn: the deadlines, the drain, the steps, the arms and the
   flush.
   - The poller returns a `rotor.WaitLimit` (Rotor's decision 29). It returns `.now` only
     when work is left, so an idle colibri never makes the loop spin.
   - Otherwise it returns `.at` of colibri's next deadline, or `.none` when no deadline
     exists.
   - The poller reads `loop.now_ns()`. A tick that waits reads the clock again after its
     wait and before the records (Rotor's decision 9 rule 4 as amended). The pollers see
     that reading, the last of the tick.
7. The handler runs from a Rotor task, not from the poller. The poller copies each event for
   the handler, and schedules the client's one `rotor.Task` with `loop.schedule_in` (Rotor's
   decision 30). Design §8 step 44 holds open the group that it names. Rotor runs
   a task that a record or a poller queues in the same tick, after the records. The task
   calls `on_finished` and `on_connected`. So the program's code never runs inside a poller,
   where Rotor refuses `add_poller` and `remove_poller`.
8. The poller's `WaitLimit` bounds the wait of each tick at colibri's next deadline. So a
   long wait in another library's tick does not delay a deadline, and colibri arms no timer.
   - On a shared loop, only the loop's thread calls `shutdown` (ruling 9). colibri keeps no
     flag for another thread, posts no `rotor.Message.wake` and takes no `rotor.Remote`.
   - On the loop's thread, `shutdown` changes colibri's state directly. The next tick calls
     the poller before it waits, so the poller sees the new state first. This applies to a
     `shutdown` from the handler too.
   - To stop colibri on a shared loop, the program wakes its loop by its own means. Code on
     the loop's thread then calls `shutdown`, and the program ticks until `stopped()`.
   - On a private loop, any thread may call `shutdown`, which stores colibri's flag. `run`
     and `fetch` tick with a wait of `stop_wait_ns_max` (50 ms), so the stop takes effect
     within 50 ms.
   - colibri's private loop has no registry, so no thread can post a wake to it.
9. One thread runs a colibri object for its whole life: `init`, `run`, `fetch`,
   `set_destination`, `cancel` and `deinit` run on the loop's thread.
   - On a shared loop, `shutdown` runs on the loop's thread too, and colibri asserts the
     thread.
   - On a private loop, `shutdown` is the one call another thread may make.
   - colibri makes its private loop at `init`, not at `run`.
10. colibri counts its own operations and cancels only its own handles. `rotor.SharedLoop`
    refuses `cancel_all` at compile time (Rotor's decision 28), so colibri cannot call it on
    a shared loop.
    - On a shared loop, `deinit` does not tick. It asserts `stopped()`. The program reaches
      `stopped()` when it calls `shutdown` and ticks the loop until `stopped()` returns true.
    - `stopped()` is true only when no operation and no task of colibri is in flight. So
      `release_buffers` is valid, because the group's last operation had its final event.
    - `deinit` then removes the poller and takes the buffers back with `release_buffers`.
      The group id stays reserved until the loop's `deinit`, because no Rotor call gives an
      id back (Rotor's decision 29).
    - Rotor's `deinit` halts while a poller or a task is still queued, so the program calls
      colibri's `deinit` before the loop's `deinit`.
    - On a private loop, `deinit` calls `shutdown` and ticks until `stopped()` when the program
      did not.
11. `ClientConfig.destination`, a `client.Destination`, replaces `host` and `port`.
    `Client.set_destination` gives the pool new addresses, for example from a resolver's
    callback. colibri resolves nothing (decision 100).
12. `Client.fetch(options)` runs one exchange on a private loop, and ticks the loop until it
    finishes.
    - `FetchOptions` has the shape of `std.http.Client.fetch`, with no heap and with decision
      126's words: `method`, `path`, `headers`, `never_indexed`, `request_body`,
      `response_body`, `response_headers` and `response_trailers`.
    - `FetchResult` holds `result`, `status`, `headers`, `trailers` and `body_len`. A protocol
      failure is a `result`, not an error (decision 126).
    - `Client.cancel(id)` ends one exchange, and the handler gets no `finished` for it.
13. With QUIC offered, the client opens one UDP socket for each family, both on its one buffer
    group. An open to a family that the system refuses falls back to TCP.
14. The root re-exports the modules `client` and `server`. Each type declares
    `loop_operations`, so a program can size a shared loop. The examples name the variable
    `client`.
15. Rotor's main holds the code of decision 26 at d1657ce and of decision 27 at a03d95d.
    The owner accepted Rotor's decisions 28 and 29 on 2026-11-06, at 1dfccaf. Rotor's
    decision 29 rules that both land before Rotor's next tag, `v0.10.0`.
    - colibri pins Rotor's tag `v0.10.0`, which carries Rotor's decisions 26 to 30 and 32
      (fifth amendment). v0.15.0 waits for it.
    - On 2026-11-06 Rotor had no such tag, because the owner first makes Rotor's reactor
      architecture stable.

Amended by the owner on 2026-11-06, as Rotor's session first relayed it and the owner then
confirmed it. The first text let any library tick the loop, and let colibri's `run`, `fetch`
and `deinit` tick a shared loop. It put `loop: ?*rotor.Loop = null` and a `buffer_group`
with no default in each configuration, and called the handler from the poller. Rulings 1
to 4, 7 and 10 replace that text, and ruling 2 settles the `buffer_group` that the first
text left to commit 44d.

Amended again by the owner on 2026-11-06. The first amendment put the loop kind in a field
`loop` of `ClientCapacity` and of a new `colibri.ServerCapacity`, and kept `ClientOf` and
`ServerOf`. Ruling 1 replaces that text: the kind is the second comptime argument of
`Client` and `Server`. Rulings 1 and 2 drop `colibri.ServerCapacity`, which never shipped.

Amended a third time by the owner on 2026-11-06, after he accepted Rotor's decisions 28 and
29 (`docs/decisions/0028-correct-use-and-stalls.md` and
`docs/decisions/0029-what-libraries-ask-of-a-shared-loop.md`, Rotor's 1dfccaf). Decision 28
gives a library the view `*rotor.SharedLoop`, which refuses `tick`, `drain`, `deinit`,
`cancel_all` and `discard_tasks` at compile time. Decision 29 adds `rotor.WaitLimit`,
`rotor.Message.wake`, `rotor.BufferGroup` and `reserve_group`. The owner ruled three changes:
1. The `.shared` configuration's field becomes
   `loop: struct { rotor: *rotor.SharedLoop, buffer_group: ?rotor.BufferGroup = null }`. A
   program may pass a group that it reserved with `reserve_group`. When the field is null,
   colibri calls `reserve_group` at `init`.
2. The one-shot timer of ruling 8 and its wake of 50 ms go. The poller returns `.at` of the
   next deadline, `.now` when work is left, and `.none` when it is idle with no deadline.
3. Each colibri object on a shared loop holds one of the loop's 16 group ids until the loop's
   `deinit`. Past 16, `init` returns `error.GroupsFull`. docs/usage.md states it once step 44
   is built.

Rulings 2, 3, 6, 8, 10 and 15 above hold these changes. The text that they replace:
- Ruling 2 held a `*rotor.Loop` and a `buffer_group: u16` with no default.
- Ruling 6 had a poller that returns true when work is left.
- Ruling 8 armed a one-shot timer with a record, at most `stop_wait_ns_max` ahead.
- Ruling 10 gave the group back with `release_buffers`. Now the call takes the buffers back,
  and the id stays reserved.
- Ruling 15 pinned Rotor's next tag. Now it names the tag that carries decisions 26 to 29.

Amended a fourth time by the owner on 2026-11-06. The third amendment let another thread
call `shutdown` on a shared loop. That call stored a flag and posted `rotor.Message.wake`,
and design §8 step 44 held open which call posts the wake. Rulings 8 and 9 replace that
text. On a shared loop, only the loop's thread calls `shutdown`, as it calls `init`, `cancel`
and `deinit`.

Amended a fifth time, on 2026-11-07, from Rotor's records. This amendment records facts and
makes no new colibri ruling. Rotor's session reported on 2026-11-07, as the owner ruled, what
Rotor's tag `v0.10.0` carries. Fact 1 comes from that report. Facts 2 to 8 were read on
Rotor's main at e57019e and 4ad0d91:
1. Rotor's session reported that `v0.10.0` carries Rotor's decisions 28, 29, 30 and 32, and
   not decision 31. No Rotor record names the tag beside decisions 30 and 32: Rotor's
   decision 29 names it for decisions 28 and 29 alone. Decisions 26 and 27 came after
   `v0.9.0` (d1657ce, a03d95d), so the tag carries them too. Decision 28 is on Rotor's main.
   Decisions 29, 30 and 32 are accepted and not built. Rotor's build order is W3 (the fair
   tick order), decision 29, decision 30, then decision 32. No commit on Rotor's main builds
   W3.
2. Rotor's decision 30 renames two names of decision 29 before decision 29 is built.
   `reserve_buffer_group` replaces `reserve_group`, and `error.BufferGroupsFull` replaces
   `error.GroupsFull`. `rotor.BufferGroup` keeps its name. No Rotor tag holds `reserve_group`.
   Ruling 2 and design §8 step 44 use the new names in every place.
3. Rotor's decision 30 adds scheduling groups. `rotor.SharedLoop` refuses `schedule` at
   compile time, so a library names a group in each `schedule_in(group, task)`. The program
   declares or reserves each group, and gives each library its group at `init`. Group 0 is
   `.default`. So colibri's task runs in a group that colibri's source names. Design §8 step
   44 holds open which group that is.
4. A program declares `rotor_scheduling_groups` in its root file only to name a group by name.
   Rotor's decision 30 marks this declaration and the named groups "not ruled".
   Rotor's public module reads the declaration, and the set of names is empty when the root
   declares none. A program that names no group declares nothing. A test's root is Zig's test
   runner, which declares no names.
5. Rotor's decision 32 adds a cross-core call. Each call names a `rotor.NamedSchedulingGroup`,
   `.default` included, and runs as a task in that group on the target. Rotor's decision 32
   marks this part "not ruled", because it uses the named groups. colibri makes no
   cross-core call, so decision 32 changes no colibri call. It lowers `message_tag_max` to
   `0x7fff_effd`, and the room for a post in a mailbox from 256 to 224 messages.
   `examples/link.zig` posts tag 1.
6. Rotor's decision 28 names each record, poller and task in its `init`, from
   `@typeName(Parent)` and the field. colibri's task takes its name from `Task.init`, with no
   new parameter.
7. Rotor's cee1474 keeps the descriptor that wakes each loop in its `Registry` until
   `Registry.close_wakes`. A program calls `close_wakes` after each loop and remote of the
   registry ended. colibri's private loop has no registry and claims no wake, so the rule does
   not apply to it. `examples/link.zig` makes a registry, so it calls `close_wakes`.
8. Rotor's 782d6de makes a `close` wait for each file operation on its descriptor that the
   offload's workers hold. colibri uses no offload and submits no file operation, so its
   closes do not change.

The text that the fifth amendment replaces:
- Ruling 2 named `reserve_group` and `error.GroupsFull`.
- Ruling 7 scheduled the task with `loop.schedule`.
- Ruling 15 pinned the Rotor tag that carries decisions 26 to 29.
- The third amendment keeps the names of its day, `reserve_group` and `error.GroupsFull`.

Amended a sixth time by the owner on 2026-11-07, on the scheduling group of colibri's task:
1. The configuration of `.shared` gains the field `scheduling_group`, with a default of
   `.default`. A program that uses no groups writes nothing new.
2. The field is a `rotor.NamedSchedulingGroup`, as Rotor's own example of its decision 30
   passes a library. Rotor marked the named groups "not ruled", so step 44d waited for Rotor's
   ruling on them. Rotor ruled them on 2026-11-07, in its decisions 30 and 32 at 0c1fcf7.
3. `Client` and `Server` both take the field on `.shared`. `Server` holds no task today, so
   a task that it adds later breaks no configuration. On `.private`, colibri names
   `.default`, and its configuration has no such field.

Alternatives that lost the sixth amendment:
- A field with no default. Each program would name `.default` to say nothing.
- A `rotor.SchedulingGroup`, which needs no Rotor ruling first. The owner chose the type that
  Rotor's example gives a library.
- The field on `Client` alone. A task in `Server` would then break its configuration.

Amended a seventh time, on 2026-11-08, from Rotor's tag. This amendment records facts and
makes no new colibri ruling:
1. Rotor's `v0.10.0` is the tag on 933985882d693e4d8b876e1403618a3fc6d989ef, and Rotor's CI
   passed on it. It carries Rotor's decisions 26 to 30 and 32.
2. The tag carries the nine renames of Rotor's API audit, which amend Rotor's decision 1:
   - `Operation.accept` takes no `multishot` flag, and `Operation.accept_multishot` is new.
   - Each tag enum `Code` becomes `Tag`, and `Operation.code()` becomes `Operation.tag()`.
     `rotor.Code` stays the failure code.
   - `Registry.close_wakes` becomes `Registry.deinit`, and `Registry.loops()` becomes
     `Registry.loop_count()`.
   - The root exports `rotor.Offload` and `rotor.Statistics`. `Offload.memory_bytes` takes
     the count of workers.
   - `Loop.heartbeat()` returns a `rotor.Heartbeat` view that declares `watch` alone.
   - A `Work` runs through `work.run(worker)`.
   - `Loop.init` and `Loop.memory_bytes` take a `*const Options`.
   - `Loop.AddPollerError` and `Loop.ScheduleError` are declarations of `Loop`.
3. Rotor's decision 30 sets two defaults: a group's shares are 100, and `task_charge_max` is
   64. Rotor's decision 32 takes the request and the reply of a call by `*const`.
4. Fact 7 of the fifth amendment names `Registry.close_wakes`. The call is now
   `Registry.deinit`, so `examples/link.zig` calls `registry.deinit()` after its loops end.

Amended an eighth time, by decision 159 on 2026-11-08. A `.shared` object put Rotor's types in
colibri's public API, and a program on another loop could not host it. Decision 159 replaces
the kind `.shared` with `.hosted`, which takes a host interface in colibri's own terms:
- Ruling 1 stays, with `enum { private, hosted }`. Its reason for no Loop type changes: the
  interface is colibri's own contract, so a fake host tests colibri and not a stand-in for
  Rotor.
- Ruling 2: the field `loop` and the sixth amendment's `scheduling_group` go. The hosted
  configuration holds the sockets and their `Features`.
- Ruling 3: colibri never waits on a hosted object. The host owns the wait.
- Ruling 4 stays, and `turn` and `complete` on `.private` are a compile error too.
- Ruling 5 stays.
- Rulings 6, 7 and 8 are superseded. There is no record, no poller and no task. `turn` does
  the work, calls the handler and returns the `Wait`.
- Ruling 9 stays, with the thread assertion on `.private` alone.
- Ruling 10 is superseded. colibri counts its own operations, and `deinit` on `.hosted`
  asserts `stopped()`. `.hosted` calls no `release_buffers` and no `remove_poller`.
- Rulings 11, 12 and 13 stay.
- Ruling 14: `loop_operations` becomes `operations_max`, and `sockets_max` joins it.
- Ruling 15: colibri pins Rotor `v0.10.0` and uses its core alone.
- The third and fifth amendments' group ids, and the limit of 16 objects on one loop, no
  longer apply to colibri.
- Decision 159 reverses two alternatives that lost below: "`start`, `on_events` and
  `wait_ns`" and "Tags in `user_data`". Its text gives the reasons.

Amended a ninth time, by decision 159 as the owner amended it on 2026-11-10:
- Ruling 9: `init` may run on another thread than the loop's, because colibri makes its
  private loop at the first `run` or `fetch`, not at `init` (decision 159, ruling 5 of
  2026-11-10).
- Ruling 11: `set_destination` takes `*const client.Destination` (ruling 8 of 2026-11-10).
- Ruling 12: `cancel(id)` stays on `.private`. A hosted client's `cancel(id, now_ns)` takes
  the host's instant (ruling 1 of 2026-11-10).
- Ruling 14: the examples cannot name the variable `client`, because `client` names the
  module that the root re-exports. `examples/colibri_hosted.zig` and
  `examples/colibri_shared_rotor.zig` name it `hosted_client`, and
  `examples/colibri_server.zig` names it `http_client`.

Alternatives that lost:
- Tags in `user_data`, with `LoopIds` and `Host`, in the first draft of this decision. Each
  library needs an agreed range of bits. A wrong tag takes another library's events with no
  halt. Two routers on one loop still need one owner of `tick`.
- Any library ticks the loop, in the first text of ruling 7. Rotor's decision 27 rules that
  only the program ticks a shared loop.
- `loop: ?*rotor.Loop = null` in each configuration, in the first text of ruling 1. A
  `fetch` or a `run` on a shared loop was then a halt at run time, not a compile error. A
  program on a private loop also had to set a `buffer_group` that colibri does not read.
- `deinit` that ticks a shared loop until colibri stops. It breaks ruling 3.
- `deinit` that cancels colibri's handles and returns before their final events.
  `release_buffers` is valid only after the group's last operation had its final event, so
  colibri would need a second call to end.
- The handler called from the poller that scans for events. The program's code would run
  inside a poller, where Rotor refuses `add_poller` and `remove_poller`.
- `start`, `on_events` and `wait_ns`. Every program would write the loop by hand.
- The handler at `run`, or an implicit `start` inside `fetch`. Events that come before `run`
  would reach no handler, and a later `run` could not install one.
- A public `ClientHandler` type. No program needs the name (decision 115), and a comptime
  trampoline needs no public name.
- A Loop type parameter (ruling 1).
- The field `loop` in `server.Capacity`. The `server` module owns no I/O (ruling 2).
- `.owned` for colibri's own loop, the first name of the kind. It names who owns the loop,
  which a reader of `Client(.{}, .owned)` cannot see. The owner renamed it `.private` on
  2026-11-06. `.standalone` and `.embedded` lost, and so did a second argument of `null` or
  a loop type.
- `ClientOf` and `ServerOf` kept, with `Client` and `Server` as the types of the default
  capacity. Zig's std names a type function after the thing itself, and the suffix `Of`
  says nothing to a program.
- `Client` kept as the type of the default capacity, beside a new `ClientWith(capacity,
  loop)`. A program then learns two names for one thing, and the default hides the loop
  kind that each program must choose.
- A field `loop` in `ClientCapacity` and a new `colibri.ServerCapacity` that holds
  `endpoint` and `loop`, in the first amendment. A capacity then holds more than sizes, and
  the server needs a new public name.
- The work of a turn inside each callback. A socket would step once for each event, not once
  for each tick.
- A poller that returns "did work". It adds a tick that waits 0 ns to every turn: one more
  system call for each request.
- A poller that returns a `bool`, with no timer, in the first text of ruling 6. Another
  library's long wait would delay a deadline. The `WaitLimit` of the third amendment
  removes this problem, so the poller now needs no timer.
- A repeating timer of 50 ms alone. QUIC needs deadlines in milliseconds.
- One poller for all of colibri. It needs state that every instance shares.
- A Rotor `post` for `shutdown`. A post goes to the caller of `tick`.
- `shutdown` takes the caller's `*rotor.Remote` and posts the wake, in the third amendment.
  A program that owns a shared loop already wakes it to stop it. A second path for the wake
  adds a name and a step that a program can forget. A `Remote` also needs a registry.
- The program posts the wake after `shutdown`, in the third amendment. The program already
  wakes its loop to stop it, so a second wake adds a rule and a step that a program can
  forget.
- `buffer_group` with a default of 0. Two users that keep the default halt on one group.
- `cancel_all` at the end on any loop. It cancels the operations of other libraries.
- `payload`, `header_buffer` and a URL, as std names them. Decision 126 names the request
  body, and a pool serves one origin (RFC 9110 §4.3.1).
- colibri always reserves its group, with no `buffer_group` field, in the third amendment. A
  program that reserves the ids of its libraries in an order of its own could then not give
  colibri one of them.
- The program always passes `buffer_group`, in the third amendment. Each program then calls
  `reserve_buffer_group` for colibri, though Rotor already gives out ids that cannot clash.
- The one-shot timer of ruling 8, capped at 50 ms, in the first text of ruling 8. Each
  earlier deadline costs a cancel and a second timer, and a `shutdown` waits up to 50 ms. A
  `WaitLimit` bounds the wait with no operation. On a shared loop, a `shutdown` on the
  loop's thread takes effect with no wait.
- A `shutdown` from another thread that waits for the 50 ms bound on a shared loop too. The
  stop is then up to 50 ms late, and each idle tick ends at 50 ms.

The alternative that won on the amendment:
- The type names the owner of the loop. The first draft of this decision refused a flag
  `owns_loop`, as a third parameter of `ServerOf`. As the second comptime argument of
  `Client` and `Server` it now wins for two reasons. The compiler refuses `fetch` and `run`
  on a shared loop, and the configuration requires `loop` only where it applies.
