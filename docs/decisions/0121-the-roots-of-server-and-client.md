# Decision 121: The roots of `server` and `client` export what an endpoint and a channel take and return

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-13 in [#96](https://github.com/c4milo/colibri/issues/96); design §8
step 21d carries it.

Decision 117 ruling 3 takes `server.Connection`, `server.QuicConnection`,
`client.Connection` and `client.QuicConnection` out of the public API. Steps 21b and 21c
moved every caller to `server.Endpoint` and `client.Channel`. The four names stayed in the
roots until this step.

The rulings:
1. The four types leave the roots. They stay types of their modules, and the endpoint and
   the channel hold them. Code that reads one names it through the field that holds it:
   `std.meta.Elem(@FieldType(server.Endpoint, "tcp"))`.
2. The methods of the four types stay `pub`. The root does not export the types, so `pub`
   means only that another file of the module calls a method. h2's `Streams` and the other
   internal types use `pub` in the same way. The list test of each type names the calls
   that the other files of its module make.
3. The names that only the calls of those types took or returned leave with them:
   `server.Error`, `server.Protocol`, `client.Event`, `client.Received` and
   `client.Advert`. A program reads the version of a request from `Request.version`. It
   reads the version of a channel from the `connected` event.
4. The types of the channel lose their `Channel` prefix. CLAUDE.md tells a root to export
   each type under its own name. `ChannelValues`, `ChannelInput`, `ChannelReceived`,
   `ChannelEvent`, `ChannelOpen` and `ChannelPhase` become `client.Values`,
   `client.Input`, `client.Received`, `client.Event`, `client.Open` and `client.Phase`.
   `Phase` stays in the root because `Channel.phase` returns it.
5. `ChannelEntry` leaves the root. No call of `Channel` takes or returns it. The client
   trace reads `Channel.entries` and names the type of an entry through that field:
   `std.meta.Elem(@FieldType(client.Channel, "entries"))`.
6. `server.StartError` names what `Endpoint.init` returns. It does not hold `TlsRefused`:
   the endpoint changes that error of a TCP connection into a null `accept`.
   `client.RequestError` names what `Channel.request` returns: `Full`,
   `RequestUnsupported` and `FieldReserved`. Decision 120 ruling 12 already says that a
   channel never returns `Draining` or `ConnectionClosed`.
7. `examples/server_exchange.zig` serves TCP and QUIC through one endpoint. It calls
   `set_user_data` and `shutdown`, waits for the `closed` event, and sets
   `Config.h3_alternative`. `examples/client_exchange.zig` runs one channel. The channel
   tries QUIC first over a datagram link that drops every datagram, and it carries its
   exchanges over TCP. The two examples replace `tls_exchange.zig` and `h3_exchange.zig`.
   They keep each call that the guide quotes from the old two, for example
   `Endpoint.set_deadlines`, `Channel.take_ticket` and `Channel.transport_closed`.
8. The h11 and h2 examples stay. Step 21f decides whether `h11`, `h2`, `h3` and `quic` stay
   exported. Its check waits until the dependent that uses `h11` directly can use
   `client`. The owner found it odd to keep the two examples. To remove them here would
   decide the question of step 21f before its check.
9. docs/performance.md keeps the size of each connection. It measures each connection
   through the field of the endpoint or the channel that holds it.
10. The check of the step is that the lists of `server.zig` and `client.zig` hold no
    connection type. The roots of `h11`, `h2`, `h3` and `quic` keep `Connection` until step
    21f.

What this decision amends:
- Decision 120 ruling 7 says that step 21d only removes names. Its refused alternative says
  that the text of step 21d moves no caller. Step 21d also renames six names of the
  channel, removes `ChannelEntry` and narrows two error sets. It also runs the stream link
  and the datagram link of the examples on one pair of loops.
- Decision 115, and the rule of CLAUDE.md under "The public API is written first", say that
  the `pub fn`s of a struct are the calls of a program. From step 21d the rule applies only
  to the types that a root exports.
- Design §8 step 21b.7 and the amendment of decision 119 of 2026-10-11 say that
  `Connection` and `QuicConnection` stay exported until step 21d. They also say that
  `Connection.init` is a public function until then. The types leave the roots in 21d. Their
  methods, the three `init`s too, stay calls that the files of the endpoint and of the
  channel make.
- Decision 115 keeps `Channel.phase` public for the simulator, with `ChannelPhase` and
  `ChannelEntry`. `Channel.phase` stays, and it returns `client.Phase`.
- The check of design §8 step 21d said that no list of a root holds a connection type. It
  now names the two roots (ruling 10).

Some statements of earlier decisions no longer apply. The `protocol()` of decision 117 is
now `Request.version` on the server and the `connected` event on the client. The endpoint
and the tests call the `Connection.transport_closed` of decision 119. No program calls it.

The alternatives refused:
- "The four" as the four examples, the h11 and h2 examples too. That decides the question
  of step 21f about `h11` and `h2` here.
- The `init` of each connection in an internal file. Zig has no private fields, so a program
  can still call each method through the field `Endpoint.tcp`. Each site that starts a
  connection changes, for no program.
- Each method as a free function. Hundreds of sites change, for the same reason.
- The five names of ruling 3 kept in the roots. Decision 115 tells a root to export the
  types that the calls of a program take and return. After this step no call takes or
  returns them.
- An `Endpoint.protocol` call. It adds a public name, and no program in the tree needs it.
- The prefix removed from five names of the channel only, with `ChannelPhase` and
  `ChannelEntry` kept. These two would then be the only names of the root with a prefix,
  and no call takes or returns an entry.
- The two error sets as they were. A program that switches over either set handles errors
  that it never gets.
- No memory rows for the connections. Then no row shows the growth of a connection, which
  [#99](https://github.com/c4milo/colibri/issues/99) measures.
- A client example whose server refuses the QUIC transport at once with
  `transport_closed`. It shows no fallback delay.
- Examples that also serve h11 in cleartext and learn h3 from Alt-Svc. Each needs a second
  helper file, for cases that the simulator already checks.
- The names `server.zig` and `client.zig` for the examples. In the links of the guide they
  look like the roots of the modules.

Cost: a breaking change to both roots, in the release that already has the changes of
step 21c. A dependent that named one of the four types serves through `server.Endpoint` or
`client.Channel`. A dependent that wrote `client.ChannelEvent` and similar names writes
`client.Event` and the other new names. A dependent that named `client.ChannelEntry` names
it through `Channel.entries`. A `switch` over `server.StartError` or `client.RequestError`
loses the members that it never got. The run of the client example waits about 3 s of real
time, in each `zig build examples` and each CI run. The channel closes the QUIC connection
that it abandoned only after the closing period, three PTOs (RFC 9000 §10.2). With no RTT
sample, each PTO is about 1 s (RFC 9002 §6.2.2). Step 21d accepts the wait: the example
shows what a program sees on a network that drops UDP.

Amended on 2026-10-13 by design §8 step 21d, for what its sub-steps met that the rulings
left open:
- Each narrowed set has a test beside the list of its root. The test switches over the
  exported set and over the error set of the call's return type. A member that one set
  holds and the other does not then fails to compile.
- The server's `Connection.init` returns `InitError`, which is `StartError` with
  `TlsRefused`. The channel's `RequestError` is the `CheckError` of the connections with
  `Full`, and the connections keep the wider set. No root exports `InitError` or
  `CheckError`.
- The program that holds the loops of the examples starts them once and stops them once.
  `Link.init` and `Link.deinit` do this for a `Link`. A `DatagramLink` holds a pointer to
  the loops and does not start or stop them.
- A program that serves TCP and QUIC through one endpoint reads its clock once in each
  turn. It passes that instant to each call of the turn. The first server example read
  the clock again for each datagram. An instant then went back, and the assertion on
  QUIC's ack delay failed (`src/quic/space/space.zig`).
- How the examples keep each call of ruling 7:
  - `Endpoint.set_deadlines`: when the h3 request arrives, the server gives its QUIC
    connection an idle deadline of 100 ms. The check requires one `ended` at the idle
    deadline, before the configured 10 s pass.
  - `Channel.take_ticket`: a server issues a ticket only when its configuration holds a
    `ticket_key`. The server of each example sets one, and each check requires a ticket.
  - `Channel.transport_closed`: a second channel of the client example offers TCP alone,
    and its connect fails. The program calls `transport_closed`, and the exchange ends
    `refused`. The first channel still shows the fallback delay, so this is not the
    alternative refused above.
