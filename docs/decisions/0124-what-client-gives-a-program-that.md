# Decision 124: What `client` gives a program that leaves the protocol modules

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-17, for design §8 step 21f. A dependent planned its move from `h11` to
`client.Channel` and listed what `client` lacked, with the evidence on both sides. Step 21f's own
question, whether `h11`, `h2`, `h3` and `quic` stay exported, waits for that move.

The rulings:
1. `client.HttpExchange` leaves the API. A program sends a `client.Request` and reads a
   `client.Response`. In the owner's words, programs "either write clients or servers and
   deal with requests and responses".
   - `Request` holds `method`, `path`, `fields`, `never_indexed` and `content`.
   - `Response` holds where the answer goes: `wanted`, `values` and `body`. It also holds
     what arrived: `status`, `interims`, `body_len`, `values_len`, `outcome`, `coding`,
     `error_code` and `content_sent`.
     Decision 152 amended this on 2026-11-05: `headers` and `trailers` replace `wanted`
     and `values`.
   - The call is `Channel.request(request: *const Request, response: *Response) !Id`.
   - The program keeps both in place, with each slice they name, until the exchange's
     `finished` event or until `cancel` returns. Decision 100 ruled the same for the
     exchange.
   - The server already reads a `server.Request` and sends a `server.Response`.
2. An early final response ends the h11 connection.
   - When a final response ends while the request's content is still going out, the client
     stops the content and ends the connection, as `cancel` does.
   - When the client drops a response while the content is still going out, it does the
     same at the drop.
   - RFC 9112 §9.5 asks this when the response shows that the server closes the connection.
     This decision applies it to every such response, because a server may read the whole
     content before it ends its response.
   - The next exchange goes on another connection.
3. The channel sends an idempotent request again.
   - The rule: a connection closes or fails before any byte of a request's response
     arrives, and the method is idempotent (RFC 9110 §9.2.2). Then the channel sends the
     request again, once, on another connection (RFC 9112 §9.3.1).
   - The idempotent methods are PUT, DELETE, and the safe methods GET, HEAD, OPTIONS and
     TRACE. Any other method ends `closed`, as before.
   - Over h2 and h3, the header of a HEADERS frame on the request's stream counts as an
     byte of the response, even when its field section does not decode.
   - After a failed h11 connection, the next connection writes the first request alone
     until its final response arrives (RFC 9112 §9.3.2).
   - The program sees one outcome. The owner ruled that a program implements no part of
     HTTP: "No leaky abstractions".
   - A refused exchange still moves once (`moves_max`), and the two moves share that one
     budget.
   - A request sent again that is then refused ends `closed`, not `refused`. Its first
     attempt may have been processed, and decision 105 keeps `refused` for a request that
     no server processed.
4. `client.ChannelOf(capacity)` takes a `client.Capacity` with `quic: bool = true`
   ([#99](https://github.com/c4milo/colibri/issues/99)).
   - `server.EndpointOf` takes a `server.Capacity` in the same way, and `client.Channel` is
     `ChannelOf(.{})`.
   - A channel with no QUIC holds no QUIC connection and no QUIC TLS configuration.
   - Its `init` refuses versions that allow h3, with a new member of `client.StartError`:
     `VersionUnavailable`.
   - It has no `start_quic`, so a call of it does not compile. Such a channel never asks for
     QUIC.
5. Three limits in `client.constants`, so a program sizes its memory and bounds its loops at
   init with no name from `h11` or `tls_provider`:
   - `stream_input_len_min`: the bytes a program holds so that `receive` on a TCP
     transport takes some, in cleartext and over TLS, while `send_stream` has written what
     the connection owes;
   - `stream_output_len_min`: the least `output` with which `send_stream` always writes a
     record that it owes. It is the TLS provider's contract,
     `tls_provider.constants.record_write_len_min`, though chapulin seals a shorter record
     into a shorter output;
   - `receive_events_without_input_max`: the most `receive` calls in a row that report an
     event and take no byte.
6. Doc comments state four rules that the code keeps: `Response.status` holds the final
   status when the outcome is `too_large`; `Channel.init` may run again on a channel with
   no connection and no exchange; a program may close a transport at any time and then
   call `transport_closed`; `Open.to` is one of `Values.addresses` with only its port set.
7. A connection over TLS holds the longest h11 head that is not whole yet beside one more
   whole record. Before, `plaintext_in_len` held one h2 frame and one record, so a head longer
   than a frame, sent in records of an odd size, stopped the connection. The owner ruled the
   fix on 2026-10-17, in the client and in the server: `plaintext_in_len` grows from 33,033 to
   49,407 bytes (RFC 9112 §2.1, RFC 9846 §5.2), and each TCP connection by about 16 KB.
8. Three asks become issues: content sent with no copy into the channel's output
   ([#105](https://github.com/c4milo/colibri/issues/105)), `too_large` at the head
   ([#106](https://github.com/c4milo/colibri/issues/106)), and an IPv6 scope id
   ([#107](https://github.com/c4milo/colibri/issues/107)).

The alternatives refused:
- One struct under a name without "exchange". One type then still holds both directions.
- `HttpExchange` kept as it is.
- `Response.response_began`, which a program reads to decide a resend itself. The program
  then carries RFC 9110 §9.2.2's rule. The dependent's owner withdrew the ask for that
  reason.
- A per-exchange fact that the content ran until the close (`ended_by_close` or a
  `body_kind`), or `Config.close_delimited_refused`. Withdrawn: colibri keeps RFC 9112 §6.3
  rule 8 for a body that runs until the close.
- `Channel.negotiated(transport)`, the suite a transport settled on. Withdrawn: which suite a
  connection settles on is colibri's and chapulin's to test.
- A channel that always holds QUIC state: 704,792 bytes, the difference between
  `client.Channel` and a channel with no QUIC, that a TCP-only program never uses.
- The TLS stall of ruling 7 as an issue only. A large head over TLS then waits for a
  deadline or for the program's timeout.

Cost: a breaking change for every program that names `client.HttpExchange` or reads
`Finished`'s exchange, in the release that already breaks names under decisions 115 and
121. A program that sends an idempotent request may see the server process it twice, which
RFC 9110 §9.2.2 allows: the intended effect is the same. Each TCP connection, in the client
and in the server, grows by about 16 KB for ruling 7.

Amended by the owner on 2026-10-30, for
[#106](https://github.com/c4milo/colibri/issues/106): a response too large ends at its
head, by default.
- A final response whose Content-Length is larger than the room left in `body` ends
  `too_large` at its head, and its content is not read. The response to HEAD and a 304 are
  not judged so, because their Content-Length counts content they do not carry (RFC 9110
  §8.6).
- h11 also ends the connection, because it cannot end one exchange alone (RFC 9112 §9.3.1).
  h2 resets the stream with CANCEL (RFC 9113 §8.1), and h3 with H3_REQUEST_CANCELLED (RFC
  9114 §4.1.1).
- Content in a coding the client decodes is still judged as it arrives, because its
  decoded length is not known at the head (decision 101).

The alternative refused: `Request.close_when_too_large`, which leaves the rule to each
program. A program that holds a slot for a large response it would drop then holds it until
the content drains.
