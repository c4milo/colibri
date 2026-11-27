# Decision 91: How h11 uses stdx's gzip and deflate decoders

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-25, for https://github.com/c4milo/colibri/issues/64. It settles what
entries 88 and 90 left open.
- One compression coding at most on a body: `chunked`, plus at most one of `gzip` or
  `deflate`. RFC 9112 §6.1 lets `Transfer-Encoding` list several codings, and colibri knows of
  no peer that stacks two compression codings. A server answers 501 to more than one, and a
  client fails the response.
- `deflate` is the zlib format alone, as RFC 9110 §8.4.1.2 defines it. A raw deflate stream
  fails the zlib header check and is refused.
- h11 caps no decoded size. The decoded bytes go into the application's buffers, so colibri's
  memory stays bounded, and the application stops reading at its own limit, as it does for
  any body.
- A `gzip` body may hold several members (RFC 1952 §2.2). Each member's CRC-32 and length are
  checked.
- Bytes after the coded stream ends inside the body make the message malformed. A server
  answers 400 and closes the connection, and a client fails the response. Bytes that belong
  to no coding are a framing disagreement, which is how request smuggling starts.
- Two verdicts. A server answers 400 and closes for a corrupt body, such as a wrong checksum or
  a malformed block. It answers 501 for a feature it refuses, such as a zlib preset dictionary
  or a window over the limit (RFC 9112 §6.1). A client fails the response and closes the
  connection in both cases.
- Decoders live in a pool the caller owns, sized by a named limit. h11 takes a slot only while
  a message carries `gzip` or `deflate`, and returns it when the message ends. When the pool is
  empty, a server answers 503 and a client fails the response.
- The client offers `gzip` and `deflate` only when the caller turns on a connection option.
  Then it sends `TE: gzip, deflate` with `TE` in `Connection` (RFC 9110 §10.1.4). Without the
  option it offers nothing, and it refuses a response that carries either coding, because
  RFC 9112 §7.4 makes `chunked` the only acceptable coding when no `TE` field is sent.

The alternatives refused:
- Stacked compression codings, with a named limit on their depth. Each layer costs another
  window of 32,768 bytes.
- Raw deflate accepted by inspecting the first two bytes. A corrupt body would then pass as
  raw deflate for longer before it failed.
- A named limit on each message's decoded size, or on its ratio to the coded size. The ratio
  limit also refuses content that is legitimately repetitive.
- The first `gzip` member alone, which refuses input RFC 1952 allows.
- Leftover bytes read and dropped, so two parsers can disagree about what a body held.
- One verdict for every decoder error.
- A decoder inside every connection. A server holding 10,000 idle connections would spend
  about 400 MB on decoders it rarely uses.
- Offering the codings on every client connection, or on none.

Recorded by the owner on 2026-10-17, after the review of design §8 step 20e, with no change:
the pool of decoders is shared, so slow coded uploads can hold all of it. Sixteen request
bodies in a compression coding, each at decision 110's minimum body rate, hold the default
pool for up to the cap of 300 s on a request. Meanwhile each other coded body gets 503.
Clients seldom send a coded request body. An operator who sees it places a larger pool, or
shortens the body deadlines with `set_deadlines`. Refused: a shorter cap on the time of a
coded body, which would be a new named limit.
