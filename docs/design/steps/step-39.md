# Design §8 step 39: streamed bodies in the pool, proposed 2026-11-05

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 153](../../decisions/0153-a-client-that-runs-on-a.md) as amended. It depends on no other step, and ships in
v0.15.0 with steps 38b, 42 and 43. Step 44 moves to v0.16.0 (the owner's ruling of 2026-11-08).
- **The public names:** `client.Streamed`, `client.WriteBodyError`, `Request.streamed`,
  `ConnectionPool.write_body`, `ConnectionPool.release_body`, and the events `headers`, `body`
  and `body_taken` (decision 153 ruling 7). `h11.Connection.write_chunk_head`,
  `h2.Connection.release_stream`, `h3.Connection.peek_data` and `h3.Connection.release_data` serve
  them. `client.ConnectionPool` needs `peek_data` to copy an h3 piece once (decision 153 ruling
  12).
- **The commits:** 39a splits the files near the 500-line limit; 39b writes h11 chunk heads
  with no copy; 39c holds h2 stream credit; 39d holds h3 DATA; 39e sends request bodies in
  pieces; 39f receives response bodies in pieces; 39g lets a request body go on after the
  response's headers over h2 and h3; 39h extends the TLA+ model and the trace; 39i adds the
  example and the docs; 39j is the review; 39k applies the owner's rulings on it.
- **The rules.** The pool copies no piece and holds one piece of each body at a time. It gives
  back flow credit only after `release_body`. A streamed request is sent again only before
  its first `body_taken`.
- **The checks.** A request body in pieces and a response body in pieces each arrive whole over
  h11, h2 and h3, and over h2 and h3 both at once. A server that sends faster than the program
  releases is held by flow control. The TLA+ model finds each of decision 153's rules
  violated when the rule is off. An example streams a gRPC-shaped exchange both ways in memory.
- **39a, the splits,** `4f736236` and `bdc71c02`. Files near 500 lines move their request
  content and the resend rule into files of their own, with no change in behaviour.
- **39b, h11 chunk heads,** `ba29d7da`. `h11.Connection.write_chunk_head` writes the CRLF that
  ends the chunk before, then the size line, and the piece goes out from the program's memory.
  `BodyChunked` leaves `h11.connection.SendError`, and `BodyNotChunked`, `ChunkEmpty` and
  `ChunkIncomplete` join it.
  - 8 mutations **CAUGHT**: the CRLF before the next head dropped, the size written in decimal,
    the last chunk with no CRLF before it, a count past the chunk, and a head of length 0, a
    head before the last chunk's data, an end before it, and a head on a body that is not
    chunked each accepted.
- **39c, h2 stream credit,** `c53a3554`. A stream opened with `hold_credit` gives back its
  stream credit only at `h2.Connection.release_stream`. The connection's credit goes back at
  each frame (RFC 9113 §6.9.1).
  - 5 mutations **CAUGHT**: stream credit given back at receipt, connection credit held too, the
    room check before the queue removed, a WINDOW_UPDATE after the peer ended the stream, and
    credit that waited for room never queued.
- **39d, h3 DATA held in quic,** `926afd58`. A request opened with `hold_data` reports
  `data_available`, and `h3.Connection.release_data` takes its bytes from quic.
  `h3.Connection` grows by 16 bytes for each request stream, to 147,112.
  - 6 mutations **CAUGHT**: `read` in place of `peek`, the held stream not skipped, a FIN inside
    a held DATA frame accepted, a refused stream that keeps its hold, and `release_data` that
    takes a reset stream's bytes or takes none.
- **39e, request bodies in pieces,** `0aa4c79b`. `client.Streamed`, `client.WriteBodyError`,
  `ConnectionPool.write_body` and the `body_taken` event. `exchange_events_max` is 4, and
  `receive_events_without_input_max` counts it for each exchange.
  - 13 mutations **CAUGHT**: a resend after a take, END_STREAM or FIN on a piece that is not the
    last, `body_taken` over h3 before the acknowledgment, chunked framing with a stated length,
    a refusal after a take reported `refused`, an h11 piece never taken, STOP_SENDING not read
    as the end of the body, a piece handed while the exchange waited never given to the
    connection, a second piece or a piece after the end accepted, `body_taken` after
    `finished`, and one event counted for each exchange.
- **39f, response bodies in pieces,** `d1a79c72`. `Streamed.response`, the `headers` and `body`
  events, and `ConnectionPool.release_body`.
  - 13 mutations **CAUGHT**: `finished` while a piece is held, h11 that reads past a held piece,
    h2 stream credit at receipt, h3 content read at receipt, h2 padding not skipped, the
    held-back part counted as taken, a coding offered for a streamed response, a drop that
    keeps the piece, a move after `headers` (**NOT CAUGHT** first, until its test sent the
    GOAWAY before the reset), a refusal after `headers` reported `refused`, h3 that reads
    nothing after a release until a datagram arrives, the end of an h11 body over TLS never
    read, and END_STREAM after the held-back part ignored.
- **39g, a request body after the response's head,** `37afccc0`. Tests only: h2 and h3 servers
  echo each request piece while the response streams.
  - 2 mutations **CAUGHT**: h2 CANCEL and h3's reset at the response's head.
- **39h, the model and the trace,** `ccebebc3` and `c29f9ae5`.
  - `spec/tla/client_exchanges` gains `Streamed`, `handed`, `taken` and `pieces`, the actions
    `WriteBody`, `TakeBody`, `BodyArrives` and `ReleaseBody`, and three rules, each with a
    mutant: `FinishWhenReleased` (`finish_with_piece.cfg`), `CreditAfterRelease`
    (`credit_before_release.cfg`) and `ResendBeforeTaken` (`resend_after_taken.cfg`).
    `ClientExchanges_streamed.cfg` and `ClientExchanges_streamed_rough.cfg` must hold.
  - The client trace run makes one exchange with content in two a streamed PUT. It hands the
    next piece at each `body_taken`, reads each response piece into 4 bytes, and holds each
    piece up to 30 ms. Over 256 seeds, 80 exchanges were streamed, 122 pieces were taken and
    141 response pieces were held.
  - The run found a bug in 39e. A piece handed at `body_taken`, before the next `send`, was
    taken over h3 before it went out, and an assertion failed. `ccebebc3` fixes it, and 2
    mutations of the fix are **CAUGHT** by `test-client`.
  - 4 mutations of the client **CAUGHT** by the trace run: `finished` while a piece is held, a
    refusal after a take reported `refused`, h2 that reads on while a piece is held, and a move
    after a take. The last was **NOT CAUGHT** first, while each streamed exchange was a POST;
    the run then made them PUTs, which move after a close.
  - **Not run yet:** TLC, on the new configurations, the three mutants and
    `tools/client_trace.sh`. Another TLC held the machine for the whole layer. SANY parsed the
    model, the trace module and one written seed of each trace run. A person runs `zig build
    tla` on the model and `tools/client_trace.sh` before the step is called done.
- **39i, the example and the docs,** `7ae675a3`. `examples/client_stream.zig` streams a
  gRPC-shaped call both ways over h2 in cleartext, and docs/usage.md describes streamed bodies.
  - 4 breaks of the example **CAUGHT**, and 1 **NOT CAUGHT**, which examples/README.md lists.
- **39j, the review,** `b1b7dd8f` to `14379e94`. Two reviewers checked the step.
  - An h11 response that h11 read whole ended `closed` when the transport closed while the
    caller held its last piece, in cleartext and over TLS. `b1b7dd8f` reads the owed end at the
    close. 2 mutations **CAUGHT**.
  - A piece held when a GOAWAY ended its h3 exchange never went back to QUIC, so the stream
    never closed and `finished` never came. `ecedbd07` always releases the piece. 2 mutations
    **CAUGHT**: the release skipped, and the content of such a stream left in QUIC, which was
    **NOT CAUGHT** in the review.
  - The review found 8 more mutations **NOT CAUGHT**. A test for each makes it **CAUGHT**:
    - in `test-h2`: an `.open` stream read as ended, padding held, credit queued after a
      failure, and the `stream_credit_waiting` term of `owes_window_update` removed;
    - in `test-client`: no `BodyStopped` on an exchange the pool ended, no unblock in
      `write_body` or in `release_body`, and no h3 reset when a response ends before the
      request body.
  - 4 mutations stay **NOT CAUGHT**. Three are equivalent:
    - the `stream_credit_waiting` term of `has_pending`: the flag is set only on a full reply
      queue, and a reset that empties the queue owes its RST_STREAM;
    - `release_data` that drops the FIN: the next frame read sees it;
    - `finished` before `headers`: `Owed.next` reports `headers` first.
  - The fourth, a drop that keeps `body_len`, has no test. A cancelled exchange's `body_len`
    is read by no one. 39k restores the bytes that fit at an h11 `too_large`.
  - A `release_body` starts a new run of the calls `receive_events_without_input_max` counts.
    docs/usage.md says so, and a test over h3 reads more pieces with no input than the bound.
  - Two questions went to the owner: the h3 connection's credit that a held piece keeps, and
    the two copies of each h3 piece. 39k carries his rulings.
- **39k, the owner's rulings of 2026-11-06,** `8c164a1d` to this commit, after a rebase onto
  `5527558a`. Decision 153 rulings 11, 12 and 13.
  - Ruling 11: a held piece keeps the h3 connection's credit, which is correct, since its bytes
    take room in the receive pool (RFC 9000 §4.1). Each request stream now gets
    `quic_stream_window`, 65,536 bytes, as its window, and not the whole pool (RFC 9000
    §18.2). `24f037f3` makes the change. A test holds one stream's piece while a second
    exchange finishes. docs/usage.md no longer states a gap. 1 mutation **CAUGHT**: the window
    restored to the pool's capacity.
  - Ruling 12: `data_available` reports a count of bytes, and `h3.Connection.peek_data`
    copies them from QUIC straight into `Response.body`. h3's 16,384-byte buffer takes none.
    `ca905619` makes the change. 7 mutations **CAUGHT**: the count past the DATA frame, the
    count measured past a gap, a FIN inside the frame accepted, `peek_data` past the held
    bytes, a copy into the buffer `receive` was given, the client's two copies, and a held
    count less than the copy. The first two were **NOT CAUGHT** until a test delivered two DATA
    frames out of order.
  - Ruling 13: an h11 response that is not streamed and ends `too_large` keeps the bytes that
    fit, and a drop clears `body_len` only for a held piece. `d495cf10` makes the change. h2
    and h3 end such an exchange without a drop. 1 mutation **CAUGHT**: `body_len` cleared at
    each drop. 1 **NOT CAUGHT**, as in 39j: a drop that keeps a held piece's `body_len`.
  - Each commit's memory table was measured again after the rebase, and `server.Endpoint` is
    52,461,840 bytes with step 39. Rulings 11, 12 and 13 change no size.
  - After the review of 39k:
    - Ruling 11 sets only a request stream's first window. Decision 49 grows it up to the pool
      when the program releases pieces quickly, so a piece held after that growth can fill the
      pool. docs/usage.md now says so, and the question went to the owner. A cap on the growth
      is the fixed window that decision 49 rejected.
    - `h3.Connection.peek_data` failed an assertion on a stream that the peer reset after the
      `data_available` event. It now copies none, as `release_data` takes none, and the reset
      stays to be reported. A test resets a held stream and peeks.
    - New tests: a DATA frame header that arrives alone reports no content, and an h2 or h3
      response that ends `too_large` keeps the bytes that fit.
    - 4 mutations **CAUGHT**, each **NOT CAUGHT** before these tests: no wait on a DATA frame
      header alone, `peek_data` with no reset check, and `body_len` cleared at an h2 or an h3
      refusal.
  - The owner's rulings of 2026-11-06 on the review:
    - Decision 49 as amended: a stream's receive window grows up to the receive pool's capacity
      less the stream's starting window, and not up to the whole pool (RFC 9000 §4.1). The rule
      applies to client and server streams alike. `quic.Connection` takes the cap from the
      stream's own starting window, and a pool of two starting windows or less keeps the
      window where it starts.
    - In a pool of 262,144 bytes, a request stream grows to 196,608 bytes. A test holds a
      piece of that stream, and a second exchange of 32,768 bytes finishes. The client sends
      MAX_DATA once half the connection's window is consumed. Until the program releases the
      held piece, the other streams together thus get at most one starting window, less the
      bytes consumed since the last MAX_DATA. The test consumes little before the hold.
    - A review on 2026-11-06 found that the other streams can get no bytes at all. This
      occurs when they consumed one starting window or more since the last MAX_DATA. The
      records now state that limit. The owner rules whether MAX_DATA must count held bytes.
    - A test reads the cap on a unidirectional stream and on a locally initiated stream. Both
      mutations that grow one of them to the whole pool are **CAUGHT** by the `quic` tests,
      and each was **NOT CAUGHT** before the test.
    - `h3.Connection.peek_data` returns 0 on a stream reset, refused or closed since its
      `data_available` event, as `release_data` takes none. The owner accepted this, with no
      error.
    - 3 mutations **CAUGHT** by the `quic` tests: growth back to the pool's capacity, the floor
      removed, and the floor and its assertion removed. Growth back to the capacity is also
      **CAUGHT** by the client test, with its two window checks removed too.
  - The owner's two rulings of 2026-11-06 on that limit, in decision 49 as amended and
    decision 153 ruling 11. A survey of 19 implementations' published defaults supports them:
    HAProxy, which sizes windows from fixed buffers, keeps 10% of the connection from one
    stream.
    - The cap stays, and its reserve is a named limit: `stream_window_reserve_windows` in
      `src/quic/constants_limits.zig`, 1, which the test of decision 137 pins. The unit is the
      stream's own starting window, because that window is the reserve by definition. The cap
      is the pool's capacity less that count of windows.
    - MAX_DATA is also owed on low credit (RFC 9000 §4.1, §4.2). A connection with a receive
      pool owes it when the credit left to the peer is below its floor, and one byte or more
      was consumed since the last MAX_DATA (`receive_credit_floor` in
      `src/quic/connection/connection.zig`, `flow.Receiver.owes_credit_below`). The limit is
      still the bytes consumed plus the window. The rule of the fraction stays beside it.
      The floor is the part of the pool that a stream of the largest starting window leaves
      free at its cap: one starting window in a pool of two windows or more, and 0 when a
      stream can fill the pool. A first version took one window in every pool. The simulator's
      h3 client, whose stream window is its whole pool, then sent MAX_DATA for each byte, and
      the endpoint and h3 deadline censuses moved. With the floor at 0 there, they do not.
    - The three RFC 9959 resume censuses moved, and are pinned again: `cubic` `0xd172ab1d`,
      `newreno` `0xa6e99f3b` and `bbr` `0x029edec0`. The simulator's QUIC endpoint has a
      connection window of two stream windows below its pool, so its credit falls below the
      floor before half the window is consumed, and MAX_DATA goes out sooner.
    - The guarantee: while a piece is held, the other streams together can keep one reserve
      in the pool, and each byte they consume gives one byte of credit back. A test in
      `quic` runs the review's probe: a pool of four windows, a window and a half consumed
      before the hold, and the held stream filled to its cap. The other streams get credit
      four times. The client test now finishes a second response of 65,536 bytes, one
      reserve and its frames, while the first stream's piece is held.
    - `spec/tla/h3_deadlines` takes the low-credit rule into `ConnectionCreditOwed`, with
      `Reserve` for `stream_window_reserve_windows` and `CreditFloor` for the floor of a pool
      of `ConnectionWindow` units. Its trace writer sizes `ConnectionWindow` so that the
      model's credit never falls below one `StreamWindow`, as the run's large pool never does.
      TLC was not run.
    - 6 mutations **CAUGHT** by the `quic` tests: the low-credit rule removed, the condition of
      one consumed byte removed, the connection's floor at 0, the named reserve at 2, the
      reserve written inline as two windows, and a floor of one reserve in every pool. The
      client tests catch each of these but two. They do not read the named limit. The
      condition of one consumed byte is **NOT CAUGHT** there: a MAX_DATA that repeats its
      limit costs only a frame. The `quic` test catches it.
