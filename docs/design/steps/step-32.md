# Design §8 step 32: the h11 client's bounded drop

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 146](../../decisions/0146-an-h11-client-bounds-the-drop.md) bounds the drop of an h11 response the caller no longer
reads ([#125](https://github.com/c4milo/colibri/issues/125)), for a `client.ConnectionPool` that
speaks h11.
- **The public names,** each listed in a test beside the root before the code (decision 115):
  - `Timeouts`, a struct with one field, `drop_ns: ?u64`, 50 ms by default. A program that
    cancels an h11 exchange needs it to choose how long the connection reads the rest.
  - `Config.timeouts: Timeouts`.
  - `ConnectionPool.cancel(id, now_ns)`, whose new parameter starts the drop's time.
  - `constants.limits.drop_len_max`, 256 KiB, and `constants.policy.drop_timeout_ns`, 50 ms.
- **The rules.** A drop ends the connection when the content left passes `drop_len_max`, when
  its time runs out, or at once when the response closes the connection (RFC 9112 §6.3, §9.6).
  The exchanges after it then end as a failed connection ends them, and the pool moves them.
  `deadline_ns` and `on_instant` carry the time, so no new call is added.
- **The checks.** A client test at each bound, and one where each bound is not reached. A
  mutation for each bound. The pool trace run against `spec/tla/client_exchanges`, whose model
  gains the end of a drop at a bound.
- **The cost.** Each exchange slot holds the bytes it dropped and the end of its drop, 24
  bytes. A connection holds 16 slots, so each client TCP connection and the QUIC connection
  grow by 384 bytes, and `Config` by 16.
- 13 mutations **CAUGHT**: the Content-Length left ignored, the bound off by one, the dropped
  bytes not counted, the "close" option and content until the close each ignored, no bound
  judged at the head, the time fired late, a cancel or a read starting no time, the time started
  again at each read, the pool naming no drop deadline or firing none, and `Config.timeouts`
  not carried to the connection.
