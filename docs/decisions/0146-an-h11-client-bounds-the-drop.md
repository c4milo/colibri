# Decision 146: An h11 client bounds the drop of a response the caller no longer reads

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-02 ([#125](https://github.com/c4milo/colibri/issues/125)). Decision
124 keeps an h11 connection when the caller cancels an exchange, or when its content does not fit:
the connection reads the rest of the response and drops it (RFC 9112 §9.3). That drop had no bound.
A large response read every byte left, and a slow one held the connection until it ended. In a pool
of one TCP connection, the exchanges after it wait behind the drop.

The rulings:
1. A drop reads at most `constants.limits.drop_len_max`, 256 KiB of content. When the
   response's Content-Length says more is left, or more arrives, the connection fails
   instead, as a cancel fails it while the request's content goes out.
2. A drop lasts at most `Timeouts.drop_ns`, 50 ms by default, and null turns the limit off.
   `client.Timeouts` is a new public type, which `Config.timeouts` holds. The server's
   `Timeouts` has the same name (decision 126), and later client limits join it.
3. `ConnectionPool.cancel` takes the instant, as `cancel(id, now_ns)`, so the drop's time
   starts at the cancel. A drop that starts inside `receive` takes that call's instant. The
   time of a drop whose response waits behind another starts when that response ends, so a
   drop never fails the response before it. The pool's `deadline_ns` names the end of the
   earliest drop, and `on_instant` fails the connection whose drop ran out.
4. No drop when the response closes the connection: it carries `Connection: close` or comes
   from HTTP/1.0 (RFC 9112 §9.6), or its content runs until the close (RFC 9112 §6.3 rule 8).
   The connection then ends with the response, so the drop gains nothing.

The bounds are Go 1.27's, which drains an unread HTTP/1 body for at most 256 KB and 50 ms,
and skips the drain after `Connection: close` (https://go.dev/blog/http-connection-reuse).

Alternatives that lost:
- The limit as a field of `Config`, as `fallback_delay_ns` is. The owner chose one type for
  the client's timeouts, as the server has.
- A fixed 50 ms in `constants_policy.zig`. No program could change it.
- The time starting at the next instant the pool reads after a cancel. No public call changes,
  but a pool with no input after the cancel would never start the time.
- 64 KiB or 1 MiB for the size. The first closes more connections; the second reads more
  bytes for nothing.

Cost: `cancel` changes its signature, so every program that cancels changes its call. A
dropped response past a bound costs a new TCP connection, and over TLS a new handshake.
