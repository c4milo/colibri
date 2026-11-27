# Decision 95: h11 counts body bytes the caller sends from its own buffer

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-26, for a caller that already holds a large body in a buffer of its
own, such as an object store client sending segments of several MiB.
- `Connection.count_body(len)` counts `len` bytes against the body the head declared, as
  `write_body` does, and writes nothing. The caller sends those bytes itself, next, before
  any other byte of the connection: in cleartext from its buffer, and over TLS through
  `connection_tls.encrypt` from the same buffer.
- It serves a body with a Content-Length, a body the close ends, and a tunnel. A chunked body
  refuses it with `BodyChunked`, because each chunk needs a size line before its data (RFC
  9112 §7.1), and colibri writes that line.
- `write_body` and `count_body` share one count, so a caller may use both on one body.

The alternatives refused:
- `write_body` alone, which copies every byte of the body into the output buffer. The caller
  already holds the bytes, and the copy reads and writes each of them once more.
- A call that returns the bytes to send as a list of slices, the caller's among them. A body
  with a Content-Length has no framing, so the list would hold one slice, the caller's own.
- A chunked form that writes a chunk's size line, counts the caller's bytes, and writes the
  CRLF after them. No caller needs it yet.

Cost: colibri cannot check that the bytes counted are the bytes sent, or that they go out
next. A caller that counts one thing and sends another frames the message wrongly, which is
how request smuggling starts.
