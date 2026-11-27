# Decision 138: h2 writes a DATA frame's header for data the caller writes after it

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-30, for https://github.com/c4milo/colibri/issues/105: the client sends
a request's content from the program's memory, as decision 95 lets h11 do.
- `Connection.write_data_header(output, stream_id, payload_len, end_stream)` writes the
  header of the DATA frame that `write_data` would write into `output`, and charges both
  flow-control windows (RFC 9113 §6.9.1). It returns the bytes of the payload the frame
  carries in `consumed`, and the header's bytes in `written`.
- The caller writes those `consumed` bytes right after the header, in `output`, before any
  other byte of the connection. END_STREAM is on the frame of the last byte (RFC 9113
  §6.1), and the frame has no padding.
- The client uses it in cleartext. Over TLS, a frame's header and its data go through the
  client's output together, because the provider seals one slice. chapulin's
  `writeParts` will seal the two, and `tls_provider` takes it then
  (https://github.com/c4milo/chapulin/issues/212).

The alternatives refused:
- `write_data` alone, which copies every byte of the content into the output.
- A call that counts bytes and writes nothing, as h11's `count_body` does. h2 frames its
  data, so the header must be written in front of each frame's bytes.
- The header of each frame in a TLS record of its own. Each 16 KiB frame then costs one more
  record and one more seal. The owner chose chapulin's call over two slices.

Cost: colibri cannot check that the bytes the caller writes after the header are the ones
the header counts. A caller that writes others frames the stream wrongly.

Amended on 2026-10-31 by decision 139: the call writes the header into a buffer of its own,
`write_data_header(header, room_len, stream_id, payload_len, end_stream)`, where `room_len`
is the bytes the whole frame may take. Over TLS the frame's data never shares a buffer with
its header, so `output` could not size the frame.
