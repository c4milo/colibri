//! When a stream is done with (RFC 9000 §3), and what closing it gives back. Part of design §8
//! step 9e.
//!
//! A stream is finished once each part it has is in a terminal state: the sending part in "Data
//! Recvd" or "Reset Recvd" (§3.1), the receiving part in "Data Read" or "Reset Read" (§3.2). A
//! unidirectional stream has one part at this endpoint and a bidirectional one has both. Closing
//! frees the stream's slot in the table and its receive-pool blocks (decision 61), and for a
//! stream the peer opened it counts toward the MAX_STREAMS credit (§4.6).
//!
//! Every transition that can finish a part is followed by `close_if_finished`: an
//! acknowledgment that moves the sending part to "Data Recvd" or "Reset Recvd", and a read that
//! moves the receiving part to "Data Read" or "Reset Read".
const std = @import("std");
const assert = std.debug.assert;
const stream_module = @import("../../stream/stream.zig");
const connection_module = @import("../connection.zig");

const Connection = connection_module.Connection;
const Stream = stream_module.Stream;

/// Closes `stream` when each of its parts is finished, and answers whether it did. `stream` is
/// not to be used once this answers true.
pub fn close_if_finished(connection: *Connection, stream: *Stream) bool {
    const id = stream.stream_identifier();
    const role = connection.streams.role;
    // RFC 9000 §3.1: "Data Recvd" and "Reset Recvd" end the sending part.
    if (id.is_sendable_by(role) and !stream.sending.state.is_terminal()) return false;
    // RFC 9000 §3.2: "Data Read" and "Reset Read" end the receiving part.
    if (id.is_receivable_by(role) and !stream.receiving.state.is_terminal()) return false;
    // Decision 61: what the stream still held in the receive pool goes back to it.
    if (connection.receive_storage) |storage| stream.incoming.release(storage);
    connection.streams.close(id);
    assert(connection.streams.lookup(id) == .closed);
    return true;
}

test {
    // The tests share `connection_stream_read_test.zig`'s pair, which reads what closing needs.
    _ = @import("connection_stream_read_test.zig");
}
