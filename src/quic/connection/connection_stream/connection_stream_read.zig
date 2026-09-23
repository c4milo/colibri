//! The application reads what the peer sent on a stream, in order (decision 61). Part of design §8
//! step 9e.
//!
//! The octets waited in the connection's receive pool (`stream_incoming.zig`). A read copies them
//! from the lowest offset not yet read up to the first that has not arrived, and what it copied is
//! what the application consumed: RFC 9000 §4.1 measures new credit from it, so reading is what
//! lets the peer send more. The pool's blocks go back as they are read.
const std = @import("std");
const assert = std.debug.assert;
const stream_module = @import("../../stream/stream.zig");
const connection_module = @import("../connection.zig");
const stream_close = @import("connection_stream_close.zig");

const Connection = connection_module.Connection;
const StreamId = stream_module.StreamId;

pub const Error = error{
    /// The identifier names no stream this endpoint receives on now: one not opened, one closed,
    /// or one only this endpoint sends on (RFC 9000 §2.1). Nothing changed.
    NotReadable,
    /// The peer reset the stream (RFC 9000 §19.4), so its octets are not delivered. It is said
    /// once, which moves the stream to "Reset Read" (§3.2).
    StreamReset,
};

/// What one read took.
pub const Read = struct {
    /// Octets written to the front of the output.
    len: usize,
    /// Whether the application now has every octet up to the final size (RFC 9000 §4.5), which
    /// moves the stream to "Data Read" (§3.2).
    fin: bool,
};

/// Copies the octets of stream `id` the application has not read, up to the first that has not
/// arrived, into `output`. The connection must have been given a receive pool.
pub fn read(connection: *Connection, id: StreamId, output: []u8) Error!Read {
    // Decision 61: a connection given no pool keeps no octets, so a read of one is the caller's
    // defect rather than something a peer can cause.
    const storage = connection.receive_storage.?;
    if (!id.is_receivable_by(connection.streams.role)) return Error.NotReadable;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return Error.NotReadable,
    };
    // RFC 9000 §3.2: "Receiving RESET_STREAM causes the receiving part of a stream to transition
    // to 'Reset Recvd'", and the application is told of the reset instead of the octets.
    if (stream.receiving.state == .reset_recvd) {
        _ = stream.receiving.on(.application_read_reset);
        // RFC 9000 §3.2: "Reset Read" ends the receiving part, which may finish the stream.
        _ = stream_close.close_if_finished(connection, stream);
        return Error.StreamReset;
    }
    const len = stream.incoming.read(storage, stream.receive_flow.consumed, output);
    // RFC 9000 §4.1: both limits are measured from what was consumed.
    stream.receive_flow.consume(len);
    connection.receive_flow.consume(len);
    const final_size = stream.receiving.final_size orelse return .{ .len = len, .fin = false };
    const fin = stream.receive_flow.consumed == final_size;
    assert(stream.receive_flow.consumed <= final_size);
    if (!fin) return .{ .len = len, .fin = false };
    // RFC 9000 §3.2: "Data Recvd" becomes "Data Read" once the application has every octet,
    // which ends the receiving part and may finish the stream.
    _ = stream.receiving.on(.application_read_all);
    _ = stream_close.close_if_finished(connection, stream);
    return .{ .len = len, .fin = true };
}

test {
    _ = @import("connection_stream_read_test.zig");
}
