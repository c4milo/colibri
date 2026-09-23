//! The limits this endpoint gives its peer (RFC 9000 §4.1, §4.6): MAX_DATA, MAX_STREAM_DATA and
//! MAX_STREAMS (§19.9 to §19.11). Part of design §8 step 9e.
//!
//! `flow.Receiver` decides when new credit is worth a frame, and grows its window (decision 49).
//! What it measures from is what the application consumed, so `consume` is how the caller says it
//! read octets, and reading is what lets the peer send more (§4.1). A stream count is given back
//! when a stream the peer opened closes (`Streams.close`, §4.6).
//!
//! RFC 9000 §13.3 sends a lost limit frame again at the current value, and only when the lost
//! packet carried the most recent frame for its scope. Each scope keeps that packet's number in a
//! `flow.Advertised`, so a loss is matched by number and nothing is kept per packet.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const flow = @import("../flow.zig");
const frame_module = @import("../frame/frame.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const stream_module = @import("../stream/stream.zig");
const connection_module = @import("connection.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Record = recovery_sent.Record;
const Stream = stream_module.Stream;
const StreamId = stream_module.StreamId;
const Directionality = stream_module.Directionality;

pub const Error = error{
    /// The identifier names no stream this endpoint receives on now: one not opened, one closed,
    /// or one only this endpoint sends on (RFC 9000 §2.1). Nothing changed.
    NotReadable,
};

/// Records that the application read `len` more octets of stream `id`, in order. RFC 9000 §4.1:
/// "a receiver could determine the flow control offset to be advertised based on the current
/// offset of data consumed on a stream", and both limits, the stream's and the connection's, are
/// measured from it. `len` never passes what arrived.
pub fn consume(connection: *Connection, id: StreamId, len: u64) Error!void {
    if (!id.is_receivable_by(connection.streams.role)) return Error.NotReadable;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return Error.NotReadable,
    };
    stream.receive_flow.consume(len);
    connection.receive_flow.consume(len);
}

/// Writes the MAX_DATA, MAX_STREAMS and MAX_STREAM_DATA frames owed now, each at the limit current
/// when it is written, and records packet `number` as the one carrying them. True when any went
/// in. A frame that does not fit stays owed for the next packet.
pub fn write_limits(connection: *Connection, level: Level, writer: *Writer, number: u64, now_ns: u64) bool {
    // RFC 9000 §12.4, Table 3 marks all three "__01", and decision 20 refuses 0-RTT, so they
    // travel in 1-RTT packets alone.
    if (level != .application) return false;
    const round_trip_ns = round_trip_of(connection);
    var wrote = write_max_data(connection, writer, number, now_ns, round_trip_ns);
    for ([_]Directionality{ .bidirectional, .unidirectional }) |directionality| {
        if (write_max_streams(connection, directionality, writer, number, now_ns)) wrote = true;
    }
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        if (write_max_stream_data(connection, stream, writer, number, now_ns, round_trip_ns)) wrote = true;
    }
    return wrote;
}

/// Owes a limit frame again for every scope whose most recent one the lost packets carried
/// (RFC 9000 §13.3: "An updated value is sent in a MAX_DATA frame if the packet containing the
/// most recently sent MAX_DATA frame is declared lost", and the same for the other two). The
/// records are one space's, and only 1-RTT packets carried these frames.
pub fn on_packets_lost(connection: *Connection, level: Level, lost: []const Record) void {
    if (level != .application) return;
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (lost) |record| {
        connection.max_data.on_lost(record.number);
        for (&connection.streams.max_streams) |*advertised| advertised.on_lost(record.number);
        var walk = connection.streams.pool.iterator();
        // Bounded by the table's capacity, `streams_per_connection_max`.
        while (walk.next()) |stream| stream.max_stream_data.on_lost(record.number);
    }
}

/// RFC 9000 §19.9: the connection's limit, when new credit is worth a frame or a lost one is owed.
fn write_max_data(connection: *Connection, writer: *Writer, number: u64, now_ns: u64, round_trip_ns: u64) bool {
    const fresh = connection.receive_flow.credit_frame_limit(now_ns, round_trip_ns) != null;
    if (!fresh and !connection.max_data.owed) return false;
    const frame: frame_module.Frame = .{ .max_data = .{ .maximum = connection.receive_flow.limit } };
    return write_or_owe(writer, frame, &connection.max_data, number);
}

/// RFC 9000 §19.11: how many streams of one type the peer may open, once enough of them closed.
fn write_max_streams(connection: *Connection, directionality: Directionality, writer: *Writer, number: u64, now_ns: u64) bool {
    const streams = &connection.streams;
    const which = @intFromEnum(directionality);
    const fresh = streams.peer_limit_frame(directionality, now_ns) != null;
    if (!fresh and !streams.max_streams[which].owed) return false;
    const frame: frame_module.Frame = .{ .max_streams = .{
        .directionality = frame_directionality(directionality),
        .maximum = streams.peer_limit[which].limit,
    } };
    return write_or_owe(writer, frame, &streams.max_streams[which], number);
}

/// RFC 9000 §19.10: one stream's limit. §13.3: "An endpoint SHOULD stop sending MAX_STREAM_DATA
/// frames when the receiving part of the stream enters a 'Size Known' or 'Reset Recvd' state",
/// because the peer can send no more than the final size whatever the limit says.
fn write_max_stream_data(
    connection: *const Connection,
    stream: *Stream,
    writer: *Writer,
    number: u64,
    now_ns: u64,
    round_trip_ns: u64,
) bool {
    if (stream.receiving.state != .recv) return false;
    const fresh = stream.receive_flow.credit_frame_limit(now_ns, round_trip_ns) != null;
    if (!fresh and !stream.max_stream_data.owed) return false;
    // RFC 9000 §19.10 makes MAX_STREAM_DATA for a stream the peer cannot send on a connection
    // error. Credit comes only from `consume`, which refuses such a stream, so none is owed here.
    assert(stream.stream_identifier().is_receivable_by(connection.streams.role));
    const frame: frame_module.Frame = .{ .max_stream_data = .{ .stream_id = stream.id, .maximum = stream.receive_flow.limit } };
    return write_or_owe(writer, frame, &stream.max_stream_data, number);
}

/// Writes `frame` and records the packet carrying it, or leaves the frame owed when it does not
/// fit, so the next packet carries it at the limit current then.
fn write_or_owe(writer: *Writer, frame: frame_module.Frame, advertised: *flow.Advertised, number: u64) bool {
    frame_module.write(writer, frame) catch {
        advertised.owed = true;
        return false;
    };
    advertised.on_sent(number);
    return true;
}

/// The round trip `flow.Receiver` tunes its window against (decision 49), or 0 before RFC 9002
/// has a sample, which grows nothing.
fn round_trip_of(connection: *const Connection) u64 {
    const rtt = &connection.recovery.rtt;
    if (!rtt.has_sample()) return 0;
    return rtt.smoothed_ns;
}

/// RFC 9000 §19.11's bit and §2.1's bit name the same two stream types, under the frame layer's
/// name and the stream table's.
fn frame_directionality(directionality: Directionality) frame_module.Directionality {
    return switch (directionality) {
        .bidirectional => .bidirectional,
        .unidirectional => .unidirectional,
    };
}

test {
    _ = @import("connection_flow_test.zig");
}
