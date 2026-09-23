//! The flow control frames (RFC 9000 §4.1, §4.6): MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS, the
//! limits this endpoint gives its peer (§19.9 to §19.11), and DATA_BLOCKED, STREAM_DATA_BLOCKED
//! and STREAMS_BLOCKED, which say the peer's limits are holding this endpoint back (§19.12 to
//! §19.14). Part of design §8 step 9e.
//!
//! `flow.Receiver` decides when new credit is worth a frame, and grows its window (decision 49).
//! What it measures from is what the application consumed, so `consume` is how the caller says it
//! read octets, and reading is what lets the peer send more (§4.1). A stream count is given back
//! when a stream the peer opened closes (`Streams.close`, §4.6).
//!
//! A BLOCKED frame goes out once per limit, and only while this endpoint has something the limit
//! holds back: octets to send (§4.1), or a stream it tried to open (§4.6).
//!
//! A sender that stays blocked with nothing in flight sends them again one PTO after its last
//! ack-eliciting packet (`blocked_deadline_ns`), because §4.1 asks for it "periodically" so the
//! peer's idle timeout does not close the connection.
//!
//! RFC 9000 §13.3 sends a lost limit frame again at the current value, and only when the lost
//! packet carried the most recent frame for its scope; a lost BLOCKED frame likewise, and only
//! while the endpoint is still blocked on that limit. Each scope keeps that packet's number in a
//! `frame.Latest`, so a loss is matched by number and nothing is kept per packet.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
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

/// Writes the DATA_BLOCKED, STREAMS_BLOCKED and STREAM_DATA_BLOCKED frames owed now, each naming
/// the limit current when it is written, and records packet `number` as the one carrying them.
/// True when any went in.
pub fn write_blocked(connection: *Connection, level: Level, writer: *Writer, number: u64) bool {
    // RFC 9000 §12.4, Table 3 marks all three "__01", as it does the limit frames.
    if (level != .application) return false;
    var wrote = write_data_blocked(connection, writer, number);
    for ([_]Directionality{ .bidirectional, .unidirectional }) |directionality| {
        if (write_streams_blocked(connection, directionality, writer, number)) wrote = true;
    }
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        if (write_stream_data_blocked(stream, writer, number)) wrote = true;
    }
    return wrote;
}

/// Owes a flow control frame again for every scope whose most recent one the lost packets
/// carried (RFC 9000 §13.3: "An updated value is sent in a MAX_DATA frame if the packet
/// containing the most recently sent MAX_DATA frame is declared lost", the same for the other
/// limits, and "A new frame is sent if a packet containing the most recent frame for a scope is
/// lost" for the blocked ones). The records are one space's, and only 1-RTT packets carried these
/// frames.
pub fn on_packets_lost(connection: *Connection, level: Level, lost: []const Record) void {
    if (level != .application) return;
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (lost) |record| {
        connection.max_data.on_lost(record.number);
        connection.data_blocked.on_lost(record.number);
        for (&connection.streams.max_streams) |*latest| latest.on_lost(record.number);
        for (&connection.streams.streams_blocked) |*latest| latest.on_lost(record.number);
        var walk = connection.streams.pool.iterator();
        // Bounded by the table's capacity, `streams_per_connection_max`.
        while (walk.next()) |stream| {
            stream.max_stream_data.on_lost(record.number);
            stream.stream_data_blocked.on_lost(record.number);
        }
    }
}

/// RFC 9000 §19.9: the connection's limit, when new credit is worth a frame or a lost one is owed.
fn write_max_data(connection: *Connection, writer: *Writer, number: u64, now_ns: u64, round_trip_ns: u64) bool {
    const fresh = connection.receive_flow.credit_frame_limit(now_ns, round_trip_ns) != null;
    if (!fresh and !connection.max_data.owed) return false;
    const frame: frame_module.Frame = .{ .max_data = .{ .maximum = connection.receive_flow.limit } };
    return connection.max_data.write(writer, frame, number);
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
    return streams.max_streams[which].write(writer, frame, number);
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
    return stream.max_stream_data.write(writer, frame, number);
}

/// The instant the BLOCKED frames are owed again, or null when they are not. RFC 9000 §4.1: "To
/// keep the connection from closing, a sender that is flow control limited SHOULD periodically
/// send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it has no ack-eliciting packets in
/// flight." The period runs from the last ack-eliciting 1-RTT packet, which is the space both
/// frames travel in (§12.4, Table 3).
pub fn blocked_deadline_ns(connection: *Connection) ?u64 {
    if (connection.termination.state != .active) return null;
    const application = @intFromEnum(Level.application);
    const since_ns = connection.recovery.timer.spaces[application].last_ack_eliciting_sent_at_ns orelse return null;
    if (ack_eliciting_in_flight(connection)) return null;
    if (!is_flow_limited(connection)) return null;
    const probe_timeout_ns = connection.recovery.rtt.probe_timeout_ns(true);
    return since_ns +| constants.blocked_repeat_probe_timeouts *| probe_timeout_ns;
}

/// Owes again each DATA_BLOCKED and STREAM_DATA_BLOCKED frame whose limit still holds octets back,
/// once `blocked_deadline_ns` has come (RFC 9000 §4.1).
pub fn on_blocked_deadline(connection: *Connection) void {
    if (is_data_blocked(connection)) connection.data_blocked.owed = true;
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        if (is_stream_data_blocked(stream)) stream.stream_data_blocked.owed = true;
    }
}

/// Whether any packet in flight elicits an acknowledgment, in any space (RFC 9002 §2).
fn ack_eliciting_in_flight(connection: *Connection) bool {
    // Bounded by the three spaces of RFC 9000 §12.3.
    for (&connection.recovery.tables) |*table| {
        if (table.ack_eliciting_count() > 0) return true;
    }
    return false;
}

/// Whether either limit holds back octets this endpoint has to send (RFC 9000 §4.1).
fn is_flow_limited(connection: *Connection) bool {
    if (is_data_blocked(connection)) return true;
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        if (is_stream_data_blocked(stream)) return true;
    }
    return false;
}

/// RFC 9000 §4.1: the connection's limit holds back octets a stream has to send.
fn is_data_blocked(connection: *Connection) bool {
    return connection.send_flow.is_blocked() and has_unframed_octets(connection);
}

/// RFC 9000 §4.1: one stream's limit holds back octets it has to send.
fn is_stream_data_blocked(stream: *const Stream) bool {
    return stream.send_flow.is_blocked() and stream.sending.may_send_data() and stream.outgoing.unframed_len() > 0;
}

/// RFC 9000 §19.12: the connection's limit holds back octets this endpoint has to send (§4.1: a
/// sender "has data to write but is blocked by flow control limits").
fn write_data_blocked(connection: *Connection, writer: *Writer, number: u64) bool {
    const sender = &connection.send_flow;
    const blocked = is_data_blocked(connection);
    const fresh = blocked and sender.blocked_frame_limit() != null;
    const frame: frame_module.Frame = .{ .data_blocked = .{ .limit = sender.limit } };
    return write_blocked_frame(writer, frame, blocked, fresh, &connection.data_blocked, number);
}

/// RFC 9000 §19.14: the peer's limit refused a stream this endpoint tried to open (§4.6: "An
/// endpoint that is unable to open a new stream due to the peer's limits SHOULD send a
/// STREAMS_BLOCKED frame").
fn write_streams_blocked(connection: *Connection, directionality: Directionality, writer: *Writer, number: u64) bool {
    const streams = &connection.streams;
    const which = @intFromEnum(directionality);
    const blocked = streams.open_refused[which] and streams.local_limit[which].is_blocked();
    const fresh = blocked and streams.blocked_frame_limit(directionality) != null;
    const frame: frame_module.Frame = .{ .streams_blocked = .{
        .directionality = frame_directionality(directionality),
        .limit = streams.local_limit[which].limit,
    } };
    return write_blocked_frame(writer, frame, blocked, fresh, &streams.streams_blocked[which], number);
}

/// RFC 9000 §19.13: one stream's limit holds back octets it has to send.
fn write_stream_data_blocked(stream: *Stream, writer: *Writer, number: u64) bool {
    const blocked = is_stream_data_blocked(stream);
    const fresh = blocked and stream.send_flow.blocked_frame_limit() != null;
    const frame: frame_module.Frame = .{ .stream_data_blocked = .{ .stream_id = stream.id, .limit = stream.send_flow.limit } };
    return write_blocked_frame(writer, frame, blocked, fresh, &stream.stream_data_blocked, number);
}

/// Writes a blocked frame when a new limit blocks or a lost one is owed, and drops what is owed
/// once the endpoint is no longer blocked: RFC 9000 §13.3 resends one "only while the endpoint is
/// blocked on the corresponding limit".
fn write_blocked_frame(
    writer: *Writer,
    frame: frame_module.Frame,
    blocked: bool,
    fresh: bool,
    latest: *frame_module.Latest,
    number: u64,
) bool {
    if (!blocked) {
        latest.owed = false;
        return false;
    }
    if (!fresh and !latest.owed) return false;
    return latest.write(writer, frame, number);
}

/// Whether any stream has octets it could send if the connection's limit let it.
fn has_unframed_octets(connection: *Connection) bool {
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        if (stream.sending.may_send_data() and stream.outgoing.unframed_len() > 0) return true;
    }
    return false;
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
