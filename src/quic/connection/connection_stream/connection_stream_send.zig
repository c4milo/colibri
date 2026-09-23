//! The STREAM frames this endpoint sends (RFC 9000 §19.8), one per packet (decision 56), with
//! their octets read from the caller's stream provider (decision 57). Part of design §8 step 9e.
//!
//! The caller opens a stream and says how far its octets reach with `supply`. It passes no
//! octets: `send` reads them through the provider when a packet has room, and reads a lost range
//! again the same way. Lost ranges go first (RFC 9000 §13.3), and new octets wait while any is
//! owed, which is what bounds the lost table (decision 57).
//!
//! Which stream's new octets go next is RFC 9000 §2.3's: the caller sets a priority per stream,
//! a lower value goes first, and streams of one value take turns (`set_priority`).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../../constants.zig");
const frame_module = @import("../../frame/frame.zig");
const frame_stream = @import("../../frame/frame_stream.zig");
const stream_module = @import("../../stream/stream.zig");
const stream_provider_module = @import("../../stream/stream_provider.zig");
const connection_module = @import("../connection.zig");
const connection_stream_frames = @import("connection_stream_frames.zig");

const Writer = core.Writer;
const Level = core.Level;
const Connection = connection_module.Connection;
const Stream = stream_module.Stream;
const Streams = stream_module.Streams;
const StreamId = stream_module.StreamId;
const Directionality = stream_module.Directionality;
const Range = stream_module.stream_lost.Range;
const StreamProvider = stream_provider_module.StreamProvider;

pub const Error = error{
    /// The identifier names no stream this endpoint may still send on: one not opened, one
    /// closed, one only the peer sends on (RFC 9000 §2.1), or one the caller already ended or
    /// reset (§3.1). Nothing changed.
    NotWritable,
    /// RFC 9000 §19.8: a stream cannot reach past 2^62-1. Nothing changed.
    OffsetTooLarge,
    /// The identifier names no stream this endpoint receives on now, or one whose receiving part
    /// has left "Recv" and "Size Known", where RFC 9000 §19.5 permits STOP_SENDING. Nothing
    /// changed.
    NotReadable,
};

/// Opens the next stream this endpoint initiates (RFC 9000 §2.1), with the limits the peer's
/// parameters give it (§18.2).
pub fn open(connection: *Connection, directionality: Directionality) stream_module.stream_table.OpenError!StreamId {
    const stream = try connection.streams.open_local(directionality);
    const id = stream.stream_identifier();
    connection_stream_frames.initialise_flow(connection, stream, id);
    return id;
}

/// Says the caller's octets on `id` now reach `end`, never below what it said before, and that
/// the stream ends there when `fin` is set (RFC 9000 §4.5). The caller keeps the octets until
/// colibri reports the stream in "Data Recvd" or reset (decision 57).
pub fn supply(connection: *Connection, id: StreamId, end: u64, fin: bool) Error!void {
    if (!id.is_sendable_by(connection.streams.role)) return Error.NotWritable;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return Error.NotWritable,
    };
    // RFC 9000 §3.1: "Ready" and "Send" accept data from the application, until it ends the
    // stream.
    if (!stream.sending.may_send_data() or stream.outgoing.finished) return Error.NotWritable;
    stream.outgoing.supply(end, fin) catch return Error.OffsetTooLarge;
}

/// Abandons sending on `id` with the application's `error_code` (RFC 9000 §3.1, §19.4). colibri
/// owes a RESET_STREAM from here on and reads none of the stream's octets again, so the caller may
/// drop them (decision 57).
pub fn reset(connection: *Connection, id: StreamId, error_code: u64) Error!void {
    if (!id.is_sendable_by(connection.streams.role)) return Error.NotWritable;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return Error.NotWritable,
    };
    // RFC 9000 §3.1: "Reset Sent" is reached from "Ready", "Send" and "Data Sent" alone.
    if (!connection.streams.reset(stream, error_code)) return Error.NotWritable;
}

/// Asks the peer to stop sending on `id`, because the application reads no more of it (RFC 9000
/// §3.5), with the application's `error_code`. Asking twice changes nothing.
pub fn stop_sending(connection: *Connection, id: StreamId, error_code: u64) Error!void {
    if (!id.is_receivable_by(connection.streams.role)) return Error.NotReadable;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return Error.NotReadable,
    };
    // RFC 9000 §19.5: "A STOP_SENDING frame can be sent for streams in the 'Recv' or 'Size Known'
    // states".
    if (!wants_stop_sending(stream)) return Error.NotReadable;
    if (stream.stop_sending.owed or stream.stop_sending.sent) return;
    stream.stop_error_code = error_code;
    stream.stop_sending.owed = true;
}

/// Writes the RESET_STREAM and STOP_SENDING frames owed now (RFC 9000 §19.4, §19.5) and records
/// packet `number` as the one carrying them. True when any went in.
pub fn write_endings(connection: *Connection, level: Level, writer: *Writer, number: u64) bool {
    // RFC 9000 §12.4, Table 3 marks both "__01", and decision 20 refuses 0-RTT.
    if (level != .application) return false;
    var wrote = false;
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        if (write_reset(stream, writer, number)) wrote = true;
        if (write_stop_sending(stream, writer, number)) wrote = true;
    }
    return wrote;
}

/// RFC 9000 §19.4. The final size is every octet framed: nothing is framed after the reset, so
/// it is the same in every copy (§13.3: "The content of a RESET_STREAM frame MUST NOT change when
/// it is sent again") and it is what both flow control limits counted (§4.5).
fn write_reset(stream: *Stream, writer: *Writer, number: u64) bool {
    if (!stream.reset_stream.owed) return false;
    // A RESET_STREAM is owed only from "Reset Sent", which only its acknowledgment leaves.
    assert(stream.sending.state == .reset_sent);
    const reset_frame: frame_module.Frame = .{ .reset_stream = .{
        .stream_id = stream.id,
        .error_code = stream.reset_error_code,
        .final_size = stream.outgoing.framed_end,
    } };
    return stream.reset_stream.write(writer, reset_frame, number);
}

/// RFC 9000 §19.5, sent until the receiving part leaves "Recv" and "Size Known" (§3.5: then
/// "sending a STOP_SENDING frame is unnecessary").
fn write_stop_sending(stream: *Stream, writer: *Writer, number: u64) bool {
    if (!stream.stop_sending.owed) return false;
    if (!wants_stop_sending(stream)) {
        stream.stop_sending.owed = false;
        return false;
    }
    const stop_frame: frame_module.Frame = .{ .stop_sending = .{ .stream_id = stream.id, .error_code = stream.stop_error_code } };
    return stream.stop_sending.write(writer, stop_frame, number);
}

/// Whether the peer may still send on `stream`, which is when STOP_SENDING has a use (RFC 9000
/// §3.5, §19.5).
fn wants_stop_sending(stream: *const Stream) bool {
    return stream.receiving.state == .recv or stream.receiving.state == .size_known;
}

/// What one STREAM frame took, which the send path puts in the packet's record (RFC 9000 §13.3).
pub const Written = struct {
    /// Octets of `output` the frame occupies. 0 means none was written.
    len: usize = 0,
    stream_id: u64 = 0,
    offset: u64 = 0,
    data_len: u16 = 0,
    fin: bool = false,
};

/// Writes one STREAM frame into `output` (RFC 9000 §19.8): the oldest lost range when one is
/// owed, and a stream's new octets when none is.
pub fn write(connection: *Connection, stream_provider: StreamProvider, output: []u8) Written {
    drop_unneeded(&connection.streams);
    // RFC 9000 §13.3: "Endpoints SHOULD prioritize retransmission of data over sending new data".
    if (connection.streams.lost.oldest()) |range| {
        const written = frame(stream_provider, range, output);
        if (written.len > 0) connection.streams.lost.take_oldest(written.data_len, written.fin);
        return written;
    }
    return write_new(connection, stream_provider, output);
}

/// Drops the lost ranges at the front that no stream needs any more: RFC 9000 §13.3, "Once an
/// endpoint sends a RESET_STREAM frame, no further STREAM frames are needed", and a closed stream
/// needs none.
fn drop_unneeded(streams: *Streams) void {
    // Bounded by the table, each pass dropping one range or stopping.
    for (0..constants.stream_lost_ranges_max) |_| {
        const range = streams.lost.oldest() orelse return;
        const needed = switch (streams.lookup(.{ .value = range.stream_id })) {
            .live => |stream| stream.sending.retransmits_data(),
            .closed => false,
            // Nothing is framed on a stream before it opens.
            .unopened => unreachable,
        };
        if (needed) return;
        streams.lost.drop_oldest();
    }
}

/// Frames the new octets of the stream RFC 9000 §2.3's order puts first: the lowest priority
/// value, and among streams of one value, the next after the one that sent last, so they take
/// turns. A stream that frames nothing, for want of room or of octets from the provider, gives way
/// to the next.
fn write_new(connection: *Connection, stream_provider: StreamProvider, output: []u8) Written {
    var tried: [constants.streams_per_connection_max]bool = @splat(false);
    // Bounded by the table's capacity: each pass tries one stream it has not tried, or ends.
    for (0..constants.streams_per_connection_max) |_| {
        const chosen = choose(connection, &tried) orelse return .{};
        tried[chosen.slot] = true;
        const written = frame(stream_provider, chosen.owed, output);
        if (written.len == 0) continue;
        on_new_framed(connection, chosen.stream, written);
        connection.streams.send_turn = chosen.slot;
        return written;
    }
    return .{};
}

/// A stream with new octets to send, where it sits in the table, and what it owes.
const Choice = struct {
    stream: *Stream,
    slot: u32,
    owed: Range,
};

/// The untried stream with new octets that sends next, or null when there is none.
fn choose(connection: *Connection, tried: *const [constants.streams_per_connection_max]bool) ?Choice {
    var best: ?Choice = null;
    var best_rank: u64 = 0;
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        // The iterator has moved one past the slot it returned.
        const slot = walk.slot - 1;
        if (tried[slot]) continue;
        const owed = owed_new(connection, stream) orelse continue;
        const rank = rank_of(stream.priority, slot, connection.streams.send_turn);
        if (best != null and rank >= best_rank) continue;
        best = .{ .stream = stream, .slot = slot, .owed = owed };
        best_rank = rank;
    }
    return best;
}

/// Orders streams by priority, then by how far past the last one to send a stream's slot is, so
/// the next slot after it ranks first among equals (RFC 9000 §2.3).
fn rank_of(priority: u8, slot: u32, turn: u32) u64 {
    const capacity = constants.streams_per_connection_max;
    const distance = (slot + capacity - turn - 1) % capacity;
    return @as(u64, priority) * capacity + distance;
}

/// Sets where `id`'s new octets go against other streams': a lower value first, and streams of
/// one value take turns. RFC 9000 §2.3: "A QUIC implementation SHOULD provide ways in which an
/// application can indicate the relative priority of streams." Lost octets still go before any
/// new ones (§13.3).
pub fn set_priority(connection: *Connection, id: StreamId, priority: u8) Error!void {
    if (!id.is_sendable_by(connection.streams.role)) return Error.NotWritable;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return Error.NotWritable,
    };
    stream.priority = priority;
}

/// The new octets of `stream` that may go out now, or null when there are none.
fn owed_new(connection: *const Connection, stream: *const Stream) ?Range {
    // RFC 9000 §3.1: new data leaves from "Ready" or "Send" alone.
    if (!stream.sending.may_send_data()) return null;
    const outgoing = &stream.outgoing;
    // RFC 9000 §4.1: "Senders MUST NOT send data in excess of either limit."
    const credit = @min(stream.send_flow.available(), connection.send_flow.available());
    const len = @min(outgoing.unframed_len(), credit);
    // RFC 9000 §4.5: the FIN goes with the stream's last octet, or alone after it.
    const fin = outgoing.owes_fin() and len == outgoing.unframed_len();
    if (len == 0 and !fin) return null;
    return .{ .stream_id = stream.id, .offset = outgoing.framed_end, .len = len, .fin = fin };
}

/// Spends the credit new octets took and moves the stream on.
fn on_new_framed(connection: *Connection, stream: *Stream, written: Written) void {
    // RFC 9000 §4.1: new octets count against the stream's limit and the connection's. A lost
    // range sent again counts against neither, because its offsets were counted once already.
    stream.send_flow.spend(written.data_len);
    connection.send_flow.spend(written.data_len);
    stream.outgoing.on_framed(written.data_len, written.fin);
    // RFC 9000 §3.1: a STREAM frame enters "Send", and one carrying the FIN enters "Data Sent".
    _ = stream.sending.on(if (written.fin) .sent_fin else .sent_data);
}

/// Frames as much of `owed` as `output` and the provider allow, with the FIN when the frame
/// carries the range's last octet. Nothing is written when `output` cannot hold the header and
/// something after it, or when the provider has no octets for a range that has some.
fn frame(stream_provider: StreamProvider, owed: Range, output: []u8) Written {
    // `Record.data_len` is 16 bits, and a packet never exceeds the largest UDP payload
    // (RFC 9000 §18.2), which `datagram_ceiling` bounds every datagram by.
    assert(output.len <= constants.datagram_len_max);
    const cap = @min(owed.len, output.len);
    const length_len = wire.varint.encoded_len_minimal(cap);
    const header_len = frame_stream.stream_header_len(owed.stream_id, owed.offset, length_len);
    if (output.len < header_len) return .{};
    const data_max = @min(cap, output.len - header_len);
    const data_len = if (data_max == 0) 0 else stream_provider.read(owed.stream_id, owed.offset, output[header_len..][0..data_max]);
    // A range with octets needs at least one of them in the frame; a FIN alone needs none.
    if (owed.len > 0 and data_len == 0) return .{};
    const fin = owed.fin and data_len == owed.len;
    var writer = Writer.init(output[0..header_len]);
    // The header was measured for exactly this room, so it cannot fall short.
    frame_stream.write_stream_header(&writer, .{
        .stream_id = owed.stream_id,
        .offset = owed.offset,
        .data_len = data_len,
        .length_len = length_len,
        .fin = fin,
    }) catch unreachable;
    assert(writer.written().len == header_len);
    return .{
        .len = header_len + data_len,
        .stream_id = owed.stream_id,
        .offset = owed.offset,
        .data_len = @intCast(data_len),
        .fin = fin,
    };
}

test {
    _ = @import("connection_stream_send_test.zig");
    _ = @import("connection_stream_send_ending_test.zig");
    _ = @import("connection_stream_send_priority_test.zig");
}
