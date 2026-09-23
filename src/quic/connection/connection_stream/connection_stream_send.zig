//! The STREAM frames this endpoint sends (RFC 9000 §19.8), one per packet (decision 56), with
//! their octets read from the caller's stream provider (decision 57). Part of design §8 step 9e.
//!
//! The caller opens a stream and says how far its octets reach with `supply`. It passes no
//! octets: `send` reads them through the provider when a packet has room, and reads a lost range
//! again the same way. Lost ranges go first (RFC 9000 §13.3), and new octets wait while any is
//! owed, which is what bounds the lost table (decision 57).
//!
//! Which stream's octets go next is the frame scheduler's
//! (https://github.com/c4milo/colibri/issues/29). Until there is one, the first stream in the
//! table's order that has octets and credit to send them goes first.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../../constants.zig");
const frame_stream = @import("../../frame/frame_stream.zig");
const stream_module = @import("../../stream/stream.zig");
const stream_provider_module = @import("../../stream/stream_provider.zig");
const connection_module = @import("../connection.zig");
const connection_stream_frames = @import("connection_stream_frames.zig");

const Writer = core.Writer;
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

/// Frames the new octets of the first stream that has some and the credit to send them.
fn write_new(connection: *Connection, stream_provider: StreamProvider, output: []u8) Written {
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        const owed = owed_new(connection, stream) orelse continue;
        const written = frame(stream_provider, owed, output);
        // No room here, or a provider with nothing yet for this stream: another may have some.
        if (written.len == 0) continue;
        on_new_framed(connection, stream, written);
        return written;
    }
    return .{};
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
}
