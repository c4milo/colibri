//! The octets of each request stream of a QUIC client connection (decision 79), split from
//! `quic_connection_h3.zig` in design §8 step 39. A request stream carries the HEADERS frame and,
//! when the request has content, one DATA frame header, which the connection keeps, then the
//! request's content from the caller's memory. QUIC reads them by offset, and may read them again
//! until the stream closes (RFC 9000 §3.1), so an ended exchange holds its octets until then.
const quic = @import("quic");
const constants = @import("../constants.zig");
const slots_module = @import("../slots.zig");
const quic_connection = @import("quic_connection.zig");

const QuicConnection = quic_connection.QuicConnection;
const Slot = slots_module.Slot;
const StreamProvider = quic.stream.StreamProvider;

/// The frames of one request stream the connection keeps (decision 79).
pub const RequestStream = struct {
    /// The HEADERS frame, then the DATA frame's header when the request has content.
    prefix: [constants.limits.request_prefix_len_max]u8,
    prefix_len: usize,
};

/// The provider QUIC reads the request streams from: h3 serves its own streams, and the rest come
/// from the requests (decision 79).
pub fn provider(connection: *QuicConnection) StreamProvider {
    return connection.h3.provider(.{ .context = connection, .vtable = &vtable });
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_request };

/// A request stream's octets from `offset`: its kept frames, then the request's content. Every
/// call at one offset answers the same octets, which RFC 9000 §2.2 asks of a retransmission.
fn read_request(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const connection: *QuicConnection = @ptrCast(@alignCast(context));
    const slot = holding(connection, stream_id) orelse return 0;
    const stream = &connection.streams[connection.slots.index_of(slot)];
    const content = slot.request.body;
    const from: usize = @intCast(offset);
    if (from >= stream.prefix_len + content.len) return 0;
    var written: usize = 0;
    if (from < stream.prefix_len) {
        written = @min(output.len, stream.prefix_len - from);
        @memcpy(output[0..written], stream.prefix[from..][0..written]);
        // The output filled before the kept frames ended.
        if (written < stream.prefix_len - from) return written;
    }
    // The content follows the kept frames in the same call, as far as `output` holds.
    const content_from = from + written - stream.prefix_len;
    const len = @min(output.len - written, content.len - content_from);
    @memcpy(output[written..][0..len], content[content_from..][0..len]);
    return written + len;
}

/// The slot whose stream is `stream_id` and may still send its octets, or null: an exchange the
/// caller cancelled holds none, so QUIC reads nothing of its memory.
fn holding(connection: *QuicConnection, stream_id: u64) ?*Slot {
    for (&connection.slots.slots) |*slot| {
        if (slot.holds_octets and slot.stream_id == stream_id) return slot;
    }
    return null;
}

/// Releases the octets of every stream that closed: QUIC sends nothing on it again (RFC 9000
/// §3.1), so its exchange's `finished` event may go out.
pub fn release_closed(connection: *QuicConnection) void {
    for (&connection.slots.slots) |*slot| {
        if (!slot.holds_octets) continue;
        if (connection.transport.streams.lookup(.{ .value = slot.stream_id }) == .live) continue;
        slot.holds_octets = false;
    }
}
