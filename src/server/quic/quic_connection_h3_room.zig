//! Whether an h3 response has room for what its program waits to write (decision 119): the
//! endpoint asks once a datagram may have freed room, and reports `writable` when it has. Only the
//! peer's acknowledgments free a response's runs and its encoder's ring (RFC 9000 §3.1). Split out
//! of `quic_connection_h3.zig` for length.
const h3 = @import("h3");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");

const QuicConnection = quic_connection.QuicConnection;
const Number = quic_connection.Number;

/// Octets of a DATA frame's header at most: its type, one octet, and its length's variable-length
/// integer (RFC 9114 §7.1, RFC 9000 §16).
const data_header_len_max: usize = 1 + h3.wire.constants.varint_len_max;

/// Whether the response to request `id` has room for a head: a run for its frame (decision 119's
/// `writable`).
pub fn takes_head(connection: *QuicConnection, id: Number) bool {
    const record = quic_connection_h3.live(connection, id) orelse return false;
    return record.response.has_room();
}

/// Whether the response to request `id` takes more content: the runs of a DATA frame, and room for
/// its header among the kept frames or, for a coded response, room in the encoder's ring.
pub fn takes_content(connection: *QuicConnection, id: Number) bool {
    const record = quic_connection_h3.live(connection, id) orelse return false;
    const pieces = &record.response;
    if (pieces.runs_len + quic_connection_h3.data_runs > pieces.runs.len) return false;
    const coded = record.coded orelse return pieces.kept_room().len >= data_header_len_max;
    return coded.room_len(connection.config.encoders.?) > 0;
}

/// Whether the response to request `id` holds no run the peer has not acknowledged, so a head or a
/// trailer section larger than the room its kept frames left either fits or never will.
pub fn takes_any(connection: *QuicConnection, id: Number) bool {
    const record = quic_connection_h3.live(connection, id) orelse return false;
    return record.response.runs_len == 0;
}

/// Whether the response to request `id` takes its trailer section: a run for its frame, after a
/// coded response's encoder wrote its last octets (RFC 9110 §6.5).
pub fn takes_trailers(connection: *QuicConnection, id: Number) bool {
    const record = quic_connection_h3.live(connection, id) orelse return false;
    if (record.coded) |coded| {
        if (!coded.finished) return false;
    }
    return record.response.has_room();
}
