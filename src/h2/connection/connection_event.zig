//! The events an h2 connection's `receive` returns, at most one per frame (decision 39), and what
//! one call consumed. `connection.zig` names each of them.
const constants = @import("../constants.zig");
const message = @import("../message/message.zig");

/// A request the peer sent, at a server: its pseudo-header fields, and the field section it came
/// from, which `field_section` returns until the next call (RFC 9113 §8.3.1).
pub const Request = struct {
    stream_id: u32,
    request: message.Request,
    end_stream: bool,
};

/// A response the peer sent, at a client (RFC 9113 §8.3.2).
pub const Response = struct {
    stream_id: u32,
    response: message.Response,
    end_stream: bool,
};

/// A trailer section the peer sent, which ends the stream (RFC 9113 §8.1).
pub const Trailers = struct {
    stream_id: u32,
};

/// DATA the peer sent. `payload` points into the caller's input and is valid until the next call.
pub const Data = struct {
    stream_id: u32,
    payload: []const u8,
    end_stream: bool,
};

/// A stream that ended with a RST_STREAM: the peer's (`stream_reset`) or colibri's
/// (`stream_refused`), carrying the code the frame names (RFC 9113 §6.4).
pub const StreamReset = struct {
    stream_id: u32,
    error_code: u32,
};

/// The GOAWAY the peer sent (RFC 9113 §6.8). Its Additional Debug Data carries no semantic value
/// and is not reported.
pub const PeerGoaway = struct {
    last_stream_id: u32,
    error_code: u32,
};

/// An ALTSVC frame the server sent, at a client (RFC 7838 §4): the Alt-Svc field value `value`
/// names alternatives for the origin of stream `stream_id`, or, on stream 0, for `origin`. Both
/// slices point into the input `receive` read.
pub const AltSvc = struct {
    stream_id: u32,
    origin: []const u8,
    value: []const u8,
};

/// What one frame meant to the caller, at most one per `receive` (decision 39).
pub const Event = union(enum) {
    /// The peer acknowledged the SETTINGS colibri sent, which are now in force (RFC 9113 §6.5.3).
    settings_acknowledged,
    /// The peer's SETTINGS frame was applied; colibri owes the acknowledgment (§6.5.3).
    settings_applied,
    /// The peer sent a PING carrying the ACK flag, with this Opaque Data (§6.7). colibri sends no PING of its own, so it never asked for one.
    ping_acknowledged: [constants.protocol.ping_len]u8,
    request: Request,
    response: Response,
    trailers: Trailers,
    data: Data,
    /// The peer ended a stream (§6.4).
    stream_reset: StreamReset,
    /// colibri ended a stream and queued the RST_STREAM (§5.4.2).
    stream_refused: StreamReset,
    goaway: PeerGoaway,
    alt_svc: AltSvc,

    /// The stream whose peer side the event ended (RFC 9113 §8.1), or null: a request, a response
    /// or DATA that carried END_STREAM, and every trailer section, which always carries it. One
    /// call answers what three kinds of event say.
    pub fn ended_stream(event: Event) ?u32 {
        return switch (event) {
            .request => |request| if (request.end_stream) request.stream_id else null,
            .response => |response| if (response.end_stream) response.stream_id else null,
            .data => |data| if (data.end_stream) data.stream_id else null,
            .trailers => |trailers| trailers.stream_id,
            else => null,
        };
    }
};

/// What one `receive` call consumed and produced.
pub const Received = struct {
    /// Octets of the caller's slice the connection took. 0 when no whole frame was there, or when
    /// the replies must be written first.
    consumed: usize,
    /// What the frame meant, when it meant anything to the caller.
    event: ?Event,
};
