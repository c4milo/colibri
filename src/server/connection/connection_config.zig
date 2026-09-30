//! What every server connection over TCP borrows (decision 100), split off `connection.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md).
const std = @import("std");
const http = @import("http");
const h11 = @import("h11");
const tls = @import("tls");
const event = @import("../event.zig");
const alt_svc = @import("../alt_svc.zig");
const coding_pool = @import("../coding/coding_pool.zig");
const deadline = @import("../deadline.zig");
const constants = @import("../constants.zig");

const Protocol = event.Protocol;

/// What every connection of a server borrows. The caller keeps it alive while any connection
/// holds it.
pub const Config = struct {
    /// The TLS configuration, or null for cleartext. Its ALPN list names what the server offers,
    /// `h2` and `http/1.1` in the order it prefers them (RFC 7301 §3.2).
    tls: ?*const tls.record.ServerConfig = null,
    /// The protocol a cleartext connection speaks: h11, or h2 with prior knowledge (RFC 9113
    /// §3.3). Over TLS, ALPN chooses (decision 88).
    cleartext: Protocol = .h11,
    /// h11's decoders of the `gzip` and `deflate` transfer codings, which connections may share
    /// (decision 91). With none, h11 answers a request carrying either coding 501.
    decoders: ?h11.coding.Storage = null,
    /// Where h11 decodes a body carrying `gzip` or `deflate` (decision 98). A `body` event's octets
    /// point into it until the next `receive` of any connection sharing it. Empty with no decoders.
    decoded: []u8 = &.{},
    /// The h3 endpoint each connection over TLS advertises (decision 100): an Alt-Svc line on each
    /// final h11 response, and one ALTSVC frame per h2 connection (`alt_svc.zig`). Null for none.
    h3_alternative: ?alt_svc.Alternative = null,
    /// The content codings the server applies to a response the caller marks `codable`, in its
    /// order of preference, and the pool their encoders come from, which connections may share
    /// (decision 101). Both or neither.
    codings: []const http.content_coding.Coding = &.{},
    encoders: ?coding_pool.Encoders = null,
    /// The limits of decision 110's deadlines. A connection copies them when it starts, and
    /// `Connection.set_deadlines` changes one connection's.
    deadlines: deadline.Deadlines = .{},
    /// The shortest DATA frame h2 sends when a window, not the content, decides its length
    /// (decision 110).
    data_frame_len_min: u32 = constants.data_frame_len_min,
};
