//! HTTP/2, RFC 9113. RFC 9113 obsoletes RFC 7540; 7540 is never read and never cited.
//!
//! The pieces, bottom up: `frame` reads and writes the ten frame types (§4, §6); `settings` holds
//! the six settings and the acknowledgment discipline (§6.5); `window` is the signed flow-control
//! window (§5.2, §6.9, invariant 15); `stream` is the state machine of §5.1 as pure functions;
//! `streams` is the stream table over core's slot pool (§5.1.1, §5.1.2, decision 14);
//! `field_block` reassembles a field block fragment by fragment into one field section (§4.3,
//! decision 40); `message` checks a decoded field section as a request, a response or a trailer
//! section (§8); `connection` ties them together, one frame in and one event out (decision 39).
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const hpack = @import("hpack");
pub const tls = @import("tls");
pub const constants = @import("constants.zig");

pub const role = @import("role.zig");
pub const Role = role.Role;
pub const frame = @import("frame/frame.zig");
pub const settings = @import("settings.zig");
pub const window = @import("window.zig");
pub const stream = @import("stream/stream.zig");
pub const streams = @import("stream/streams.zig");
pub const field_block = @import("field_block.zig");
pub const FieldBlock = field_block.FieldBlock;
pub const message = @import("message/message.zig");
pub const connection = @import("connection/connection.zig");
pub const Connection = connection.Connection;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = role;
    _ = frame;
    _ = settings;
    _ = window;
    _ = stream;
    _ = streams;
    _ = @import("stream/streams_slot.zig");
    _ = @import("stream/streams_window.zig");
    _ = field_block;
    _ = @import("field_block_decode.zig");
    _ = @import("field_block_limit.zig");
    _ = message;
    _ = connection;
    _ = @import("connection/connection_receive.zig");
    _ = @import("connection/connection_control.zig");
    _ = @import("connection/connection_stream.zig");
    _ = @import("connection/connection_data.zig");
    _ = @import("connection/connection_headers.zig");
    _ = @import("connection/connection_reply.zig");
    _ = @import("connection/connection_send.zig");
}
