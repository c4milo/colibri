//! HTTP/2, RFC 9113. RFC 9113 obsoletes RFC 7540; 7540 is never read and never cited.
//!
//! The pieces, bottom up: `frame` reads and writes the ten frame types (§4, §6); `settings` holds
//! the six settings and the acknowledgment discipline (§6.5); `window` is the signed flow-control
//! window (§5.2, §6.9, invariant 15); `stream` is the state machine of §5.1 as pure functions.
//! The connection ties them together (decision 39).
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
pub const stream = @import("stream.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = role;
    _ = frame;
    _ = settings;
    _ = window;
    _ = stream;
}
