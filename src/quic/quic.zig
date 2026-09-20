//! The transport of RFC 8999, 9000, 9001 and 9002. Knows nothing about HTTP (decision 5,
//! invariant 26), which build/modules.zig enforces and tools/graph_check.zig proves.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const crypto = @import("crypto");
pub const tls = @import("tls");
pub const constants = @import("constants.zig");
pub const packet = @import("packet/packet.zig");
pub const frame = @import("frame/frame.zig");
pub const space = @import("space/space.zig");
pub const termination = @import("termination.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = packet;
    _ = frame;
    _ = space;
    _ = termination;
}
