//! The packet-protection vtable colibri drives for QUIC (decision 9). No production implementation
//! lives here.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
}
