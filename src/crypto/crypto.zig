//! The packet-protection vtable colibri drives for QUIC (decisions 9 and 48), and what both sides
//! of it must agree on: the sizes RFC 9001 §5 fixes, and the packet number recovery a suite
//! performs while it removes protection. No production implementation is in this tree.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");
pub const suite = @import("suite.zig");
pub const packet_number = @import("packet_number.zig");

pub const Suite = suite.Suite;
pub const Level = suite.Level;
pub const Direction = suite.Direction;
pub const Role = suite.Role;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = suite;
    _ = packet_number;
}
