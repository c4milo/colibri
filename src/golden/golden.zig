//! The byte-exact corpus and its manifest (decision 26).
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const constants = @import("constants.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
}
