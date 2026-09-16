//! The TLS provider vtable, in both modes (decision 8). No production implementation lives here;
//! src/sim/ carries a null one, which is test-only and never packaged.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
}
