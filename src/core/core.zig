//! Limits, assertions, and the containers more than one module needs and no module owns.
//! Imports nothing, which is what lets every other module import it (docs/design.md §3).
const std = @import("std");

pub const constants = @import("constants.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
}
