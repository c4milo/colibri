//! The version-independent HTTP semantics core of RFC 9110 (decision 15). It holds no verdict: an
//! h2 verdict and an h3 verdict differ for the same predicate, so this module returns a reason and
//! the protocol module names the error.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

pub const field = @import("field.zig");
pub const connection_specific = @import("connection_specific.zig");
pub const method = @import("method.zig");
pub const status = @import("status.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = field;
    _ = connection_specific;
    _ = method;
    _ = status;
}
