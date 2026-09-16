//! HTTP/2, RFC 9113. RFC 9113 obsoletes RFC 7540; 7540 is never read and never cited.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const hpack = @import("hpack");
pub const tls = @import("tls");
pub const constants = @import("constants.zig");

pub const role = @import("role.zig");
pub const Role = role.Role;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = role;
}
