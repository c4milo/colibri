//! The root of `zig build tls-accept`: design §8 step 5's server-side TLS check, which runs one
//! handshake as the server, `tls.record.Server`, against a client that is not colibri's and then
//! moves one record each way. It is a root of its own because an executable has one `main`, and
//! the others belong to the h2 server, the h2 client and the client-side handshake check.
const std = @import("std");

pub const check_file = @import("tls/check_file.zig");
pub const accept_check = @import("tls/accept_check.zig");

pub const main = accept_check.main;

test {
    std.testing.refAllDecls(@This());
    _ = check_file;
    _ = accept_check;
}
