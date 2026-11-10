//! A program that names the `.private` kind of `colibri.Server` and of `colibri.Client` in a
//! build that passes no `.rotor = true` (decision 159). It must not compile, and the compiler
//! must print colibri's message once for each type. tools/consumer_check.sh builds it and
//! requires that failure. Each type is in a block of its own, so the compiler judges both.
const colibri = @import("colibri");

comptime {
    _ = colibri.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .private);
}

comptime {
    _ = colibri.Client(.{ .quic = false }, .private);
}

pub fn main() void {}
