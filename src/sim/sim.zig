//! The deterministic harness: clock, byte pipe, trace, the null TLS provider and the null crypto
//! suite (design §10). The datagram network lands with design §8 step 8. It imports no
//! protocol module, so it cannot know anything a caller would not.
const std = @import("std");

pub const core = @import("core");
pub const tls = @import("tls");
pub const crypto = @import("crypto");
pub const constants = @import("constants.zig");

pub const random = @import("random.zig");
pub const clock = @import("clock.zig");
pub const trace = @import("trace.zig");
pub const pipe = @import("pipe.zig");
pub const null_provider = @import("null_provider.zig");
pub const NullProvider = null_provider.NullProvider;
pub const null_suite = @import("null_suite.zig");
pub const NullSuite = null_suite.NullSuite;
pub const Random = random.Random;
pub const Clock = clock.Clock;
pub const Trace = trace.Trace;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = random;
    _ = clock;
    _ = trace;
    _ = pipe;
    _ = null_provider;
    _ = null_suite;
    _ = @import("null_suite_keys.zig");
}
