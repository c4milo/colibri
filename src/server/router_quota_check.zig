//! The second root of `zig build router-hidden-check` (build/router_check.zig, decision 122). It
//! compiles the test of the quota in `router/router_quota_test.zig`, whose table of 257 routes
//! compiles in about a minute. The owner ruled on 2026-10-14 that it is a second test binary of
//! the step. The step compiles it in parallel with `router_hidden_check.zig`.
//!
//! The step compiles this file with the imports of the `server` module, as it does
//! `router_hidden_check.zig`. No packaged module imports this file.

test {
    _ = @import("router/router_quota_test.zig");
    // The `server` module's imports link chapulin's objects through `tls`. This reference runs the
    // comptime block of `tls`'s root, which keeps chapulin's `ch_assert_fail` (decision 172).
    _ = @import("tls");
}
