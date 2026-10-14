//! The second root of `zig build router-hidden-check` (build/router_check.zig, decision 122). It
//! compiles the test of the quota in `router/router_quota_test.zig`, whose table of 257 routes
//! compiles in about a minute. The owner ruled on 2026-10-14 that it is a second test binary of
//! the step. The step compiles it in parallel with `router_hidden_check.zig`.
//!
//! The step compiles this file with the imports of the `server` module, as it does
//! `router_hidden_check.zig`. No packaged module imports this file.

test {
    _ = @import("router/router_quota_test.zig");
    // The hook a test binary defines, as every program that links chapulin does. The `server`
    // module imports `tls`, which links chapulin.
    _ = @import("test_hooks.zig");
}
