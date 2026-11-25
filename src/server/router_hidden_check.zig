//! The root of `zig build router-hidden-check` (build/router_check.zig, decision 122). The compile
//! of the cross-check in `router/router_hidden_test.zig` lasts about a minute. The owner ruled on
//! 2026-10-14 that it runs apart from `zig build test-server`, in this binary of its own.
//! `zig build test` runs both.
//!
//! The step compiles this file with the imports of the `server` module, so the router's files
//! compile as they do in the server. No packaged module imports this file. It sits in `src/server/`
//! because a file of a module imports no file outside the directory of its root.

test {
    _ = @import("router/router_hidden_test.zig");
    // The `server` module's imports link chapulin's objects through `tls`. This reference runs the
    // comptime block of `tls`'s root, which keeps chapulin's `ch_assert_fail` (decision 172).
    _ = @import("tls");
}
