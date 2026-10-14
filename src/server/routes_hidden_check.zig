//! The root of `zig build routes-hidden-check` (build/routes_check.zig, decision 122). The compile
//! of the cross-check in `routes/routes_hidden_test.zig` takes about a minute. The owner ruled on
//! 2026-10-14 that it runs apart from `zig build test-server`, in this binary of its own.
//! `zig build test` runs both.
//!
//! The step compiles this file with the imports of the `server` module, so the router's files
//! compile as they do in the server. No packaged module imports this file. It sits in `src/server/`
//! because a file of a module imports no file outside the directory of its root.

test {
    _ = @import("routes/routes_hidden_test.zig");
    // The hook a test binary defines, as every program that links chapulin does. The `server`
    // module imports `tls`, which links chapulin.
    _ = @import("test_hooks.zig");
}
