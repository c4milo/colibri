//! Check fixture for tools/graph_check.zig. Compiled as the root of a module carrying exactly the
//! import set build/modules.zig gives `quic`; the compile MUST fail, because decision 5 keeps
//! every HTTP module out of that set (docs/invariants.md INV-26).
//!
//! The import sits in a `comptime` block on purpose. Zig analyses lazily, so an unreferenced
//! `const x = @import("http");` compiles clean and the check would pass while proving nothing.
comptime {
    _ = @import("http");
}
