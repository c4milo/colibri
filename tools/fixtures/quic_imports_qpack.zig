//! Gate fixture for tools/graph_gate.zig. Compiled as the root of a module carrying exactly the
//! import set build/modules.zig gives `quic`; the compile MUST fail, because decision 5 keeps
//! every HTTP module out of that set (docs/invariants.md INV-26).
//!
//! The import sits in a `comptime` block on purpose. Zig analyses lazily, so an unreferenced
//! `const x = @import("qpack");` compiles clean and the gate would pass while proving nothing.
comptime {
    _ = @import("qpack");
}
