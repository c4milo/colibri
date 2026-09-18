//! Limits, assertions, and the containers more than one module needs and no module owns.
//! Imports nothing, so every other module can import it (docs/design.md §3).
const std = @import("std");

pub const constants = @import("constants.zig");

/// The bounded reader and writer of invariant 3. Every parser reads through `Reader` and every
/// encoder writes through `Writer`; neither owns memory, and both work over the caller's slices.
pub const reader = @import("reader.zig");
pub const writer = @import("writer.zig");
pub const Reader = reader.Reader;
pub const Writer = writer.Writer;

/// The bounded slot pool with a per-class watermark of decision 14 and invariant 13, which the
/// h2 and QUIC stream tables are built on.
pub const slots = @import("slots.zig");
pub const Pool = slots.Pool;

/// The fuzz harness every decoder's tests share. Test-only.
pub const fuzz = @import("fuzz.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = reader;
    _ = writer;
    _ = slots;
    _ = fuzz;
}
