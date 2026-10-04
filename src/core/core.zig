//! Limits, assertions, and the containers more than one module needs and no module owns.
//! Imports nothing, so every other module can import it (docs/design.md §3).
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    /// The bounded reader and writer of invariant 3. Every parser reads through `Reader` and every
    /// encoder writes through `Writer`; neither owns memory, and both work over the caller's slices.
    pub const reader = @import("reader.zig");
    pub const writer = @import("writer.zig");
    /// The bounded slot pool with a per-class watermark of decision 14 and invariant 13, which the
    /// h2 and QUIC stream tables are built on.
    pub const slots = @import("slots.zig");
    /// The encryption levels of RFC 9001 §4.1.4, which `crypto` and `tls` both speak and neither
    /// owns: design §3 makes them siblings with no edge between them.
    pub const encryption_level = @import("encryption_level.zig");
    /// The fuzz harness every decoder's tests share. Test-only.
    pub const fuzz = @import("fuzz.zig");
    /// The comparison of a type's public declarations with a list of names, which the tests of
    /// decision 115 share. Test-only.
    pub const public_names = @import("public_names.zig");
};

pub const Reader = files.reader.Reader;
pub const Writer = files.writer.Writer;
pub const Pool = files.slots.Pool;
pub const Level = files.encryption_level.Level;
pub const levels_count = files.encryption_level.levels_count;

pub const reader = struct {
    pub const Error = files.reader.Error;
};

pub const writer = struct {
    pub const Error = files.writer.Error;
};

pub const fuzz = struct {
    pub const input = files.fuzz.input;
    pub const input_with_value = files.fuzz.input_with_value;
    pub const sweep = files.fuzz.sweep;
    pub const sweep_len_max = files.fuzz.sweep_len_max;
};

pub const public_names = struct {
    pub const expect = files.public_names.expect;
    pub const reference = files.public_names.reference;
};

test "decision 115: the root exports the names code outside the module uses" {
    try files.public_names.expect(@This(), &.{
        "constants", "Reader",       "Writer", "Pool",
        "Level",     "levels_count", "reader", "writer",
        "fuzz",      "public_names",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = files.public_names.reference(@This(), &.{});
}
