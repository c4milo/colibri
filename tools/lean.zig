//! colibri's Lean proofs (decision 77), built by pepegrillo's lake runner. The project is
//! spec/lean/. After the proofs build, the vectors the proved definitions give are checked against
//! the committed files under src/, in src/qpack/ and src/wire/, which the Zig unit tests read.
//!
//! Run: `zig build lean`, or `zig build lean -- write` to rewrite the vector files.

const std = @import("std");
const pepegrillo = @import("pepegrillo");

/// The directory the vector files are under, from spec/lean/, where lake runs.
const vector_directory = "../../src";

const exit_usage: u8 = 2;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    const mode: []const u8 = if (arguments.len == 1)
        "--check"
    else if (arguments.len == 2 and std.mem.eql(u8, arguments[1], "write"))
        "--write"
    else {
        std.debug.print("usage: lean [write]\n", .{});
        std.process.exit(exit_usage);
    };
    var output_buffer: [std.heap.page_size_min]u8 = undefined;
    var error_buffer: [std.heap.page_size_min]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &output_buffer);
    var errors = std.Io.File.stderr().writerStreaming(init.io, &error_buffer);
    defer errors.interface.flush() catch {};
    const context: pepegrillo.Context = .{
        .arena = arena,
        .io = init.io,
        .environ = init.environ_map,
        .out = &out.interface,
        .errors = &errors.interface,
    };
    const built = try pepegrillo.lean.run(&context, .{}, &.{});
    if (built != 0) std.process.exit(built);
    const vectors = if (std.mem.eql(u8, mode, "--write"))
        try pepegrillo.lean.run(&context, .{ .lake_arguments = &.{ "exe", "vectors", "--write", vector_directory } }, &.{})
    else
        try pepegrillo.lean.run(&context, .{ .lake_arguments = &.{ "exe", "vectors", "--check", vector_directory } }, &.{});
    out.interface.flush() catch {};
    errors.interface.flush() catch {};
    std.process.exit(vectors);
}
