//! Writes the golden corpus into src/golden/ (decision 26, design §8 step 1).
//!
//! Run:   zig build golden
//! Check: zig build golden-check      # which zig build test runs
//! Test:  zig build test-tools
//!
//! Usage: golden <golden-directory>
//!
//! For each format of `corpus_cases.zig` the tool writes one directory under the golden directory,
//! named for the format, holding one `.bin` file per case and a version 1 `manifest.txt`. The
//! octets and the manifest come from `corpus.build` and `corpus.render_manifest`, which are in
//! `src/golden/` and are pure; this tool is the only part that touches the filesystem, because the
//! `io` lint rule keeps `std.fs` out of `src/`.
//!
//! A format directory holding a `FROZEN` marker is refused: nothing in it is written or removed,
//! and the tool exits 1 after the other formats are written. In a directory it does write, a
//! `.bin` file no case names is removed, so the directory holds exactly the table.
//!
//! Exit status: 0 when every format was written, 1 when a frozen directory was refused, 2 on a
//! usage error.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const corpus = @import("golden_corpus");

const golden_constants = corpus.constants;
const Writer = corpus.core.Writer;

const exit_refused: u8 = 1;
const exit_usage: u8 = 2;

/// Most entries the tool reads from one format directory before it fails.
const directory_entries_max = 1024;

const Outcome = union(enum) {
    /// The format's cases and manifest were written, and this many stale files removed.
    written: struct { stale_removed: usize },
    /// The directory carries the frozen marker, and nothing was written.
    refused,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len != 2) {
        std.debug.print("usage: golden <golden-directory>\n", .{});
        std.process.exit(exit_usage);
    }
    var refused = false;
    for (corpus.cases.all) |entry| {
        const cases_len = corpus.cases_of(entry.format).len;
        switch (try write_format(init.io, arena, arguments[1], entry.format)) {
            .written => |written| std.debug.print(
                "golden: {s}/{t}: {d} cases written, {d} stale files removed\n",
                .{ arguments[1], entry.format, cases_len, written.stale_removed },
            ),
            .refused => {
                std.debug.print("golden: {s}/{t} carries {s}; refused, nothing written\n", .{
                    arguments[1],
                    entry.format,
                    golden_constants.frozen_marker_name,
                });
                refused = true;
            },
        }
    }
    if (refused) std.process.exit(exit_refused);
}

fn write_format(io: Io, arena: Allocator, root: []const u8, format: corpus.cases.Format) !Outcome {
    const path = try std.fs.path.join(arena, &.{ root, @tagName(format) });
    var dir = try Io.Dir.cwd().createDirPathOpen(io, path, .{ .open_options = .{ .iterate = true } });
    defer dir.close(io);
    if (dir.access(io, golden_constants.frozen_marker_name, .{})) {
        return .refused;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    for (corpus.cases_of(format)) |*case| {
        var buffer: [golden_constants.case_len_max]u8 = @splat(0);
        var octets = Writer.init(&buffer);
        try corpus.build(format, case, &octets);
        const name = try std.mem.concat(arena, u8, &.{ case.name, golden_constants.case_file_extension });
        try dir.writeFile(io, .{ .sub_path = name, .data = octets.written() });
    }
    var manifest_buffer: [golden_constants.manifest_len_max]u8 = @splat(0);
    var manifest = Writer.init(&manifest_buffer);
    try corpus.render_manifest(format, &manifest);
    try dir.writeFile(io, .{ .sub_path = golden_constants.manifest_file_name, .data = manifest.written() });

    return .{ .written = .{ .stale_removed = try remove_stale_cases(io, arena, dir, format) } };
}

/// Removes every `.bin` file in `dir` that no case of `format` names. Names are copied before any
/// removal, because the iterator reuses its buffer and a removal changes what it would read next.
fn remove_stale_cases(io: Io, arena: Allocator, dir: Io.Dir, format: corpus.cases.Format) !usize {
    var stale_names: [directory_entries_max][]const u8 = undefined;
    var stale_count: usize = 0;
    var iterator = dir.iterate();
    for (0..directory_entries_max) |_| {
        const entry = try iterator.next(io) orelse break;
        if (entry.kind != .file or !is_stale(entry.name, format)) continue;
        stale_names[stale_count] = try arena.dupe(u8, entry.name);
        stale_count += 1;
    } else return error.TooManyEntries;
    for (stale_names[0..stale_count]) |name| try dir.deleteFile(io, name);
    return stale_count;
}

fn is_stale(file_name: []const u8, format: corpus.cases.Format) bool {
    const stem = case_stem(file_name) orelse return false;
    for (corpus.cases_of(format)) |case| {
        if (std.mem.eql(u8, case.name, stem)) return false;
    }
    return true;
}

/// The case name a corpus file carries, or null when the file is not a corpus case.
fn case_stem(file_name: []const u8) ?[]const u8 {
    if (!std.mem.endsWith(u8, file_name, golden_constants.case_file_extension)) return null;
    return file_name[0 .. file_name.len - golden_constants.case_file_extension.len];
}

const testing = std.testing;

test "a corpus file's stem is its case name, and other files are not cases" {
    try testing.expectEqualStrings("varint_empty", case_stem("varint_empty.bin").?);
    try testing.expectEqual(null, case_stem("manifest.txt"));
    try testing.expectEqual(null, case_stem("FROZEN"));
}

test "a file no case names is stale, and a case's own file is not" {
    try testing.expect(!is_stale("varint_empty.bin", .varint));
    try testing.expect(is_stale("varint_empty.bin", .huffman));
    try testing.expect(is_stale("varint_retired.bin", .varint));
    try testing.expect(!is_stale("manifest.txt", .varint));
}

test "a frozen directory is refused and a writable one is written in full" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    try tmp.dir.createDirPath(io, "huffman");
    try tmp.dir.writeFile(io, .{ .sub_path = "huffman/FROZEN", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "huffman/kept.bin", .data = "x" });
    try testing.expectEqual(Outcome.refused, try write_format(io, arena, root, .huffman));
    try tmp.dir.access(io, "huffman/kept.bin", .{});

    try tmp.dir.createDirPath(io, "varint");
    try tmp.dir.writeFile(io, .{ .sub_path = "varint/varint_retired.bin", .data = "x" });
    const outcome = try write_format(io, arena, root, .varint);
    try testing.expectEqual(1, outcome.written.stale_removed);
    try testing.expectError(error.FileNotFound, tmp.dir.access(io, "varint/varint_retired.bin", .{}));
    var buffer: [16]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x25}, try tmp.dir.readFile(io, "varint/varint_1_octet_37.bin", &buffer));
    try tmp.dir.access(io, "varint/manifest.txt", .{});
}
