//! Runs the QPACK vectors of qpackers/qifs against the qpack module (docs/design.md §8 step 11,
//! decisions 25 and 75).
//!
//! Run:   zig build qpack-vectors
//! Check: zig build test              # runs the same step
//! Test:  zig build test-tools
//!
//! Usage: qpack_vectors <qifs directory>
//!
//! `qifs/` holds six inputs, each a list of header sets in the QIF text format: a name, a TAB and
//! a value per line, a blank line after each set, and `#` for a comment. `encoded/qpack-05/` holds
//! what six encoders made of them, one directory each, in files named
//! `<input>.out.<capacity>.<blocked streams>.<acknowledgment mode>`. The QUIC working group's
//! "QPACK Offline Interop" page defines those files: blocks of a 64-bit stream ID, a 32-bit length
//! and the octets, all in network byte order, where stream 0 is the encoder stream.
//!
//! For each file the tool starts colibri's decoder with the file's capacity and blocked-stream
//! count, and delivers the blocks in file order. A request block that blocks is kept, and decoded
//! once `ready_stream` names its stream. The sections, in stream ID order, must be the input's
//! header sets, line for line. The acknowledgment mode is what the encoder assumed of a decoder
//! it could not hear, so a decoder reading the file needs nothing from it, and the decoder's own
//! instructions are written and dropped.
//!
//! Two things come from the format rather than RFC 9204. The page starts the table at its maximum
//! capacity "for historical reasons", where RFC 9204 §3.2.2 starts it at zero, so the tool sets
//! it. And the corpus targets draft-ietf-quic-qpack-05: decision 25 has a mismatch checked
//! against RFC 9204 before it is treated as colibri's bug.
//!
//! This tool is developer tooling: it allocates and reads the filesystem, which the library never
//! does.
//!
//! Exit status: 0 when every file passed, 1 when any did not, 2 on a usage error.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const assert = std.debug.assert;
const qpack = @import("qpack");

const Reader = qpack.core.Reader;
const Writer = qpack.core.Writer;
const FieldSection = qpack.http.field_section.FieldSection;
const Decoder = qpack.decoder.Decoder;

const encoded_directory = "encoded/qpack-05";
const inputs_directory = "qifs";
const input_extension = ".qif";

/// The RFC's own examples, which the tool skips. `examples.out.220.100.1` encodes RFC 9204
/// Appendix B, whose sections name `www.example.com`, but `draft-examples.qif` lists an earlier
/// draft's, which name `www.ietf.org` and hold one line each. Decision 25 makes the RFC the
/// authority where the corpus disagrees, and `src/qpack/decoder_test.zig` checks Appendix B itself.
const examples_name = "examples";

/// The largest file the tool reads; the largest in the corpus is 352 KB.
const file_bytes_max = 16 << 20;

/// The encoder stream's ID in the offline format.
const encoder_stream_id: u64 = 0;

/// Room for every instruction the decoder may owe at once, each a few octets.
const decoder_stream_room: usize = 4096;

const exit_mismatch: u8 = 1;
const exit_usage: u8 = 2;

const Failure = error{
    NameMalformed,
    InputMalformed,
    StreamRepeated,
    StillBlocked,
    SectionCountDiffers,
    LineCountDiffers,
    LineDiffers,
};

const Line = struct {
    name: []const u8,
    value: []const u8,
};

/// One section the decoder produced, and the stream it came on.
const Decoded = struct {
    stream_id: u64,
    lines: []const Line,
};

/// A request block kept while its stream is blocked.
const Held = struct {
    stream_id: u64,
    octets: []const u8,
};

/// What an encoded file's name says: `<input>.out.<capacity>.<blocked streams>.<mode>`.
const Name = struct {
    input: []const u8,
    capacity: u64,
    blocked_streams: u64,
};

const Counts = struct {
    files: u64 = 0,
    sections: u64 = 0,
    lines: u64 = 0,
    blocked: u64 = 0,
    skipped: u64 = 0,
    failed: u64 = 0,
};

/// Where the last mismatch was, for the report: the section, the line, what the input listed and
/// what the decoder produced.
const Mismatch = struct {
    section: usize = 0,
    line: usize = 0,
    listed: Line = .{ .name = "", .value = "" },
    decoded: Line = .{ .name = "", .value = "" },
};

var last_mismatch: Mismatch = .{};

/// The decoder and the buffers it fills, placed outside any stack frame.
var decoder: Decoder = undefined;
var section: FieldSection = undefined;
var strings: [qpack.core.constants.field_section_size_max]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len != 2) {
        std.debug.print("usage: qpack_vectors <qifs directory>\n", .{});
        std.process.exit(exit_usage);
    }
    var counts: Counts = .{};
    run_corpus(init.io, init.gpa, arguments[1], &counts) catch |failure| {
        std.debug.print("qpack-vectors: {s}\n", .{@errorName(failure)});
        std.process.exit(exit_mismatch);
    };
    std.debug.print("qpack-vectors: files={d} sections={d} lines={d} blocked={d} skipped={d} failed={d}\n", .{
        counts.files, counts.sections, counts.lines, counts.blocked, counts.skipped, counts.failed,
    });
    if (counts.failed > 0) std.process.exit(exit_mismatch);
}

fn run_corpus(io: Io, gpa: Allocator, root_path: []const u8, counts: *Counts) !void {
    var root = try Io.Dir.cwd().openDir(io, root_path, .{});
    defer root.close(io);
    var inputs = try root.openDir(io, inputs_directory, .{});
    defer inputs.close(io);
    var encoders = try root.openDir(io, encoded_directory, .{ .iterate = true });
    defer encoders.close(io);
    var walk = encoders.iterate();
    while (try walk.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var directory = try encoders.openDir(io, entry.name, .{ .iterate = true });
        defer directory.close(io);
        try run_encoder(io, gpa, inputs, directory, entry.name, counts);
    }
}

fn run_encoder(io: Io, gpa: Allocator, inputs: Io.Dir, directory: Io.Dir, encoder_name: []const u8, counts: *Counts) !void {
    var files = directory.iterate();
    while (try files.next(io)) |entry| {
        if (entry.kind != .file) continue;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const name = parse_name(entry.name) orelse return error.NameMalformed;
        if (std.mem.eql(u8, name.input, examples_name)) {
            counts.skipped += 1;
            continue;
        }
        const encoded = try directory.readFileAlloc(io, entry.name, arena, .limited(file_bytes_max));
        const input_path = try std.mem.concat(arena, u8, &.{ name.input, input_extension });
        const input = try inputs.readFileAlloc(io, input_path, arena, .limited(file_bytes_max));
        const expected = try parse_qif(arena, input);
        run_file(arena, encoded, expected, name, counts) catch |failure| {
            counts.failed += 1;
            const at = last_mismatch;
            std.debug.print("qpack-vectors: {s}/{s}: {s} at section {d} line {d}\n  listed:  {s}: {s}\n  decoded: {s}: {s}\n", .{
                encoder_name,   entry.name,      @errorName(failure), at.section,       at.line,
                at.listed.name, at.listed.value, at.decoded.name,     at.decoded.value,
            });
            continue;
        };
        counts.files += 1;
    }
}

/// Takes `<input>.out.<capacity>.<blocked streams>.<mode>` apart, or answers null.
fn parse_name(name: []const u8) ?Name {
    var parts = std.mem.splitBackwardsScalar(u8, name, '.');
    _ = parts.next() orelse return null;
    const blocked = parts.next() orelse return null;
    const capacity = parts.next() orelse return null;
    const out = parts.next() orelse return null;
    if (!std.mem.eql(u8, out, "out")) return null;
    const input = parts.rest();
    if (input.len == 0) return null;
    return .{
        .input = input,
        .capacity = std.fmt.parseUnsigned(u64, capacity, 10) catch return null,
        .blocked_streams = std.fmt.parseUnsigned(u64, blocked, 10) catch return null,
    };
}

/// The header sets of a QIF file, in order. A blank line ends a set, and a run of them ends one.
fn parse_qif(arena: Allocator, text: []const u8) ![]const []const Line {
    var sets: std.ArrayList([]const Line) = .empty;
    var set: std.ArrayList(Line) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, "#")) continue;
        if (line.len == 0) {
            if (set.items.len > 0) try sets.append(arena, try set.toOwnedSlice(arena));
            continue;
        }
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return error.InputMalformed;
        try set.append(arena, .{ .name = line[0..tab], .value = line[tab + 1 ..] });
    }
    if (set.items.len > 0) try sets.append(arena, try set.toOwnedSlice(arena));
    return sets.toOwnedSlice(arena);
}

/// Decodes one encoded file and compares its sections with `expected`.
fn run_file(arena: Allocator, encoded: []const u8, expected: []const []const Line, name: Name, counts: *Counts) !void {
    decoder.init(.{ .max_table_capacity = name.capacity, .blocked_streams = name.blocked_streams });
    // The offline format starts the table at its maximum capacity, "for historical reasons".
    decoder.table.set_capacity(name.capacity) catch unreachable;
    var run: Run = .{ .arena = arena };
    var blocks = Reader.init(encoded);
    // Bounded by the file, since every block consumes at least its twelve-octet header.
    while (blocks.remaining_len() > 0) {
        const stream_id = try blocks.read_int(u64);
        const len = try blocks.read_int(u32);
        const octets = try blocks.take(len);
        if (stream_id == encoder_stream_id) {
            try run.encoder_stream(octets);
        } else {
            try run.request_stream(stream_id, octets, counts);
        }
    }
    if (run.held.items.len > 0) return error.StillBlocked;
    try compare(run.decoded.items, expected, counts);
}

/// One file's decoding state beyond the decoder's own.
const Run = struct {
    arena: Allocator,
    /// Encoder stream octets not yet read: an instruction may span two blocks.
    unread: std.ArrayList(u8) = .empty,
    held: std.ArrayList(Held) = .empty,
    decoded: std.ArrayList(Decoded) = .empty,

    fn encoder_stream(run: *Run, octets: []const u8) !void {
        try run.unread.appendSlice(run.arena, octets);
        var reader = Reader.init(run.unread.items);
        try decoder.read_encoder_stream(&reader);
        const consumed = run.unread.items.len - reader.remaining_len();
        run.unread.replaceRangeAssumeCapacity(0, consumed, &.{});
        // Bounded by the streams held: each one named is decoded and let go.
        while (decoder.ready_stream()) |stream_id| {
            const index = for (run.held.items, 0..) |held, index| {
                if (held.stream_id == stream_id) break index;
            } else unreachable;
            const held = run.held.orderedRemove(index);
            const lines = (try decode(run.arena, stream_id, held.octets)) orelse unreachable;
            try run.decoded.append(run.arena, .{ .stream_id = stream_id, .lines = lines });
        }
    }

    fn request_stream(run: *Run, stream_id: u64, octets: []const u8, counts: *Counts) !void {
        for (run.decoded.items) |done| {
            if (done.stream_id == stream_id) return error.StreamRepeated;
        }
        const lines = (try decode(run.arena, stream_id, octets)) orelse {
            counts.blocked += 1;
            try run.held.append(run.arena, .{ .stream_id = stream_id, .octets = octets });
            return;
        };
        try run.decoded.append(run.arena, .{ .stream_id = stream_id, .lines = lines });
    }
};

/// Decodes one section, or answers null when its stream blocks. A decoder that owes a full queue
/// of instructions has them written and dropped, and is asked again.
fn decode(arena: Allocator, stream_id: u64, octets: []const u8) !?[]const Line {
    // Bounded: once the queue is written the next call decodes or blocks.
    for (0..2) |_| {
        section.init();
        var reader = Reader.init(octets);
        var writer = Writer.init(&strings);
        switch (try decoder.read_section(stream_id, &reader, &writer, &section)) {
            .decoded => return try copy_lines(arena),
            .blocked => return null,
            .owes_instructions => drop_decoder_stream(),
        }
    }
    unreachable;
}

fn drop_decoder_stream() void {
    var sink: [decoder_stream_room]u8 = undefined;
    var writer = Writer.init(&sink);
    decoder.write_decoder_stream(&writer);
}

/// The section's lines, copied out of it before the next section reuses it.
fn copy_lines(arena: Allocator) ![]const Line {
    const lines = try arena.alloc(Line, section.len());
    for (lines, 0..) |*line, index| {
        const field = section.get(@intCast(index));
        line.* = .{ .name = try arena.dupe(u8, field.name), .value = try arena.dupe(u8, field.value) };
    }
    drop_decoder_stream();
    return lines;
}

fn compare(decoded: []Decoded, expected: []const []const Line, counts: *Counts) !void {
    std.mem.sort(Decoded, decoded, {}, struct {
        fn less(_: void, left: Decoded, right: Decoded) bool {
            return left.stream_id < right.stream_id;
        }
    }.less);
    if (decoded.len != expected.len) return error.SectionCountDiffers;
    for (decoded, expected, 0..) |got, want, index| {
        last_mismatch = .{ .section = index };
        for (got.lines, 0..) |line, at| {
            if (at >= want.len) break;
            last_mismatch = .{ .section = index, .line = at, .listed = want[at], .decoded = line };
            if (!std.mem.eql(u8, line.name, want[at].name)) return error.LineDiffers;
            if (!std.mem.eql(u8, line.value, want[at].value)) return error.LineDiffers;
        }
        if (got.lines.len != want.len) return error.LineCountDiffers;
        counts.sections += 1;
        counts.lines += want.len;
    }
}

const testing = std.testing;

test "an encoded file's name gives its input, capacity and blocked streams" {
    const name = parse_name("fb-req-hq.out.4096.100.1").?;
    try testing.expectEqualStrings("fb-req-hq", name.input);
    try testing.expectEqual(4096, name.capacity);
    try testing.expectEqual(100, name.blocked_streams);
    try testing.expectEqual(null, parse_name("fb-req.qif"));
    try testing.expectEqual(null, parse_name("fb-req.out.x.0.0"));
    try testing.expectEqual(null, parse_name(".out.0.0.0"));
}

test "a QIF file is header sets of TAB-separated lines, with comments and blank lines" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const sets = try parse_qif(arena_state.allocator(), "# stream 4\n:path\t/index.html\n\n\n# b\na\tb\tc\n");
    try testing.expectEqual(2, sets.len);
    try testing.expectEqualStrings("/index.html", sets[0][0].value);
    try testing.expectEqualStrings("b\tc", sets[1][0].value);
    try testing.expectError(error.InputMalformed, parse_qif(arena_state.allocator(), "no tab\n"));
}

/// Appends one block of the offline format. Test-only.
fn block(list: *std.ArrayList(u8), arena: Allocator, stream_id: u64, octets: []const u8) !void {
    var header: [12]u8 = undefined;
    std.mem.writeInt(u64, header[0..8], stream_id, .big);
    std.mem.writeInt(u32, header[8..12], @intCast(octets.len), .big);
    try list.appendSlice(arena, &header);
    try list.appendSlice(arena, octets);
}

test "RFC 9204 Appendix B as an offline file: a section that arrives first waits for its entries" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var file: std.ArrayList(u8) = .empty;
    // B.2's section on stream 4 comes before the encoder stream that fills the table, and the
    // encoder stream arrives in two blocks, split inside an instruction.
    try block(&file, arena, 4, &.{ 0x03, 0x81, 0x10, 0x11 });
    const inserts = [_]u8{ 0xc0, 0x0f } ++ "www.example.com".* ++ [_]u8{ 0xc1, 0x0c } ++ "/sample/path".*;
    try block(&file, arena, encoder_stream_id, inserts[0..5]);
    try block(&file, arena, encoder_stream_id, inserts[5..]);
    const expected = try parse_qif(arena, ":authority\twww.example.com\n:path\t/sample/path\n\n");
    var counts: Counts = .{};
    try run_file(arena, file.items, expected, .{ .input = "b", .capacity = 220, .blocked_streams = 1 }, &counts);
    try testing.expectEqual(1, counts.sections);
    try testing.expectEqual(1, counts.blocked);
    // With no blocked stream allowed, the same file fails.
    try testing.expectError(error.DecompressionFailed, run_file(arena, file.items, expected, .{ .input = "b", .capacity = 220, .blocked_streams = 0 }, &counts));
    // A section whose entries never arrive is a failure of its own, not a missing section.
    try testing.expectError(error.StillBlocked, run_file(arena, file.items[0..16], expected, .{ .input = "b", .capacity = 220, .blocked_streams = 1 }, &counts));
    // A wrong value in the input is a mismatch.
    const wrong = try parse_qif(arena, ":authority\twww.example.org\n:path\t/sample/path\n\n");
    try testing.expectError(error.LineDiffers, run_file(arena, file.items, wrong, .{ .input = "b", .capacity = 220, .blocked_streams = 1 }, &counts));
}
