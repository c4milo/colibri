//! Runs the HPACK vectors of http2jp/hpack-test-case against the hpack module (docs/design.md
//! §8 step 3, decision 25).
//!
//! Run:   zig build hpack-vectors
//! Check: zig build test              # runs the same step
//! Test:  zig build test-tools
//!
//! Usage: hpack_vectors <hpack-test-case directory>
//!
//! Every directory but `raw-data` holds the output of one encoder over the same stories — 32 in most, 31 in `nghttp2-16384-4096` and `nghttp2-change-table-size`, which stop at `story_30.json`, and a
//! story is one connection's field blocks in order, sharing a decoding context. For each story
//! the tool starts a decoder at the protocol's initial capacity, applies each case's
//! `header_table_size` as a limit the peer acknowledged, decodes the case's `wire` and requires
//! the lines the case lists, in order, and nothing more. `raw-data` holds the stories with no
//! wire: the tool encodes each with colibri's encoder, in each Huffman setting, and requires the
//! decoder to read back what was written.
//!
//! This tool is developer tooling: it allocates and reads the filesystem, which the library never
//! does. `src/` never reads the JSON.
//!
//! Exit status: 0 when every case passed, 1 on the first mismatch, 2 on a usage error.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const assert = std.debug.assert;
const hpack = @import("hpack");

const Writer = hpack.core.Writer;

/// The protocol's initial capacity, which the README says applies when a case names none
/// (RFC 9113 §6.5.2).
const initial_capacity: u64 = 4096;

/// The directory of stories with no wire, which the encoder is run over.
const raw_data_directory = "raw-data";

/// The largest story file the tool reads.
const story_bytes_max = 16 << 20;

/// The longest field block the encoder writes for one case.
const block_len_max = 64 << 10;

/// The longest name and value the corpus holds, in octets; a longer one is a corpus change.
const name_len_max = hpack.constants.name_len_max;
const value_len_max = hpack.constants.value_len_max;

const exit_mismatch: u8 = 1;
const exit_usage: u8 = 2;

const Failure = error{
    StoryMalformed,
    LineMissing,
    LineDiffers,
    LinesLeftOver,
    DecodeFailed,
};

const Counts = struct {
    directories: u64 = 0,
    stories: u64 = 0,
    cases: u64 = 0,
    fields: u64 = 0,
    round_trips: u64 = 0,
};

/// Where the last mismatch was, for the one report a run prints: the case, the line, what the
/// story listed and what the decoder produced or failed with.
const Mismatch = struct {
    sequence: usize = 0,
    line: usize = 0,
    expected_name: []const u8 = "",
    expected_value: []const u8 = "",
    decoded_name: []const u8 = "",
    decoded_value: []const u8 = "",
    decode_error: ?anyerror = null,
};

var last_mismatch: Mismatch = .{};

/// The contexts a run decodes and encodes in, placed outside any stack frame.
var decoder: hpack.Decoder = undefined;
var encoder: hpack.Encoder = undefined;
var round_trip_decoder: hpack.Decoder = undefined;
var block_buffer: [block_len_max]u8 = undefined;
var wire_buffer: [block_len_max]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len != 2) {
        std.debug.print("usage: hpack_vectors <hpack-test-case directory>\n", .{});
        std.process.exit(exit_usage);
    }
    var counts: Counts = .{};
    run_directory(init.io, init.gpa, arguments[1], &counts) catch |failure| {
        std.debug.print("hpack-vectors: {s}\n", .{@errorName(failure)});
        std.process.exit(exit_mismatch);
    };
    std.debug.print(
        "hpack-vectors: directories={d} stories={d} cases={d} fields={d} round_trips={d}\n",
        .{ counts.directories, counts.stories, counts.cases, counts.fields, counts.round_trips },
    );
}

fn run_directory(io: Io, gpa: Allocator, root_path: []const u8, counts: *Counts) !void {
    var root = try Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);
    var directories = root.iterate();
    while (try directories.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var directory = try root.openDir(io, entry.name, .{ .iterate = true });
        defer directory.close(io);
        try run_stories(io, gpa, directory, entry.name, counts);
        counts.directories += 1;
    }
}

fn run_stories(io: Io, gpa: Allocator, directory: Io.Dir, name: []const u8, counts: *Counts) !void {
    var stories = directory.iterate();
    while (try stories.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const text = try directory.readFileAlloc(io, entry.name, arena, .limited(story_bytes_max));
        const story = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
        const cases = (story.object.get("cases") orelse return error.StoryMalformed).array.items;
        run_story(cases, std.mem.eql(u8, name, raw_data_directory), counts) catch |failure| {
            const at = last_mismatch;
            std.debug.print("hpack-vectors: {s}/{s} case {d} line {d}: {s}\n", .{
                name,    entry.name,          at.sequence,
                at.line, @errorName(failure),
            });
            std.debug.print("  listed: {s}: {s}\n  decoded: {s}: {s}\n", .{
                at.expected_name, at.expected_value, at.decoded_name, at.decoded_value,
            });
            if (at.decode_error) |reason| std.debug.print("  decoder: {s}\n", .{@errorName(reason)});
            return failure;
        };
        counts.stories += 1;
    }
}

fn run_story(cases: []const std.json.Value, raw: bool, counts: *Counts) !void {
    if (raw) return run_round_trips(cases, counts);
    decoder.init(initial_capacity);
    for (cases, 0..) |case, sequence| {
        // A case may carry the size as null, which the README reads as the default too.
        if (case.object.get("header_table_size")) |size| {
            if (size == .integer) decoder.set_capacity_limit(@intCast(size.integer));
        }
        const hex = (case.object.get("wire") orelse return error.StoryMalformed).string;
        const wire = std.fmt.hexToBytes(&wire_buffer, hex) catch return error.StoryMalformed;
        const headers = (case.object.get("headers") orelse return error.StoryMalformed).array.items;
        expect_lines(&decoder, wire, headers) catch |failure| {
            last_mismatch.sequence = sequence;
            return failure;
        };
        counts.cases += 1;
        counts.fields += headers.len;
    }
}

/// Encodes every case of a story in each Huffman setting and decodes it back.
fn run_round_trips(cases: []const std.json.Value, counts: *Counts) !void {
    inline for (.{ .never, .always, .when_shorter }) |huffman| {
        encoder.init(initial_capacity, huffman);
        round_trip_decoder.init(initial_capacity);
        for (cases, 0..) |case, sequence| {
            const headers = (case.object.get("headers") orelse return error.StoryMalformed).array.items;
            var output = Writer.init(&block_buffer);
            try encoder.begin_block(&output);
            for (headers) |header| {
                const name, const value = try one_field(header);
                try encoder.write_field(&output, name, value, .incremental);
            }
            expect_lines(&round_trip_decoder, output.written(), headers) catch |failure| {
                last_mismatch.sequence = sequence;
                return failure;
            };
            counts.round_trips += 1;
        }
    }
}

/// Requires `block_octets` to decode to exactly `headers`, in order, recording where they did
/// not in `last_mismatch`.
fn expect_lines(context: *hpack.Decoder, block_octets: []const u8, headers: []const std.json.Value) !void {
    var block = context.block(block_octets);
    for (headers, 0..) |header, index| {
        const name, const value = try one_field(header);
        last_mismatch = .{ .line = index, .expected_name = name, .expected_value = value };
        const line = (block.next() catch |failure| {
            last_mismatch.decode_error = failure;
            return error.DecodeFailed;
        }) orelse return error.LineMissing;
        last_mismatch.decoded_name = line.name;
        last_mismatch.decoded_value = line.value;
        if (!std.mem.eql(u8, line.name, name) or !std.mem.eql(u8, line.value, value)) {
            return error.LineDiffers;
        }
    }
    last_mismatch = .{ .line = headers.len };
    const rest = block.next() catch |failure| {
        last_mismatch.decode_error = failure;
        return error.DecodeFailed;
    };
    if (rest != null) return error.LinesLeftOver;
    assert(block.consumed_len() == block_octets.len);
}

/// The one name and value of a corpus header object.
fn one_field(header: std.json.Value) !struct { []const u8, []const u8 } {
    if (header != .object or header.object.count() != 1) return error.StoryMalformed;
    const name = header.object.keys()[0];
    const value = header.object.values()[0];
    if (value != .string) return error.StoryMalformed;
    if (name.len > name_len_max or value.string.len > value_len_max) return error.StoryMalformed;
    return .{ name, value.string };
}

const testing = std.testing;

test "a story decodes to the lines it lists, and a wrong line, a missing one or an extra one fails" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const story = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"cases": [
        \\  {"seqno": 0, "header_table_size": 4096, "wire": "828684410f7777772e6578616d706c652e636f6d",
        \\   "headers": [{":method": "GET"}, {":scheme": "http"}, {":path": "/"}, {":authority": "www.example.com"}]},
        \\  {"seqno": 1, "wire": "828684be58086e6f2d6361636865",
        \\   "headers": [{":method": "GET"}, {":scheme": "http"}, {":path": "/"}, {":authority": "www.example.com"}, {"cache-control": "no-cache"}]}
        \\]}
    , .{});
    const cases = story.object.get("cases").?.array.items;
    var counts: Counts = .{};
    try run_story(cases, false, &counts);
    try testing.expectEqual(2, counts.cases);
    try testing.expectEqual(9, counts.fields);
    try run_story(cases, true, &counts);
    try testing.expectEqual(6, counts.round_trips);

    // A case's header_table_size is the limit a size update is held to: 200 over 100 fails.
    const lowered = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\[{"seqno": 0, "header_table_size": 100, "wire": "3fa90182", "headers": [{":method": "GET"}]}]
    , .{});
    try testing.expectError(error.DecodeFailed, run_story(lowered.array.items, false, &counts));
    try testing.expectEqual(error.SizeUpdateTooLarge, last_mismatch.decode_error.?);

    decoder.init(initial_capacity);
    const wire = "\x82\x86";
    const two = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\[{":method": "GET"}, {":scheme": "http"}]
    , .{});
    try expect_lines(&decoder, wire, two.array.items);
    const wrong = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\[{":method": "GET"}, {":scheme": "https"}]
    , .{});
    try testing.expectError(error.LineDiffers, expect_lines(&decoder, wire, wrong.array.items));
    try testing.expectEqual(1, last_mismatch.line);
    try testing.expectEqualStrings("https", last_mismatch.expected_value);
    try testing.expectEqualStrings("http", last_mismatch.decoded_value);
    try testing.expectError(error.LineMissing, expect_lines(&decoder, "\x82", two.array.items));
    try testing.expectError(error.LinesLeftOver, expect_lines(&decoder, "\x82\x86\x84", two.array.items));
    try testing.expectError(error.DecodeFailed, expect_lines(&decoder, "\x80", two.array.items));
    try testing.expectEqual(error.IndexZero, last_mismatch.decode_error.?);
}
