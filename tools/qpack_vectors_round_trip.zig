//! The second half of `qpack_vectors.zig`: every qifs input written by colibri's own encoder and
//! read back by colibri's decoder (decisions 75 and 76). Part of design §8 step 11.
//!
//! Each input runs at four settings, a table of 0 or 4,096 octets with 0 or 100 blocked streams,
//! and in the two acknowledgment modes of the "QPACK Offline Interop" format:
//! - Immediate: after each section the decoder reads the encoder stream and the section, and its
//!   decoder stream goes back to the encoder, so entries are acknowledged as they arrive.
//! - None: the encoder hears nothing back, and the sections go into an offline file, all of them
//!   ahead of the one block that holds every encoder stream octet. `qpack_vectors.run_file` then
//!   decodes that file. It is the latest the encoder stream can arrive, so every section with a
//!   dynamic reference blocks, and a section on a stream that may not block must have none.
//!
//! Every section must decode to the input's header set, line for line.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const qpack = @import("qpack");
const vectors = @import("qpack_vectors.zig");

const Reader = qpack.core.Reader;
const Writer = qpack.core.Writer;
const FieldSection = qpack.http.field_section.FieldSection;
const Line = vectors.Line;

/// The table sizes and blocked-stream counts colibri's encoder runs at.
const round_trip_settings = [vectors.round_trip_settings_count]qpack.decoder.Settings{
    .{},
    .{ .blocked_streams = blocked_streams },
    .{ .max_table_capacity = table_capacity },
    .{ .max_table_capacity = table_capacity, .blocked_streams = blocked_streams },
};
const table_capacity: u64 = 4096;
const blocked_streams: u64 = 100;

/// Room for one encoded section and the encoder stream octets written with it.
const encoded_room: usize = 1 << 16;

/// The encoder and its buffers, placed outside any stack frame.
var encoder: qpack.encoder.Encoder = undefined;
var section: FieldSection = undefined;
var section_octets: [encoded_room]u8 = undefined;
var stream_octets: [encoded_room]u8 = undefined;
var owed_octets: [encoded_room]u8 = undefined;

const Mode = enum { immediate, none };

/// Round-trips every input under `root_path`'s `qifs/`.
pub fn run(io: Io, gpa: Allocator, root_path: []const u8, counts: *vectors.Counts) !void {
    var root = try Io.Dir.cwd().openDir(io, root_path, .{});
    defer root.close(io);
    var inputs = try root.openDir(io, vectors.inputs_directory, .{ .iterate = true });
    defer inputs.close(io);
    var walk = inputs.iterate();
    while (try walk.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, vectors.input_extension)) continue;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const text = try inputs.readFileAlloc(io, entry.name, arena, .limited(1 << 24));
        const sets = try vectors.parse_qif(arena, text);
        for (round_trip_settings, 0..) |settings, index| {
            inline for (.{ Mode.immediate, Mode.none }) |mode| {
                round_trip(arena, sets, settings, mode, index, counts) catch |failure| {
                    std.debug.print("qpack-vectors: round trip {s} at {d}.{d}.{t}: {s}\n", .{
                        entry.name, settings.max_table_capacity, settings.blocked_streams, mode, @errorName(failure),
                    });
                    return failure;
                };
            }
        }
    }
}

fn round_trip(arena: Allocator, sets: []const []const Line, settings: qpack.decoder.Settings, comptime mode: Mode, index: usize, counts: *vectors.Counts) !void {
    encoder.init(.when_shorter);
    encoder.on_settings(.{ .max_table_capacity = settings.max_table_capacity, .blocked_streams = settings.blocked_streams });
    var file: std.ArrayList(u8) = .empty;
    var encoder_stream: std.ArrayList(u8) = .empty;
    if (mode == .immediate) vectors.decoder.init(settings);
    for (sets, 1..) |set, stream_id| {
        const written = try encode(set, stream_id);
        switch (mode) {
            .immediate => {
                try exchange(arena, stream_id, written, set);
                counts.round_trip_octets[index] += written.section.len + written.stream.len;
            },
            .none => {
                try append_block(arena, &file, stream_id, written.section);
                try encoder_stream.appendSlice(arena, written.stream);
            },
        }
        counts.round_trip_lines += set.len;
    }
    if (mode == .none) {
        try append_block(arena, &file, vectors.encoder_stream_id, encoder_stream.items);
        const name: vectors.Name = .{ .input = "", .capacity = settings.max_table_capacity, .blocked_streams = settings.blocked_streams };
        var ignored: vectors.Counts = .{};
        try vectors.run_file(arena, file.items, sets, name, &ignored);
    }
    counts.round_trips += 1;
}

const Written = struct {
    section: []const u8,
    stream: []const u8,
};

fn encode(set: []const Line, stream_id: u64) !Written {
    section.init();
    for (set) |line| try section.append(line.name, line.value);
    var output = Writer.init(&section_octets);
    var encoder_stream = Writer.init(&stream_octets);
    try encoder.write_section(stream_id, &output, &encoder_stream, &section, &.{});
    return .{ .section = output.written(), .stream = encoder_stream.written() };
}

/// Hands one section to the decoder with its encoder stream octets, and its decoder stream back
/// to the encoder: the immediate acknowledgment mode.
fn exchange(arena: Allocator, stream_id: u64, written: Written, set: []const Line) !void {
    var instructions = Reader.init(written.stream);
    try vectors.decoder.read_encoder_stream(&instructions);
    if (instructions.remaining_len() != 0) return error.EncoderStreamLeftOver;
    const lines = (try decode_owing(arena, stream_id, written.section)) orelse return error.Blocked;
    if (lines.len != set.len) return error.LineCountDiffers;
    for (lines, set) |got, want| {
        if (!std.mem.eql(u8, got.name, want.name) or !std.mem.eql(u8, got.value, want.value)) return error.LineDiffers;
    }
}

/// Decodes the section and sends the decoder's instructions back to the encoder. The queue is
/// emptied after every section, so `vectors.decode` never finds it full and drops nothing.
fn decode_owing(arena: Allocator, stream_id: u64, octets: []const u8) !?[]const Line {
    const lines = try vectors.decode(arena, stream_id, octets);
    var writer = Writer.init(&owed_octets);
    vectors.decoder.write_decoder_stream(&writer);
    var reader = Reader.init(writer.written());
    try encoder.read_decoder_stream(&reader);
    return lines;
}

fn append_block(arena: Allocator, file: *std.ArrayList(u8), stream_id: u64, octets: []const u8) !void {
    var header: [12]u8 = undefined;
    std.mem.writeInt(u64, header[0..8], stream_id, .big);
    std.mem.writeInt(u32, header[8..12], @intCast(octets.len), .big);
    try file.appendSlice(arena, &header);
    try file.appendSlice(arena, octets);
}

const testing = std.testing;

test "a round trip decodes what the encoder wrote in both modes, and a wrong input is a mismatch" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sets = try vectors.parse_qif(arena, ":method\tGET\nx-a\t1\n\nx-a\t1\nx-b\t2\n\n");
    const settings: qpack.decoder.Settings = .{ .max_table_capacity = table_capacity, .blocked_streams = blocked_streams };
    var counts: vectors.Counts = .{};
    try round_trip(arena, sets, settings, .immediate, 0, &counts);
    try round_trip(arena, sets, settings, .none, 0, &counts);
    try testing.expectEqual(2, counts.round_trips);
    try testing.expectEqual(8, counts.round_trip_lines);
    // A section decoded against the wrong input fails the comparison.
    encoder.init(.never);
    encoder.on_settings(.{ .max_table_capacity = table_capacity, .blocked_streams = blocked_streams });
    vectors.decoder.init(settings);
    const written = try encode(sets[0], 1);
    const wrong = try vectors.parse_qif(arena, ":method\tGET\nx-a\t2\n\n");
    try testing.expectError(error.LineDiffers, exchange(arena, 1, written, wrong[0]));
}
