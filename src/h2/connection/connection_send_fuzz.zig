//! The fuzz property of a response's frames (decision 29), and the sweep that runs it over every
//! input of up to two octets. A block that fits one frame is encoded in place since the owner's
//! goal of no copy on a request's path, and a larger one goes through `send_block`. Either way the
//! frames must decode to the response's fields, keep RFC 9113 §4.2 and §6.10, and be refused only
//! when they do not fit. Everything in this file is test-only.
const std = @import("std");
const core = @import("core");
const hpack = @import("hpack");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const support = @import("connection_test_support.zig");

const Reader = core.Reader;
const Smith = std.testing.Smith;
const testing = std.testing;
const test_connection = &support.test_connection;

/// An input: the field count, the room, the frame size, END_STREAM, then each field's name, its
/// value's length in units of `value_unit`, and the octets its values cycle through.
const head_octets = 4;
const fields_max = 6;
const field_octets = 2;
const value_pool_len = 32;
const fuzz_input_len = head_octets + fields_max * field_octets + value_pool_len;
/// Six values of the longest length pass `send_block_len_max`, so a case reaches its bound.
const value_unit = 32;
const value_len_max = std.math.maxInt(u8) * value_unit;

const names = [_][]const u8{ "content-type", "x-a", "cache-control", "x-trace-id", "etag", "vary" };
const ok: u16 = 200;
/// What `send_block` holds before a response that must not write it.
const sentinel: u8 = 0xa5;
/// Room for more than the largest block, so that only `send_block_len_max` refuses one.
const output_len_max = constants.limits.send_block_len_max + constants.limits.send_block_len_max;
/// A frame size larger than the initial one, which the peer may set (RFC 9113 §6.5.2).
const frame_size_large: u32 = frame_size_factor * constants.limits.frame_size_max;
const frame_size_factor = 4;
/// Where each octet of the input's head sits.
const at_count = 0;
const at_room = 1;
const at_frame_size = 2;
const at_end_stream = 3;

var fuzz_output: [output_len_max]u8 = undefined;
var values: [fields_max][value_len_max]u8 = undefined;
var block_octets: [constants.limits.send_block_len_max]u8 = undefined;

const Case = struct {
    fields: [fields_max]hpack.Field = undefined,
    count: usize,
    room: usize,
    frame_size: u32,
    end_stream: bool,
};

fn case_of(input: *const [fuzz_input_len]u8) Case {
    var case: Case = .{
        .count = input[at_count] % (fields_max + 1),
        .room = (@as(usize, input[at_room]) * output_len_max) / std.math.maxInt(u8),
        .frame_size = if (input[at_frame_size] & 1 == 0) constants.limits.frame_size_max else frame_size_large,
        .end_stream = input[at_end_stream] & 1 == 1,
    };
    const pool = input[head_octets + fields_max * field_octets ..];
    for (0..case.count) |index| {
        const entry = input[head_octets + index * field_octets ..][0..field_octets];
        const len = @as(usize, entry[1]) * value_unit;
        // Visible ASCII alone, so RFC 9113 §8.2.1 refuses no value.
        for (values[index][0..len], 0..) |*octet, at| octet.* = '!' + pool[(at + index) % pool.len] % ('~' - '!');
        case.fields[index] = .{ .name = names[entry[0] % names.len], .value = values[index][0..len] };
    }
    return case;
}

fn fuzz_response(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len]u8 = @splat(0);
    _ = smith.slice(&input);
    try check(case_of(&input));
}

fn start(case: Case) !void {
    try support.start_server();
    if (case.frame_size != constants.limits.frame_size_max) try feed_frame_size(case.frame_size);
    _ = try support.feed_request(1, "/", true);
    @memset(&test_connection.send_block, sentinel);
}

fn check(case: Case) !void {
    try start(case);
    const fields = case.fields[0..case.count];
    const written = test_connection.write_response(fuzz_output[0..case.room], 1, ok, fields, case.end_stream) catch |failure| {
        try testing.expectEqual(error.OutputTooSmall, failure);
        // Refused for room: on a fresh connection, a buffer of every octet either takes more than
        // the room, or refuses the block for `send_block_len_max` too.
        try start(case);
        const whole = test_connection.write_response(&fuzz_output, 1, ok, fields, case.end_stream) catch |again| {
            return testing.expectEqual(error.OutputTooSmall, again);
        };
        return testing.expect(whole > case.room);
    };
    const frames = try expect_frames(fuzz_output[0..written], case);
    // One frame is written in place, so `send_block` was never written (the owner's no-copy goal).
    if (frames == 1) try testing.expect(std.mem.allEqual(u8, &test_connection.send_block, sentinel));
}

/// Reads the HEADERS frame and its CONTINUATION frames, and requires their block to decode to
/// `:status` and the fields. Returns how many frames there were.
fn expect_frames(octets: []const u8, case: Case) !usize {
    var reader = Reader.init(octets);
    var block_len: usize = 0;
    var count: usize = 0;
    // Bounded by the octets: every frame takes at least its header.
    while (reader.remaining_len() > 0) : (count += 1) {
        const header = try frame.read_header(&reader);
        const expected_type = if (count == 0) constants.protocol.frame_type_headers else constants.protocol.frame_type_continuation;
        try testing.expectEqual(expected_type, header.type);
        try testing.expectEqual(1, header.stream_id);
        // RFC 9113 §4.2: no frame is longer than the peer's SETTINGS_MAX_FRAME_SIZE.
        try testing.expect(header.length <= case.frame_size);
        const fragment = try reader.take(header.length);
        @memcpy(block_octets[block_len..][0..fragment.len], fragment);
        block_len += fragment.len;
        // RFC 9113 §6.10: END_HEADERS on the last frame alone, and END_STREAM on the HEADERS.
        const last = reader.remaining_len() == 0;
        try testing.expectEqual(last, frame.has_flag(header, constants.protocol.flag_end_headers));
        const end_stream = count == 0 and case.end_stream;
        try testing.expectEqual(end_stream, frame.has_flag(header, constants.protocol.flag_end_stream));
    }
    hpack.decoder.test_decoder().init(constants.protocol.header_table_size_initial);
    var expected: [fields_max + 1]hpack.Field = undefined;
    expected[0] = .{ .name = ":status", .value = "200" };
    @memcpy(expected[1..][0..case.count], case.fields[0..case.count]);
    try hpack.decoder.expect_lines(block_octets[0..block_len], expected[0 .. case.count + 1]);
    return count;
}

/// Feeds the peer's SETTINGS frame setting SETTINGS_MAX_FRAME_SIZE.
fn feed_frame_size(size: u32) !void {
    var payload: [constants.protocol.setting_len]u8 = undefined;
    var writer = core.Writer.init(&payload);
    try writer.write_int(u16, constants.protocol.setting_max_frame_size);
    try writer.write_int(u32, size);
    const settings = try support.frame_bytes(&support.test_input, constants.protocol.frame_type_settings, 0, 0, writer.written());
    _ = try support.feed(settings);
}

test "fuzz: a response's frames decode to its fields, keep RFC 9113 §4.2 and §6.10, and fit" {
    try testing.fuzz({}, fuzz_response, .{
        .corpus = &.{
            // No field, with room for every octet, and with room for less than a frame header.
            core.fuzz.input("\x00\xff\x00\x01"),
            core.fuzz.input("\x00\x00\x00\x01"),
            // Five long values: a block longer than one frame, cut into a CONTINUATION.
            core.fuzz.input("\x05\xff\x00\x00" ++ "\x00\xfa\x01\xfa\x02\xfa\x03\xfa\x04\xfa\x05\x00" ++ "abcdefghijklmnopqrstuvwxyz012345"),
            // The same block with a frame size that holds it whole, written in place.
            core.fuzz.input("\x05\xff\x01\x00" ++ "\x00\xfa\x01\xfa\x02\xfa\x03\xfa\x04\xfa\x05\x00" ++ "abcdefghijklmnopqrstuvwxyz012345"),
        },
    });
    try core.fuzz.sweep(fuzz_response, null);
}

test "the response property holds over cases that a counter builds" {
    // The sweep reaches no field, so this pass builds every input from a counter: each octet
    // depends on its place and on the case.
    var input: [fuzz_input_len]u8 = undefined;
    for (0..case_count) |case| {
        for (&input, 0..) |*octet, index| octet.* = @truncate((index + 1) *% (case + 1) *% mix >> mix_shift);
        try check(case_of(&input));
    }
}

/// The cases the counter pass builds, and the constants that spread a counter over the octets.
const case_count = 512;
const mix: usize = 2654435761;
const mix_shift = 7;
