//! The decoder stream (RFC 9204 §4.4): the instructions the decoder owes the encoder, written
//! when the caller asks for them (decision 74). Part of design §8 step 11.
//!
//! The decoder queues Section Acknowledgments and Stream Cancellations as they arise, oldest
//! first. The third instruction, Insert Count Increment, is worked out here: RFC 9204 §4.4.3 has
//! it raise the Known Received Count to the insert count, and an acknowledgment written first may
//! already have raised it (§2.1.4). So the increment follows the queue, and reports only what the
//! acknowledgments did not. Every instruction is written whole or not at all.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const instruction = @import("instruction.zig");
const decoder_module = @import("decoder.zig");

const Writer = core.Writer;
const Decoder = decoder_module.Decoder;
const Owed = decoder_module.Owed;

/// Writes every owed instruction that fits into `writer`, oldest first, and forgets what it
/// wrote.
pub fn write(decoder: *Decoder, writer: *Writer) void {
    var written: usize = 0;
    for (decoder.owed[0..decoder.owed_len]) |owed| {
        write_one(decoder, writer, owed) catch break;
        written += 1;
    }
    const kept = decoder.owed_len - written;
    std.mem.copyForwards(Owed, decoder.owed[0..kept], decoder.owed[written..decoder.owed_len]);
    decoder.owed_len = kept;
    // The increment waits for every queued acknowledgment, since each may raise the count.
    if (kept > 0) return;
    const increment = decoder.table.insert_count() - decoder.known_received;
    // RFC 9204 §4.4.3: an Increment of zero is an error at the encoder, so none is sent.
    if (increment == 0) return;
    instruction.write_decoder(writer, .{ .insert_count_increment = increment }) catch return;
    decoder.known_received += increment;
    assert(decoder.known_received == decoder.table.insert_count());
}

/// Whether the decoder owes the encoder any instruction.
pub fn owes(decoder: *const Decoder) bool {
    return decoder.owed_len > 0 or decoder.known_received < decoder.table.insert_count();
}

fn write_one(decoder: *Decoder, writer: *Writer, owed: Owed) core.writer.Error!void {
    switch (owed) {
        .section_acknowledgment => |section| {
            try instruction.write_decoder(writer, .{ .section_acknowledgment = section.stream_id });
            // RFC 9204 §2.1.4: an acknowledged section whose Required Insert Count is above the
            // Known Received Count raises it to that count.
            decoder.known_received = @max(decoder.known_received, section.required_insert_count);
        },
        // §2.2.2.2: a cancellation says nothing about which entries arrived.
        .stream_cancellation => |stream_id| try instruction.write_decoder(writer, .{ .stream_cancellation = stream_id }),
    }
    assert(decoder.known_received <= decoder.table.insert_count());
}

const testing = std.testing;

/// The decoder the tests drive, placed outside any stack frame. Test-only.
var test_decoder: Decoder = undefined;
/// A table capacity that holds every entry the tests insert, and room for what they write.
/// Test-only.
const test_capacity: u64 = 220;
const test_room: usize = 16;

/// Applies one encoder instruction through the encoder stream. Test-only.
fn encode(held: instruction.Encoder) !void {
    var octets: [test_room]u8 = undefined;
    var writer = Writer.init(&octets);
    try instruction.write_encoder(&writer, held);
    var reader = core.Reader.init(writer.written());
    try test_decoder.read_encoder_stream(&reader);
}

/// Inserts `count` entries named `n` through the encoder stream. Test-only.
fn insert(count: u8) !void {
    for (0..count) |_| try encode(.{ .insert_literal = .{ .name = "n", .name_coding = .raw, .value = "v", .value_coding = .raw } });
}

fn start() !void {
    test_decoder.init(.{ .max_table_capacity = test_capacity });
    try encode(.{ .set_capacity = test_capacity });
}

fn expect_written(expected: []const u8) !void {
    var octets: [test_room]u8 = undefined;
    var writer = Writer.init(&octets);
    write(&test_decoder, &writer);
    try testing.expectEqualSlices(u8, expected, writer.written());
}

test "§4.4.3: new entries are reported once, by one increment" {
    try start();
    try expect_written(&.{});
    try testing.expect(!owes(&test_decoder));
    try insert(3);
    try testing.expect(owes(&test_decoder));
    // 0x03 is Insert Count Increment 3.
    try expect_written(&.{0x03});
    try testing.expect(!owes(&test_decoder));
    try expect_written(&.{});
}

test "§2.1.4: an acknowledgment that raises the count leaves only the rest to increment" {
    try start();
    try insert(3);
    test_decoder.owed[0] = .{ .section_acknowledgment = .{ .stream_id = 4, .required_insert_count = 2 } };
    test_decoder.owed_len = 1;
    // 0x84 acknowledges stream 4, which raises the count to 2, and 0x01 reports the third entry.
    try expect_written(&.{ 0x84, 0x01 });
    try testing.expectEqual(3, test_decoder.known_received);
}

test "§2.2.2.2: a cancellation leaves the count where it was" {
    try start();
    try insert(1);
    test_decoder.owed[0] = .{ .stream_cancellation = 8 };
    test_decoder.owed_len = 1;
    // 0x48 cancels stream 8, and 0x01 still reports the entry.
    try expect_written(&.{ 0x48, 0x01 });
}

test "the increment waits behind an acknowledgment that did not fit" {
    try start();
    try insert(3);
    // Stream 200 takes two octets, so a one-octet buffer holds the increment but not the
    // acknowledgment ahead of it.
    test_decoder.owed[0] = .{ .section_acknowledgment = .{ .stream_id = 200, .required_insert_count = 2 } };
    test_decoder.owed_len = 1;
    var octets: [1]u8 = undefined;
    var one = Writer.init(&octets);
    write(&test_decoder, &one);
    try testing.expectEqual(0, one.written().len);
    try testing.expectEqual(0, test_decoder.known_received);
    // 0xff 0x49 acknowledges stream 200, and 0x01 reports the entry past its count.
    try expect_written(&.{ 0xff, 0x49, 0x01 });
}

test "an instruction that does not fit waits whole, and the increment waits behind it" {
    try start();
    try insert(1);
    test_decoder.owed[0] = .{ .stream_cancellation = 8 };
    test_decoder.owed_len = 1;
    var octets: [1]u8 = undefined;
    var empty = Writer.init(octets[0..0]);
    write(&test_decoder, &empty);
    try testing.expectEqual(1, test_decoder.owed_len);
    try testing.expectEqual(0, test_decoder.known_received);
    // One octet is room for the cancellation but not the increment behind it.
    var one = Writer.init(&octets);
    write(&test_decoder, &one);
    try testing.expectEqualSlices(u8, &.{0x48}, one.written());
    try testing.expectEqual(0, test_decoder.owed_len);
    try testing.expect(owes(&test_decoder));
    try expect_written(&.{0x01});
}
