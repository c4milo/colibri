//! The octets of one of h3's own streams, kept until the peer acknowledges them (decision 79).
//! Part of design §8 step 12.
//!
//! h3 writes three streams that never end: its control stream (RFC 9114 §6.2.1) and QPACK's
//! encoder and decoder streams (RFC 9204 §4.2). `quic` reads a stream's octets back through the
//! stream provider whenever it sends or resends them (decision 57), so h3 keeps each octet until
//! the peer has it. `quic` reports how far that is from the stream's start (decision 78), and the
//! octets below it are dropped.
//!
//! The buffer holds the stream's octets from `start_offset` to `end_offset` at the front of a
//! fixed array. Dropping acknowledged octets moves the rest to the front, so the free room is one
//! slice at the end, which a `core.Writer` can write an instruction into whole. The move copies
//! only unacknowledged octets, and it happens only when a write finds too little room.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

const Writer = core.Writer;

pub fn SendBuffer(comptime capacity: usize) type {
    return struct {
        const Buffer = @This();

        octets: [capacity]u8,
        /// The stream offset of `octets[0]`: every octet below it was acknowledged.
        start_offset: u64,
        /// Octets held, from `start_offset`.
        len: usize,

        pub fn init(buffer: *Buffer) void {
            buffer.start_offset = 0;
            buffer.len = 0;
        }

        /// The stream offset one past the last octet written, which is what h3 supplies to `quic`.
        pub fn end_offset(buffer: *const Buffer) u64 {
            return buffer.start_offset + buffer.len;
        }

        /// Drops the octets below `acknowledged_end`, which the peer has (decision 78), and moves
        /// the rest to the front.
        pub fn drop_acknowledged(buffer: *Buffer, acknowledged_end: u64) void {
            // `quic` never reports an octet acknowledged that was not written, nor one it
            // reported acknowledged before as unacknowledged again.
            assert(acknowledged_end <= buffer.end_offset());
            if (acknowledged_end <= buffer.start_offset) return;
            const dropped: usize = @intCast(acknowledged_end - buffer.start_offset);
            std.mem.copyForwards(u8, buffer.octets[0 .. buffer.len - dropped], buffer.octets[dropped..buffer.len]);
            buffer.start_offset = acknowledged_end;
            buffer.len -= dropped;
        }

        /// A writer over the free room. What it writes becomes the stream's next octets once
        /// `commit` counts them.
        pub fn free(buffer: *Buffer) Writer {
            return Writer.init(buffer.octets[buffer.len..]);
        }

        /// Counts the octets a writer from `free` wrote.
        pub fn commit(buffer: *Buffer, written: []const u8) void {
            // The writer wrote into the free room, from its start.
            assert(written.len <= capacity - buffer.len);
            assert(written.len == 0 or written.ptr == buffer.octets[buffer.len..].ptr);
            buffer.len += written.len;
        }

        /// Writes `octets` whole, or nothing when they do not fit.
        pub fn write(buffer: *Buffer, octets: []const u8) core.writer.Error!void {
            var writer = buffer.free();
            try writer.write_bytes(octets);
            buffer.commit(writer.written());
        }

        /// Writes the stream's octets from `offset` into `output`, as many as fit and are held,
        /// and returns how many. `quic` reads only octets it has not seen acknowledged, which are
        /// all still here.
        pub fn read(buffer: *const Buffer, offset: u64, output: []u8) usize {
            assert(offset >= buffer.start_offset);
            if (offset >= buffer.end_offset()) return 0;
            const from: usize = @intCast(offset - buffer.start_offset);
            const len = @min(output.len, buffer.len - from);
            @memcpy(output[0..len], buffer.octets[from..][0..len]);
            return len;
        }
    };
}

const testing = std.testing;

/// A buffer small enough that a test fills it. Test-only.
const test_capacity: usize = 16;
var test_buffer: SendBuffer(test_capacity) = undefined;
var test_output: [test_capacity]u8 = undefined;

test "decision 79: octets written are read back by stream offset" {
    test_buffer.init();
    try test_buffer.write("abcdef");
    try test_buffer.write("gh");
    try testing.expectEqual(8, test_buffer.end_offset());
    try testing.expectEqual(3, test_buffer.read(5, &test_output));
    try testing.expectEqualStrings("fgh", test_output[0..3]);
    try testing.expectEqual(2, test_buffer.read(0, test_output[0..2]));
    try testing.expectEqualStrings("ab", test_output[0..2]);
    try testing.expectEqual(0, test_buffer.read(8, &test_output));
}

test "decision 79: a write that does not fit writes nothing, and dropping acknowledged octets makes room" {
    test_buffer.init();
    try test_buffer.write("0123456789abcdef");
    try testing.expectError(error.NoSpaceLeft, test_buffer.write("x"));
    try testing.expectEqual(16, test_buffer.end_offset());
    // The peer has the first ten; the rest move to the front and keep their offsets.
    test_buffer.drop_acknowledged(10);
    try testing.expectEqual(10, test_buffer.start_offset);
    try test_buffer.write("ghij");
    try testing.expectEqual(20, test_buffer.end_offset());
    try testing.expectEqual(10, test_buffer.read(10, &test_output));
    try testing.expectEqualStrings("abcdefghij", test_output[0..10]);
    // An end already dropped changes nothing.
    test_buffer.drop_acknowledged(4);
    try testing.expectEqual(10, test_buffer.start_offset);
    try testing.expectEqual(10, test_buffer.len);
}

test "decision 79: a writer over the free room commits what it wrote" {
    test_buffer.init();
    try test_buffer.write("abc");
    var writer = test_buffer.free();
    try writer.write_bytes("de");
    test_buffer.commit(writer.written());
    try testing.expectEqual(5, test_buffer.end_offset());
    try testing.expectEqual(2, test_buffer.read(3, &test_output));
    try testing.expectEqualStrings("de", test_output[0..2]);
}
