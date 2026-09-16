//! The bounded writer of invariant 3. All output colibri produces is written through it, into a
//! slice the caller owns, and it never writes past the end of that slice.
//!
//! Three rules hold for every write:
//!   1. A write that needs more octets than remain returns `error.NoSpaceLeft` and writes nothing,
//!      so the caller never finds half a field in its buffer.
//!   2. A successful write moves the cursor past exactly the octets it wrote, so the caller always
//!      knows how many octets to send.
//!   3. Integers are written octet by octet, most significant first, whatever the host's byte
//!      order. The wire is network byte order in h2 (RFC 9113 §2.2) and in QUIC (RFC 9000 §1.3).
//!
//! An encoder that writes a structure in several writes copies the writer, writes through the
//! copy, and assigns the copy back only when the whole structure fit. Octets past the committed
//! cursor are scratch: nothing reads them as output.
const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The caller's buffer has fewer octets left than the write needs.
    NoSpaceLeft,
};

pub const Writer = struct {
    buffer: []u8,
    /// Octets written so far. Never exceeds `buffer.len`.
    offset: usize = 0,

    pub fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer };
    }

    /// Octets still free in the caller's buffer.
    pub fn remaining_len(self: *const Writer) usize {
        assert(self.offset <= self.buffer.len);
        return self.buffer.len - self.offset;
    }

    /// Every octet written so far, from the start of the buffer.
    pub fn written(self: *const Writer) []const u8 {
        assert(self.offset <= self.buffer.len);
        return self.buffer[0..self.offset];
    }

    pub fn write_byte(self: *Writer, byte: u8) Error!void {
        if (self.remaining_len() == 0) return error.NoSpaceLeft;
        self.buffer[self.offset] = byte;
        self.offset += 1;
        assert(self.offset <= self.buffer.len);
    }

    /// All of `bytes`, or nothing.
    pub fn write_bytes(self: *Writer, bytes: []const u8) Error!void {
        if (bytes.len > self.remaining_len()) return error.NoSpaceLeft;
        const end = self.offset + bytes.len;
        @memcpy(self.buffer[self.offset..end], bytes);
        self.offset = end;
        assert(self.offset <= self.buffer.len);
    }

    /// Text formatted as `std.fmt` formats it, all of it or none. For colibri's own text formats —
    /// the golden manifest and the simulator trace of design §6.6 — never for a wire format.
    pub fn print(self: *Writer, comptime format: []const u8, arguments: anytype) Error!void {
        assert(self.offset <= self.buffer.len);
        const text = std.fmt.bufPrint(self.buffer[self.offset..], format, arguments) catch
            return error.NoSpaceLeft;
        self.offset += text.len;
        assert(self.offset <= self.buffer.len);
    }

    /// An unsigned integer as `@sizeOf(T)` octets in network byte order, all of them or none.
    pub fn write_int(self: *Writer, comptime T: type, value: T) Error!void {
        comptime assert(@typeInfo(T).int.signedness == .unsigned);
        comptime assert(@bitSizeOf(T) % 8 == 0 and @bitSizeOf(T) > 0);
        var octets: [@sizeOf(T)]u8 = @splat(0);
        var rest: T = value;
        for (0..@sizeOf(T)) |index| {
            octets[@sizeOf(T) - 1 - index] = @truncate(rest);
            rest = if (@sizeOf(T) == 1) 0 else rest >> 8;
        }
        assert(rest == 0);
        try self.write_bytes(&octets);
    }
};

const testing = std.testing;

test "a write inside the buffer lands and moves the cursor" {
    var buffer: [8]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try writer.write_byte(0x01);
    try writer.write_bytes(&.{ 0x02, 0x03 });
    try writer.write_int(u16, 0x0405);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04, 0x05 }, writer.written());
    try testing.expectEqual(3, writer.remaining_len());
}

test "a write past the end returns NoSpaceLeft and writes nothing" {
    var buffer: [3]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try writer.write_byte(0x01);
    try testing.expectError(error.NoSpaceLeft, writer.write_bytes(&.{ 0x02, 0x03, 0x04 }));
    try testing.expectError(error.NoSpaceLeft, writer.write_int(u32, 0x02030405));
    try testing.expectEqual(1, writer.offset);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0xee, 0xee }, &buffer);
    try writer.write_bytes(&.{ 0x02, 0x03 });
    try testing.expectError(error.NoSpaceLeft, writer.write_byte(0x04));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, writer.written());
}

test "integers write in network byte order" {
    var buffer: [15]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try writer.write_int(u8, 0xab);
    try writer.write_int(u16, 0x1234);
    try writer.write_int(u32, 0x56789abc);
    try writer.write_int(u64, 0x0102030405060708);
    try testing.expectEqualSlices(u8, &.{
        0xab, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    }, writer.written());
}

test "formatted text lands whole or not at all" {
    var buffer: [8]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try writer.print("len={d}", .{42});
    try testing.expectError(error.NoSpaceLeft, writer.print(" crc={x}", .{0xdeadbeef}));
    try testing.expectEqualStrings("len=42", writer.written());
}

test "an empty buffer takes an empty write and refuses a byte" {
    var writer = Writer.init(&.{});
    try writer.write_bytes(&.{});
    try testing.expectError(error.NoSpaceLeft, writer.write_byte(0));
}
