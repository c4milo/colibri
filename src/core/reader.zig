//! The bounded reader of invariant 3. Every parser in colibri reads peer bytes through it, from a
//! slice the caller owns, and it never reads past the end of that slice.
//!
//! Three rules hold for every read:
//!   1. A read that needs more octets than remain returns `error.Truncated` and leaves the cursor
//!      where it was, so a declared length is checked against the bytes present before any of
//!      them are used (invariant 9).
//!   2. A successful read moves the cursor past exactly the octets it returned, so the caller
//!      always knows how many octets it consumed.
//!   3. Integers are assembled octet by octet, most significant first, whatever the host's byte
//!      order. The wire is network byte order in h2 (RFC 9113 §2.2) and in QUIC (RFC 9000 §1.3).
//!
//! A parser that must not consume anything on failure copies the reader, reads through the copy,
//! and assigns the copy back only when the whole structure parsed. The reader is three words, so
//! the copy is free.
const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The structure being read runs past the end of the bytes present.
    Truncated,
};

pub const Reader = struct {
    bytes: []const u8,
    /// Octets consumed so far. Never exceeds `bytes.len`.
    offset: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    /// Octets not yet consumed.
    pub fn remaining_len(self: *const Reader) usize {
        assert(self.offset <= self.bytes.len);
        return self.bytes.len - self.offset;
    }

    /// The octets consumed so far, from the start of the slice.
    pub fn consumed(self: *const Reader) []const u8 {
        assert(self.offset <= self.bytes.len);
        return self.bytes[0..self.offset];
    }

    /// The next octet, without consuming it.
    pub fn peek_byte(self: *const Reader) Error!u8 {
        if (self.remaining_len() == 0) return error.Truncated;
        return self.bytes[self.offset];
    }

    pub fn read_byte(self: *Reader) Error!u8 {
        const byte = try self.peek_byte();
        self.offset += 1;
        assert(self.offset <= self.bytes.len);
        return byte;
    }

    /// The next `len` octets, all of them or none. A short slice is never returned.
    pub fn take(self: *Reader, len: usize) Error![]const u8 {
        if (len > self.remaining_len()) return error.Truncated;
        const start = self.offset;
        self.offset += len;
        assert(self.offset <= self.bytes.len);
        return self.bytes[start..self.offset];
    }

    /// Every octet not yet consumed. Never fails: an empty remainder is an empty slice.
    pub fn take_rest(self: *Reader) []const u8 {
        return self.take(self.remaining_len()) catch unreachable;
    }

    /// An unsigned integer of `@sizeOf(T)` octets in network byte order.
    pub fn read_int(self: *Reader, comptime T: type) Error!T {
        comptime assert(@typeInfo(T).int.signedness == .unsigned);
        comptime assert(@bitSizeOf(T) % @bitSizeOf(u8) == 0 and @bitSizeOf(T) > 0);
        const bytes = try self.take(@sizeOf(T));
        var value: T = 0;
        for (bytes) |byte| {
            value = if (@sizeOf(T) == 1) byte else (value << @bitSizeOf(u8)) | byte;
        }
        return value;
    }
};

const testing = std.testing;

test "a read inside the slice returns the octets and moves the cursor" {
    var reader = Reader.init(&.{ 0x01, 0x02, 0x03, 0x04, 0x05 });
    try testing.expectEqual(0x01, try reader.peek_byte());
    try testing.expectEqual(0x01, try reader.read_byte());
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x03 }, try reader.take(2));
    try testing.expectEqual(2, reader.remaining_len());
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, reader.consumed());
    try testing.expectEqualSlices(u8, &.{ 0x04, 0x05 }, reader.take_rest());
    try testing.expectEqual(0, reader.remaining_len());
    try testing.expectEqualSlices(u8, &.{}, reader.take_rest());
}

test "a read past the end returns Truncated and consumes nothing" {
    var reader = Reader.init(&.{ 0xaa, 0xbb });
    try testing.expectError(error.Truncated, reader.take(3));
    try testing.expectEqual(0, reader.offset);
    try testing.expectError(error.Truncated, reader.read_int(u32));
    try testing.expectEqual(0, reader.offset);
    _ = try reader.take(2);
    try testing.expectError(error.Truncated, reader.read_byte());
    try testing.expectError(error.Truncated, reader.peek_byte());
    try testing.expectEqual(2, reader.offset);
}

test "integers read in network byte order" {
    var reader = Reader.init(&.{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11 });
    try testing.expectEqual(0x1234, try reader.read_int(u16));
    try testing.expectEqual(0x56789abc, try reader.read_int(u32));
    try testing.expectEqual(0xde, try reader.read_int(u8));
    try testing.expectEqual(0xf011, try reader.read_int(u16));
}

test "an empty slice reads as truncated and takes zero octets" {
    var reader = Reader.init(&.{});
    try testing.expectError(error.Truncated, reader.peek_byte());
    try testing.expectEqualSlices(u8, &.{}, try reader.take(0));
}
