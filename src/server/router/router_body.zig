//! The request body a route reads through a `std.Io.Reader` (decision 127 ruling 2, design §8 step
//! 25.3). The root exports none of it.
//!
//! A route's `on_body` gets a reader over the bytes that arrived. When it has read them all and the
//! body has not ended, a read fails with `error.ReadFailed`, and an `on_body` that returns it waits for
//! the next bytes. At the request's last byte a read fails with `error.EndOfStream`. The bytes a
//! call leaves unread are copied into the entry's `body_bytes`, and the next call reads them first.
//! With `.whole_body`, every byte is copied there, and `on_body` runs once, after the last.
const std = @import("std");
const assert = std.debug.assert;

/// What `append` refuses: the body does not fit the entry's `body_bytes`.
pub const Error = error{ContentTooLarge};

pub fn Body(comptime body_bytes: usize) type {
    return struct {
        /// The bytes a call left unread, then the bytes that arrived after them.
        held: [body_bytes]u8 = undefined,
        held_len: usize = 0,
        /// Whether `on_body` ran with the last byte, so it runs no more.
        delivered: bool = false,
        cursor: Cursor = .{},

        const Self = @This();

        /// Adds `bytes` after the held ones. A body that does not fit is refused.
        pub fn append(body: *Self, bytes: []const u8) Error!void {
            // RFC 9110 §15.5.14: content larger than the server takes gets 413.
            if (body.held_len + bytes.len > body_bytes) return error.ContentTooLarge;
            @memcpy(body.held[body.held_len..][0..bytes.len], bytes);
            body.held_len += bytes.len;
        }

        /// The reader over the held bytes, or over `bytes` when none are held, with no copy.
        pub fn reader_over(body: *Self, bytes: []const u8) *std.Io.Reader {
            const over = if (body.held_len == 0) bytes else body.held[0..body.held_len];
            body.cursor.reader.buffer = @constCast(over);
            body.cursor.reader.seek = 0;
            body.cursor.reader.end = over.len;
            return &body.cursor.reader;
        }

        /// Keeps what the last call left unread for the next one. `over_bytes` says whether the
        /// reader read the event's bytes, which the next `receive` reuses, or the held ones.
        pub fn keep_unread(body: *Self, over_bytes: bool) Error!void {
            const reader = &body.cursor.reader;
            const unread = reader.buffer[reader.seek..reader.end];
            reader.buffer = &.{};
            reader.seek = 0;
            reader.end = 0;
            if (over_bytes) {
                assert(body.held_len == 0);
                return body.append(unread);
            }
            std.mem.copyForwards(u8, body.held[0..unread.len], unread);
            body.held_len = unread.len;
        }
    };
}

/// The reader, and whether the request's last byte arrived, which a read past the bytes reads.
pub const Cursor = struct {
    reader: std.Io.Reader = .{ .vtable = &vtable, .buffer = &.{}, .seek = 0, .end = 0 },
    ended: bool = false,
};

const vtable: std.Io.Reader.VTable = .{ .stream = stream, .discard = discard, .readVec = read_vec, .rebase = rebase };

/// The error of a read past the bytes that arrived: the end of the body, or bytes still to come.
fn past(reader: *std.Io.Reader) std.Io.Reader.Error {
    const cursor: *const Cursor = @alignCast(@fieldParentPtr("reader", reader));
    return if (cursor.ended) error.EndOfStream else error.ReadFailed;
}

fn stream(reader: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
    return past(reader);
}

fn discard(reader: *std.Io.Reader, _: std.Io.Limit) std.Io.Reader.Error!usize {
    return past(reader);
}

fn read_vec(reader: *std.Io.Reader, _: [][]u8) std.Io.Reader.Error!usize {
    return past(reader);
}

fn rebase(reader: *std.Io.Reader, _: usize) std.Io.Reader.RebaseError!void {
    return past(reader);
}
