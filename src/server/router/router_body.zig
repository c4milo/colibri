//! The reader of a request body (decision 127 ruling 2, design §8 step 25.3). The root exports
//! none of it.
//!
//! The router's reader reads the bytes that arrived. When they are all read and the body has not
//! ended, a read fails with `error.ReadFailed`. At the request's last byte a read fails with
//! `error.EndOfStream`. A stream route's `server.RequestBodyStream` reads the body through it, or
//! through the last wrapper of a middleware's `wrap_body` (decision 163 ruling 6). The bytes that
//! `on_data` leaves unread, those that `keep` kept among them, are copied into the entry's
//! `body_bytes`, and the next `on_data` reads them first. Through a wrapper, the stream copies the
//! octets that `keep` kept to the end of `body_bytes` instead, and the bytes that the router holds
//! stay clear of them (decision 163 ruling 6 as amended). A function route's every byte is copied
//! there, and the route reads them all at the body's end (decision 163 ruling 4).
const std = @import("std");
const assert = std.debug.assert;
const RequestBodyStream = @import("../request_body_stream.zig").RequestBodyStream;

/// What `append` refuses: the body does not fit the entry's `body_bytes`.
pub const Error = error{ContentTooLarge};

pub fn Body(comptime body_bytes: usize) type {
    return struct {
        /// The bytes a call left unread, then the bytes that arrived after them.
        held: [body_bytes]u8 = undefined,
        held_len: usize = 0,
        /// Whether the route got the last byte, or the router dropped the body, so no body event
        /// calls the route again.
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
            // A route that read none of the held octets leaves them at the start of `held`, so
            // nothing moves. A copy there cost each event every octet held, which grew with the
            // square of a body that a route keeps whole (design §8 step 55).
            if (@intFromPtr(unread.ptr) != @intFromPtr(&body.held)) @memmove(body.held[0..unread.len], unread);
            body.held_len = unread.len;
        }
    };
}

/// Lets go of the piece that `next` gave last, less the octets that `keep` kept, once `on_data`
/// returns. The reader then holds the kept octets at its seek, and the next `on_data` starts with
/// them. Through a wrapper, the end of the stream's `storage` may hold them instead, and the
/// wrapper then holds none of the piece. `wraps` says whether the route's chain has a wrapper.
pub fn let_go(body_stream: *RequestBodyStream, comptime wraps: bool) void {
    if (!wraps or !body_stream.stored) body_stream.reader.toss(body_stream.given - body_stream.kept);
    body_stream.given = body_stream.kept;
}

/// The octets of the end of the stream's `storage` that the octets the router holds stay clear of:
/// the octets that `keep` kept through a wrapper, which `storage` holds or will hold.
pub fn stored_len(body_stream: *const RequestBodyStream) usize {
    return if (body_stream.wrapped) body_stream.kept else 0;
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
