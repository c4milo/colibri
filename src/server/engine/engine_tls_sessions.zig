//! The TLS sessions of an engine's TCP connections over TLS (decision 167): those the program's
//! `Config.tls_buffer` holds, and the ones no connection holds. A connection over TLS takes one
//! at `accept`, and its slot gives it back when the engine releases the slot.

const std = @import("std");
const assert = std.debug.assert;
const tls_session = @import("../connection/tls_session.zig");
const TlsSession = tls_session.TlsSession;

pub const TlsSessions = struct {
    sessions: []TlsSession,
    /// The number of each free session, the next one to take last.
    free: []u32,
    free_len: usize,

    /// Cuts `buffer` into sessions, at most one for each entry of `free`, and frees them all.
    pub fn init(held: *TlsSessions, buffer: []u8, free: []u32) void {
        held.sessions = tls_session.sessions_in(buffer, free.len);
        held.free = free;
        held.free_len = held.sessions.len;
        // The first session is taken first.
        for (free[0..held.sessions.len], 0..) |*number, index| number.* = @intCast(held.sessions.len - 1 - index);
    }

    /// A session no connection holds, or null when each is held.
    pub fn take(held: *TlsSessions) ?*TlsSession {
        if (held.free_len == 0) return null;
        held.free_len -= 1;
        return &held.sessions[held.free[held.free_len]];
    }

    /// Frees `session`, which `take` gave.
    pub fn put(held: *TlsSessions, session: *TlsSession) void {
        const offset = @intFromPtr(session) - @intFromPtr(held.sessions.ptr);
        assert(offset % @sizeOf(TlsSession) == 0);
        const number = offset / @sizeOf(TlsSession);
        assert(number < held.sessions.len and held.free_len < held.sessions.len);
        held.free[held.free_len] = @intCast(number);
        held.free_len += 1;
    }
};

const testing = std.testing;

test "decision 167: a session is taken once until it is freed, and none is left past the buffer" {
    const Buffer = struct {
        threadlocal var octets: [tls_session.buffer_len(2)]u8 = undefined;
        threadlocal var free: [3]u32 = undefined;
    };
    var held: TlsSessions = undefined;
    held.init(&Buffer.octets, &Buffer.free);
    const first = held.take().?;
    const second = held.take().?;
    try testing.expect(first != second);
    try testing.expectEqual(&held.sessions[0], first);
    try testing.expectEqual(null, held.take());
    held.put(first);
    try testing.expectEqual(first, held.take().?);
    try testing.expectEqual(null, held.take());
    // The session freed is the one taken next, whichever it is.
    held.put(second);
    try testing.expectEqual(second, held.take().?);
    held.put(second);
    held.put(first);
    try testing.expectEqual(2, held.free_len);
}

test "decision 167: an empty buffer holds no session" {
    var free: [4]u32 = undefined;
    var empty: [0]u8 = .{};
    var held: TlsSessions = undefined;
    held.init(&empty, &free);
    try testing.expectEqual(null, held.take());
}
