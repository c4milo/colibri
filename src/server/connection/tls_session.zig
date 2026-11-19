//! The TLS state of one TCP connection over TLS (decision 167): chapulin's session, and the
//! octets it opened that the protocol has not read. A connection over TLS holds a pointer to
//! one, which the engine takes from the buffer the program passes in `Config.tls_buffer`. A
//! cleartext connection holds none, so its slot holds no TLS state.

const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const constants = @import("../constants.zig");

pub const TlsSession = struct {
    server: tls.record.Server,
    /// The protocol's octets opened from records and not yet read. Its first `plain_in_read`
    /// octets are what the last event pointed into, dropped at the next call.
    plain_in: [constants.limits.plaintext_in_len]u8,
};

/// The octets a buffer takes to hold `connections` sessions at any address: each session's,
/// and the room to align the first, so the program declares a plain array of `u8`.
pub fn buffer_len(connections: usize) usize {
    if (connections == 0) return 0;
    return connections * @sizeOf(TlsSession) + @alignOf(TlsSession) - 1;
}

/// The sessions `buffer` holds once its start is aligned, at most `sessions_max`.
pub fn sessions_in(buffer: []u8, sessions_max: usize) []TlsSession {
    const aligned = std.mem.alignInSlice(buffer, @alignOf(TlsSession)) orelse return &.{};
    const count = @min(aligned.len / @sizeOf(TlsSession), sessions_max);
    const sessions: [*]TlsSession = @ptrCast(@alignCast(aligned.ptr));
    return sessions[0..count];
}

const testing = std.testing;

test "decision 167: a buffer of buffer_len(n) octets holds n sessions at any alignment" {
    // Room for two sessions and one octet of shift past each alignment the buffer can start at.
    const held = 2;
    const Buffer = struct {
        threadlocal var octets: [buffer_len(held) + @alignOf(TlsSession)]u8 align(@alignOf(TlsSession)) = undefined;
    };
    for (0..@alignOf(TlsSession)) |shift| {
        const buffer = Buffer.octets[shift..][0..buffer_len(held)];
        const sessions = sessions_in(buffer, held + 1);
        try testing.expectEqual(held, sessions.len);
        const start = @intFromPtr(sessions.ptr) - @intFromPtr(buffer.ptr);
        try testing.expect(start + held * @sizeOf(TlsSession) <= buffer.len);
        try testing.expectEqual(0, @intFromPtr(sessions.ptr) % @alignOf(TlsSession));
    }
}

test "decision 167: no connections take no octets, and a short buffer holds no session" {
    try testing.expectEqual(0, buffer_len(0));
    // One octet short, at the start that wastes the most octets to align.
    const Buffer = struct {
        threadlocal var octets: [buffer_len(1)]u8 align(@alignOf(TlsSession)) = undefined;
    };
    try testing.expectEqual(0, sessions_in(Buffer.octets[1..], 1).len);
    try testing.expectEqual(1, sessions_in(Buffer.octets[0 .. buffer_len(1) - 1], 1).len);
    // At most `sessions_max`, though the buffer holds more.
    const Room = struct {
        threadlocal var octets: [buffer_len(3)]u8 = undefined;
    };
    try testing.expectEqual(2, sessions_in(&Room.octets, 2).len);
}

comptime {
    assert(@sizeOf(TlsSession) % @alignOf(TlsSession) == 0);
}
