//! One direction of the TCP trace run (https://github.com/c4milo/colibri/issues/79): every octet
//! one side handed the other, how many of them the reader consumed, and the protocol's octets they
//! carried.
//!
//! In cleartext the octets handed out are the protocol's. Over TLS they are records, so each send
//! notes the plaintext it sealed and where it ended, in octets handed out and in plaintext. A
//! reader that consumed the records of whole sends has opened the plaintext those sends sealed.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h2_trace_state = @import("h2_trace_state.zig");

const limits = sim.constants.tcp_trace;
pub const HeadKind = h2_trace_state.HeadKind;

/// Where one send ended: the octets handed out by then, and the plaintext sealed by then.
const SendEnd = struct {
    handed: usize,
    plaintext_len: usize,
};

pub const Direction = struct {
    octets: [limits.stream_len_max]u8 = undefined,
    handed: usize = 0,
    consumed: usize = 0,
    /// The protocol's octets every send sealed, in order, and where each send ended. In cleartext a
    /// send seals nothing, and the plaintext is what it handed out.
    plaintext: [limits.stream_len_max]u8 = undefined,
    plaintext_len: usize = 0,
    send_ends: [limits.sends_max]SendEnd = undefined,
    send_ends_len: usize = 0,
    /// A send wrote the protocol's octets after it sealed some, so the run cannot tell which of
    /// them it sealed.
    unplaced: bool = false,
    /// The kind of each HEADERS frame the server wrote, in order, which its caller's calls decide.
    /// The client writes request heads alone.
    heads: [limits.headers_max]HeadKind = undefined,
    heads_written: usize = 0,

    pub fn unread(direction: *Direction) []u8 {
        return direction.octets[direction.consumed..direction.handed];
    }

    pub fn room(direction: *Direction) []u8 {
        return direction.octets[direction.handed..];
    }

    pub fn note_head(direction: *Direction, kind: HeadKind) void {
        assert(direction.heads_written < direction.heads.len);
        direction.heads[direction.heads_written] = kind;
        direction.heads_written += 1;
    }

    /// Copies `pending`, the protocol's octets the writer holds before a send, after the plaintext
    /// sealed so far. `note_send` keeps what the send sealed of them.
    pub fn stage(direction: *Direction, pending: []const u8) void {
        assert(direction.plaintext_len + pending.len <= direction.plaintext.len);
        @memcpy(direction.plaintext[direction.plaintext_len..][0..pending.len], pending);
    }

    /// Notes a send that handed out `written` octets, after which the writer holds `left`, the
    /// end of what `stage` copied when the send wrote nothing else. Over TLS the send sealed the
    /// staged octets before `left`; in cleartext it handed those octets out as they were.
    pub fn note_send(direction: *Direction, staged_len: usize, written: usize, left: []const u8) void {
        assert(direction.send_ends_len < direction.send_ends.len);
        const staged = direction.plaintext[direction.plaintext_len..][0..staged_len];
        if (left.len > staged.len or !std.mem.eql(u8, staged[staged.len - left.len ..], left)) {
            direction.unplaced = true;
        } else {
            direction.plaintext_len += staged.len - left.len;
        }
        direction.handed += written;
        direction.send_ends[direction.send_ends_len] = .{ .handed = direction.handed, .plaintext_len = direction.plaintext_len };
        direction.send_ends_len += 1;
    }

    /// The protocol's octets every send handed out.
    pub fn handed_plaintext(direction: *const Direction) []const u8 {
        return direction.plaintext[0..direction.plaintext_len];
    }

    /// The protocol's octets in what the reader consumed, or null when the run cannot place them.
    /// In cleartext they are the octets themselves. Over TLS they are the plaintext of the sends
    /// whose records the reader consumed whole.
    pub fn opened_plaintext(direction: *const Direction, tls: bool) ?usize {
        if (direction.unplaced) return null;
        if (!tls or direction.consumed == 0) return direction.consumed;
        for (direction.send_ends[0..direction.send_ends_len]) |end| {
            if (end.handed == direction.consumed) return end.plaintext_len;
        }
        return null;
    }
};

const testing = std.testing;

test "a reader that consumed whole sends over TLS opened what they sealed, and one inside a send is not placed" {
    var direction: Direction = .{};
    direction.stage("abc");
    direction.note_send(3, 10, "");
    direction.stage("defg");
    direction.note_send(4, 12, "g");
    try testing.expectEqualStrings("abcdef", direction.handed_plaintext());
    direction.consumed = 10;
    try testing.expectEqual(3, direction.opened_plaintext(true).?);
    // In cleartext the octets are the protocol's, whatever the sends were.
    try testing.expectEqual(10, direction.opened_plaintext(false).?);
    direction.consumed = 11;
    try testing.expectEqual(null, direction.opened_plaintext(true));
    // A send that left octets it had not staged wrote after it sealed.
    direction.stage("h");
    direction.note_send(1, 0, "xy");
    try testing.expectEqual(null, direction.opened_plaintext(false));
}
