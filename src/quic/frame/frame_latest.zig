//! The most recent frame of one kind for one scope, which RFC 9000 §13.3 sends again when the
//! packet carrying it is lost. Part of design §8 step 9e.
//!
//! §13.3 words the rule for each frame it applies to: "An updated value is sent in a MAX_DATA
//! frame if the packet containing the most recently sent MAX_DATA frame is declared lost", and a
//! RESET_STREAM "is sent until acknowledged". What each needs is the number of the one packet that
//! last carried the frame, and whether a frame is owed. A scope is whatever the frame names: the
//! connection, one stream, or one stream type. A loss is matched by number, so nothing is kept
//! per packet.
const std = @import("std");
const core = @import("core");
const frame_module = @import("frame.zig");

const Writer = core.Writer;

pub const Latest = struct {
    /// The number of the 1-RTT packet that carried the most recent frame, when `sent` is set.
    sent_in: u64 = 0,
    sent: bool = false,
    /// Whether a frame is owed. What it says is decided when it is written.
    owed: bool = false,

    /// Records that packet `number` carried a frame for this scope.
    pub fn on_sent(latest: *Latest, number: u64) void {
        latest.sent_in = number;
        latest.sent = true;
        latest.owed = false;
    }

    /// Owes a frame again when packet `number` carried the most recent one (RFC 9000 §13.3).
    pub fn on_lost(latest: *Latest, number: u64) void {
        if (!latest.carried_by(number)) return;
        latest.sent = false;
        latest.owed = true;
    }

    /// Whether packet `number` carried the most recent frame for this scope.
    pub fn carried_by(latest: *const Latest, number: u64) bool {
        return latest.sent and latest.sent_in == number;
    }

    /// Writes `frame` into packet `number` and records it, or leaves the frame owed when it does
    /// not fit, so the next packet carries it. True when it was written.
    pub fn write(latest: *Latest, writer: *Writer, frame: frame_module.Frame, number: u64) bool {
        frame_module.write(writer, frame) catch {
            latest.owed = true;
            return false;
        };
        latest.on_sent(number);
        return true;
    }
};

const testing = std.testing;

test "§13.3: a lost frame is owed again only when it was the most recent" {
    var latest: Latest = .{};
    // Nothing sent, so no loss matches.
    latest.on_lost(0);
    try testing.expect(!latest.owed);
    latest.on_sent(4);
    latest.on_sent(7);
    latest.on_lost(4);
    try testing.expect(!latest.owed);
    try testing.expect(latest.carried_by(7));
    latest.on_lost(7);
    try testing.expect(latest.owed);
    try testing.expect(!latest.sent);
    try testing.expect(!latest.carried_by(7));
    // Sending again clears what was owed.
    latest.on_sent(9);
    try testing.expect(!latest.owed);
    try testing.expectEqual(9, latest.sent_in);
}

test "§13.3: a frame with no room stays owed, and one that fits is recorded" {
    var latest: Latest = .{};
    var none: [0]u8 = undefined;
    var full = Writer.init(&none);
    try testing.expect(!latest.write(&full, .handshake_done, 3));
    try testing.expect(latest.owed);
    var room: [1]u8 = undefined;
    var writer = Writer.init(&room);
    try testing.expect(latest.write(&writer, .handshake_done, 3));
    try testing.expect(!latest.owed);
    try testing.expect(latest.carried_by(3));
}
