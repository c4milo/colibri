//! Flow control (RFC 9000 §4.1) and stream concurrency (§4.6). Part of design §8 step 9c.
//!
//! Both are the same shape: a limit the peer advertises, a total this endpoint has used against
//! it, and a rule that a larger limit replaces a smaller one while a smaller one is ignored.
//! §4.1 states that for data — "Once a receiver advertises a limit for the connection or a
//! stream, it is not an error to advertise a smaller limit, but the smaller limit has no effect"
//! — and §4.6 states the same for streams. So one type serves the sending side of all four
//! counters a connection has: its own data, each stream's data, and the two stream counts.
//!
//! The receiving side is the other half of each pair and is a different question, because a peer
//! that passes a limit is an error rather than a wait: §4.1 makes it FLOW_CONTROL_ERROR and §4.6
//! makes it STREAM_LIMIT_ERROR. `Receiver` answers that, and says when it is worth telling the
//! peer about more room.
//!
//! Nothing here reads a clock or holds an octet. A sender asks how much it may send and a
//! receiver says whether what arrived was permitted; the buffering is the caller's.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const error_code = @import("error_code.zig");

/// What this endpoint may send against a limit the peer set (RFC 9000 §4.1, §4.6).
pub const Sender = struct {
    /// The largest total the peer has permitted.
    limit: u64,
    /// The total already spent against it: octets for data, streams opened for a count.
    used: u64,
    /// The limit this endpoint last told the peer it was blocked at, so the frame RFC 9000 §4.1
    /// and §4.6 ask for goes out once per limit and not once per attempt. A limit only rises,
    /// so a raise needs no clearing here: the next one reached is a value never reported.
    blocked_reported_at: ?u64,

    pub fn init(limit: u64) Sender {
        return .{ .limit = limit, .used = 0, .blocked_reported_at = null };
    }

    /// Raises the limit. RFC 9000 §4.1, §4.6: a frame that does not increase the limit MUST be
    /// ignored, so a smaller value returns false and changes nothing.
    pub fn raise(sender: *Sender, limit: u64) bool {
        if (limit <= sender.limit) return false;
        sender.limit = limit;
        return true;
    }

    /// What is left before the limit (RFC 9000 §4.1).
    pub fn available(sender: *const Sender) u64 {
        assert(sender.used <= sender.limit);
        return sender.limit - sender.used;
    }

    pub fn is_blocked(sender: *const Sender) bool {
        return sender.available() == 0;
    }

    /// Spends `amount` against the limit. RFC 9000 §4.1: a sender MUST NOT send data in excess
    /// of either limit, so a caller asks `available` first and this asserts what it was told.
    pub fn spend(sender: *Sender, amount: u64) void {
        assert(amount <= sender.available());
        sender.used += amount;
    }

    /// The limit to name in a STREAM_DATA_BLOCKED, DATA_BLOCKED or STREAMS_BLOCKED frame, or
    /// null when none is owed. RFC 9000 §4.1: a sender SHOULD send one to say it has data to
    /// write and is blocked; §4.6 asks the same of stream counts. One per limit is enough,
    /// because a peer that raises the limit learns nothing from a second.
    pub fn blocked_frame_limit(sender: *Sender) ?u64 {
        if (!sender.is_blocked()) return null;
        if (sender.blocked_reported_at) |reported| {
            if (reported == sender.limit) return null;
        }
        sender.blocked_reported_at = sender.limit;
        return sender.limit;
    }
};

/// Why a peer's use of a limit was refused.
pub const Error = error{
    /// RFC 9000 §4.1: the sender violated the advertised connection or stream data limit, which
    /// a receiver MUST close the connection for.
    FlowControlExceeded,
    /// RFC 9000 §4.6: a stream ID past the limit this endpoint advertised.
    StreamLimitExceeded,
};

/// RFC 9000 §20.1: the code each refusal closes the connection with.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        error.FlowControlExceeded => error_code.flow_control_error,
        error.StreamLimitExceeded => error_code.stream_limit_error,
    };
}

/// What a peer may send against a limit this endpoint set (RFC 9000 §4.1, §4.6).
pub const Receiver = struct {
    /// The largest total this endpoint has advertised.
    limit: u64,
    /// The largest total the peer has reached, which for data is one past its highest offset
    /// (§4.5) and for streams is the count it has opened.
    used: u64,
    /// The part of `used` the application has taken, which is what the next limit is measured
    /// from: §4.1 says a receiver could determine the offset to advertise from the data
    /// consumed.
    consumed: u64,
    /// How far ahead of what was consumed this endpoint keeps the limit.
    window: u64,

    pub fn init(window: u64) Receiver {
        assert(window > 0);
        return .{ .limit = window, .used = 0, .consumed = 0, .window = window };
    }

    /// Takes a peer's use of the limit: an offset one past its data for §4.1, or a count for
    /// §4.6. It is a high-water mark, so a retransmission that reaches less far is no error.
    pub fn use(receiver: *Receiver, reached: u64, failure: Error) Error!void {
        // RFC 9000 §4.1, §4.6: passing the limit this endpoint advertised ends the connection.
        if (reached > receiver.limit) return failure;
        receiver.used = @max(receiver.used, reached);
    }

    /// Records what the application took, which is what new credit is measured from (§4.1).
    pub fn consume(receiver: *Receiver, amount: u64) void {
        assert(receiver.consumed + amount <= receiver.used);
        receiver.consumed += amount;
    }

    /// The limit to advertise in a MAX_DATA, MAX_STREAM_DATA or MAX_STREAMS frame, or null when
    /// it is not worth one. RFC 9000 §4.2 leaves the timing to the implementation; colibri
    /// sends when the peer has used enough of its window that a round trip of silence would
    /// block it, which is `window / flow_credit_fraction`.
    pub fn credit_frame_limit(receiver: *Receiver) ?u64 {
        const next = receiver.consumed + receiver.window;
        assert(next >= receiver.limit or receiver.consumed < receiver.limit - receiver.window);
        const gain = next - receiver.limit;
        if (gain < receiver.window / constants.flow_credit_fraction) return null;
        receiver.limit = next;
        return next;
    }

    /// What the peer may still send before it is blocked.
    pub fn available(receiver: *const Receiver) u64 {
        assert(receiver.used <= receiver.limit);
        return receiver.limit - receiver.used;
    }
};

const testing = std.testing;

/// A window the tests measure credit against, and a fraction of it. Test-only.
const test_window = 1000;
const half_window = test_window / constants.flow_credit_fraction;

test "§4.1: a sender spends against the limit and is blocked at it" {
    var sender = Sender.init(test_window);
    try testing.expectEqual(test_window, sender.available());
    try testing.expect(!sender.is_blocked());
    sender.spend(600);
    try testing.expectEqual(400, sender.available());
    sender.spend(400);
    try testing.expect(sender.is_blocked());
    try testing.expectEqual(0, sender.available());
}

test "§4.1, §4.6: a larger limit takes effect and a smaller one is ignored" {
    var sender = Sender.init(test_window);
    sender.spend(test_window);
    // RFC 9000 §4.1: a frame that does not increase the limit MUST be ignored.
    try testing.expect(!sender.raise(test_window));
    try testing.expect(!sender.raise(test_window - 1));
    try testing.expectEqual(0, sender.available());
    try testing.expect(sender.raise(test_window + 500));
    try testing.expectEqual(500, sender.available());
    try testing.expect(!sender.is_blocked());
}

test "§4.1: a blocked sender says so once per limit" {
    var sender = Sender.init(test_window);
    // RFC 9000 §4.1: the frame says the sender has data to write and is blocked, so it is owed
    // only once it actually is.
    try testing.expectEqual(null, sender.blocked_frame_limit());
    sender.spend(test_window);
    try testing.expectEqual(test_window, sender.blocked_frame_limit().?);
    // A second attempt at the same limit tells the peer nothing it does not know.
    try testing.expectEqual(null, sender.blocked_frame_limit());
    // A raised limit that is reached again is worth a new frame.
    try testing.expect(sender.raise(test_window + 100));
    try testing.expectEqual(null, sender.blocked_frame_limit());
    sender.spend(100);
    try testing.expectEqual(test_window + 100, sender.blocked_frame_limit().?);
    try testing.expectEqual(null, sender.blocked_frame_limit());
}

test "§4.1: a peer that passes the limit ends the connection, and one that does not may retry" {
    var receiver = Receiver.init(test_window);
    try receiver.use(400, error.FlowControlExceeded);
    // A retransmission reaching less far is no error and lowers no mark.
    try receiver.use(100, error.FlowControlExceeded);
    try testing.expectEqual(400, receiver.used);
    try receiver.use(test_window, error.FlowControlExceeded);
    try testing.expectEqual(0, receiver.available());
    // RFC 9000 §4.1: one octet past the advertised limit is FLOW_CONTROL_ERROR.
    try testing.expectError(error.FlowControlExceeded, receiver.use(test_window + 1, error.FlowControlExceeded));
    // RFC 9000 §4.6 uses the same counter and its own code.
    var streams = Receiver.init(3);
    try streams.use(3, error.StreamLimitExceeded);
    try testing.expectError(error.StreamLimitExceeded, streams.use(4, error.StreamLimitExceeded));
    // RFC 9000 §20.1: FLOW_CONTROL_ERROR is 0x03 and STREAM_LIMIT_ERROR is 0x04.
    try testing.expectEqual(0x03, connection_error_code(error.FlowControlExceeded));
    try testing.expectEqual(0x04, connection_error_code(error.StreamLimitExceeded));
}

test "§4.1, §4.2: credit follows what the application took, not what arrived" {
    var receiver = Receiver.init(test_window);
    try receiver.use(test_window, error.FlowControlExceeded);
    // Everything arrived but nothing was read, so there is no more room to offer.
    try testing.expectEqual(null, receiver.credit_frame_limit());
    // Reading less than the fraction is not yet worth a frame.
    receiver.consume(half_window - 1);
    try testing.expectEqual(null, receiver.credit_frame_limit());
    receiver.consume(1);
    try testing.expectEqual(test_window + half_window, receiver.credit_frame_limit().?);
    // The limit moved, so the same read is not offered twice.
    try testing.expectEqual(null, receiver.credit_frame_limit());
    try testing.expectEqual(half_window, receiver.available());
}

test "§4.1: the window is what the limit stays ahead of, however much was read at once" {
    var receiver = Receiver.init(test_window);
    try receiver.use(test_window, error.FlowControlExceeded);
    // The application reads everything at once, so the limit jumps a whole window past it.
    receiver.consume(test_window);
    try testing.expectEqual(2 * test_window, receiver.credit_frame_limit().?);
    try testing.expectEqual(test_window, receiver.available());
    try receiver.use(2 * test_window, error.FlowControlExceeded);
    try testing.expectError(error.FlowControlExceeded, receiver.use(2 * test_window + 1, error.FlowControlExceeded));
}
