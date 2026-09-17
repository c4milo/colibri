//! The flow-control window of RFC 9113 §5.2 and §6.9: a credit counter in octets, kept once for
//! the connection and once per stream, in each direction (decision 13). The connection owns every
//! window. Nothing here knows about streams or frames.
//!
//! `Window` is the counter. On the send side it holds the space the peer advertised: DATA payloads
//! consume it, the peer's WINDOW_UPDATE frames add to it, and a change to the peer's
//! SETTINGS_INITIAL_WINDOW_SIZE adjusts every stream window by the difference (§6.9.2). On the
//! receive side it holds the space colibri advertised, with the roles mirrored. `Receiver` wraps
//! the receive side and decides when the credit the application freed is worth a WINDOW_UPDATE.
//!
//! The counter is signed (invariant 15). A send window goes below zero when a reduction in the
//! peer's SETTINGS_INITIAL_WINDOW_SIZE outruns data already sent (§6.9.2), and a receive window
//! goes below zero for the mirror reason (§6.9.3). Every operation asserts the counter stays in
//! `[-window_max, window_max]`. That assertion checks colibri's own arithmetic: a peer's number is
//! refused with an error before the counter moves, so a failed call changes nothing.
//!
//! Each operation makes one check, then moves the counter:
//!   1. `consume`: the payload fits the space available, or `error.Exceeded` (§6.9.1).
//!   2. `add` and `adjust`: the result is at most `window_max`, or `error.Overflow` (§6.9.1,
//!      §6.9.2).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// The largest window, as the signed quantity the counter holds (RFC 9113 §6.9.1).
const available_max: i64 = constants.window_max;

/// The floor of invariant 15's range. A window drops by at most the initial window it once held,
/// so it never goes below minus `window_max` (RFC 9113 §6.9.2).
const available_min: i64 = -available_max;

/// One flow-control window, connection or stream, in one direction: the credit a sender may still
/// spend on DATA payloads (RFC 9113 §6.9.1). On the send side the peer advertised it; on the
/// receive side colibri did, and `Receiver` wraps it.
pub const Window = struct {
    /// Octets the sender may still send. Negative after a reduction of the initial window that
    /// outran data already sent (RFC 9113 §6.9.2).
    available: i64,

    /// A window holding `initial` octets of credit. `initial` is at most `window_max`: the
    /// settings codec refuses a larger SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 §6.5.2) before a
    /// window is made from it.
    pub fn init(initial: u32) Window {
        assert(initial <= constants.window_max);
        const window: Window = .{ .available = initial };
        assert(window.in_range());
        return window;
    }

    /// Whether `available` is within invariant 15's range.
    pub fn in_range(window: *const Window) bool {
        return window.available >= available_min and window.available <= available_max;
    }

    /// The octets a flow-controlled frame may carry now: `available`, or 0 while the window is not
    /// positive.
    pub fn sendable(window: *const Window) u32 {
        assert(window.in_range());
        // RFC 9113 §6.9.2: a sender MUST NOT send new flow-controlled frames until the window
        // becomes positive.
        if (window.available <= 0) return 0;
        return @intCast(window.available);
    }

    /// Subtracts a flow-controlled payload of `len` octets. On the send side colibri calls this
    /// before sending, and `error.Exceeded` means the frame waits (RFC 9113 §6.9.1). On the
    /// receive side `Receiver.receive` calls it and names what `error.Exceeded` means there.
    ///
    /// An empty payload always fits, even on a negative window: an empty DATA frame carrying
    /// END_STREAM may be sent with no space available (§6.9.1). Without END_STREAM, an empty DATA
    /// frame on a window that is not positive is a new flow-controlled frame §6.9.2 forbids, and
    /// the connection refuses it, because this function does not see the flag.
    pub fn consume(window: *Window, len: u32) error{Exceeded}!void {
        assert(window.in_range());
        // RFC 9113 §6.9.1: the sender MUST NOT send a flow-controlled frame with a length that
        // exceeds the space available in either of the flow-control windows.
        if (len > window.sendable()) return error.Exceeded;
        window.available -= len;
        assert(len == 0 or window.available >= 0);
        assert(window.in_range());
    }

    /// Adds the increment of a WINDOW_UPDATE frame (RFC 9113 §6.9). The frame codec refuses an
    /// increment of 0 and masks the reserved bit before it gets here, so `increment` is in the
    /// legal range 1 to `window_max` (§6.9). `error.Overflow` means the increment pushed the
    /// window past `window_max`, and colibri terminates the stream with RST_STREAM or the
    /// connection with GOAWAY, either carrying FLOW_CONTROL_ERROR (§6.9.1).
    pub fn add(window: *Window, increment: u32) error{Overflow}!void {
        assert(window.in_range());
        assert(increment >= 1 and increment <= constants.window_max);
        // RFC 9113 §6.9.1: a sender MUST NOT allow a flow-control window to exceed 2^31-1 octets.
        if (window.available + increment > available_max) return error.Overflow;
        window.available += increment;
        assert(window.in_range());
    }

    /// Adds the difference a change to SETTINGS_INITIAL_WINDOW_SIZE makes, from
    /// `initial_window_delta`, to one stream window (RFC 9113 §6.9.2). The window may end below
    /// zero. `error.Overflow` means the change pushed the window past `window_max`, a connection
    /// error of FLOW_CONTROL_ERROR (§6.9.2).
    pub fn adjust(window: *Window, delta: i64) error{Overflow}!void {
        assert(window.in_range());
        assert(delta >= available_min and delta <= available_max);
        // RFC 9113 §6.9.2: a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control
        // window to exceed the maximum size is a connection error of type FLOW_CONTROL_ERROR.
        if (window.available + delta > available_max) return error.Overflow;
        window.available += delta;
        assert(window.in_range());
    }
};

/// The amount RFC 9113 §6.9.2 adds to every stream window when SETTINGS_INITIAL_WINDOW_SIZE
/// changes from `old` to `new`: `new - old`, negative when the window shrank. Both values are at
/// most `window_max`, which the settings codec checks (§6.5.2).
pub fn initial_window_delta(old: u32, new: u32) i64 {
    assert(old <= constants.window_max and new <= constants.window_max);
    const delta = @as(i64, new) - @as(i64, old);
    assert(delta >= available_min and delta <= available_max);
    return delta;
}

/// colibri's receive side of one window, connection or stream: the window it advertised to the
/// peer, the octets received that the application has not yet consumed, and the credit the
/// application freed that colibri has not yet sent back in a WINDOW_UPDATE. The connection owns
/// one for the connection window and one per stream.
///
/// The window is at least `window_update_threshold` octets, at `init` and after every adjustment
/// the connection makes to `window` when it lowers the initial window it advertises (RFC 9113
/// §6.9.3). A smaller window could fill without the freed credit ever reaching the threshold, so
/// no WINDOW_UPDATE would go out and the peer would stall at a zero window, because WINDOW_UPDATE
/// frames are what let a sender resume (§6.9.3). `init` asserts the contract; the initial window
/// colibri advertises is `window_initial`, and the threshold is half of it.
pub const Receiver = struct {
    /// The space the peer may still fill.
    window: Window,
    /// Octets received and charged to the window that the application has not yet consumed.
    unreleased: u32,
    /// Octets the application consumed since the last WINDOW_UPDATE, not yet credited back.
    released: u32,

    /// A receiver whose window holds `initial` octets and whose application has freed nothing.
    /// `initial` is at least `window_update_threshold`, as the type's comment explains.
    pub fn init(initial: u32) Receiver {
        assert(initial >= constants.window_update_threshold);
        const receiver: Receiver = .{
            .window = Window.init(initial),
            .unreleased = 0,
            .released = 0,
        };
        assert(receiver.in_range());
        return receiver;
    }

    /// Whether the window is within invariant 15's range and the three counts add up to the
    /// initial window colibri currently advertises: every octet of that window is either still
    /// available, held by the application, or freed and waiting to be credited back, so the sum
    /// is within `[0, window_max]`.
    pub fn in_range(receiver: *const Receiver) bool {
        const advertised = @as(i64, receiver.unreleased) + receiver.released +
            receiver.window.available;
        return receiver.window.in_range() and advertised >= 0 and advertised <= available_max;
    }

    /// Charges a DATA payload the peer sent against the window. The connection calls this on the
    /// connection window for every flow-controlled frame, even one in error, unless it treats the
    /// frame as a connection error (RFC 9113 §6.9). `error.Exceeded` means the peer sent past the
    /// limit colibri imposed, which a sender MUST respect (§5.2.1): the connection answers with
    /// FLOW_CONTROL_ERROR (§7). One exception is the connection's to judge: on a stream window
    /// colibri itself reduced, the peer may have sent the data before it processed the SETTINGS
    /// frame, and §6.9.3 lets the connection either keep processing the stream or reset it with
    /// FLOW_CONTROL_ERROR. The window does not move on `error.Exceeded` either way.
    pub fn receive(receiver: *Receiver, len: u32) error{Exceeded}!void {
        assert(receiver.in_range());
        try receiver.window.consume(len);
        receiver.unreleased += len;
        assert(receiver.in_range());
    }

    /// The application consumed `len` octets, at most the `unreleased` octets it was given. The
    /// credit accumulates in `released` until it reaches `window_update_threshold`, then goes back
    /// into the window and comes back as the increment the connection must send in a
    /// WINDOW_UPDATE (RFC 9113 §6.9.1 advises against very small increments; the threshold is
    /// colibri's, design §7). Below the threshold, null.
    pub fn release(receiver: *Receiver, len: u32) ?u32 {
        assert(receiver.in_range());
        assert(len <= receiver.unreleased);
        receiver.unreleased -= len;
        const released = @as(i64, receiver.released) + len;
        if (released < constants.window_update_threshold) {
            receiver.released = @intCast(released);
            assert(receiver.in_range());
            return null;
        }
        const increment: u32 = @intCast(released);
        assert(increment >= 1 and increment <= constants.window_max);
        // `in_range` held on entry, so the credit fits back into the window: no overflow.
        receiver.window.add(increment) catch unreachable;
        receiver.released = 0;
        assert(receiver.in_range());
        return increment;
    }
};

// Tests.

const testing = std.testing;

test "a window consumes down to zero, and one octet more is Exceeded" {
    var window = Window.init(10);
    try window.consume(4);
    try window.consume(6);
    try testing.expectEqual(0, window.available);
    try testing.expectEqual(0, window.sendable());
    try testing.expectError(error.Exceeded, window.consume(1));
    try testing.expectEqual(0, window.available);
}

test "a payload longer than the space available is Exceeded and the window does not move" {
    var window = Window.init(constants.window_initial);
    try testing.expectEqual(constants.window_initial, window.sendable());
    try testing.expectError(error.Exceeded, window.consume(constants.window_initial + 1));
    try testing.expectEqual(constants.window_initial, window.available);
}

test "a WINDOW_UPDATE may fill the window to exactly window_max" {
    var window = Window.init(1);
    try window.add(constants.window_max - 1);
    try testing.expectEqual(constants.window_max, window.available);
    try testing.expectEqual(constants.window_max, window.sendable());
}

test "a WINDOW_UPDATE that would exceed window_max is Overflow and the window does not move" {
    var window = Window.init(2);
    try testing.expectError(error.Overflow, window.add(constants.window_max - 1));
    try testing.expectEqual(2, window.available);
    var full = Window.init(constants.window_max);
    try testing.expectError(error.Overflow, full.add(1));
    try testing.expectEqual(constants.window_max, full.available);
}

test "RFC 9113 §6.9.2's example: 60 KB sent, then an initial window of 16 KB, leaves -44 KB" {
    var window = Window.init(constants.initial_window_size_initial);
    try window.consume(60 * 1024);
    try window.adjust(initial_window_delta(constants.initial_window_size_initial, 16 * 1024));
    try testing.expectEqual(-44 * 1024, window.available);
    try testing.expectEqual(0, window.sendable());
    try testing.expectError(error.Exceeded, window.consume(1));
    try testing.expectEqual(-44 * 1024, window.available);
}

test "a negative window takes an empty payload, which an empty DATA frame with END_STREAM carries" {
    var window = Window.init(0);
    try window.adjust(-1);
    try window.consume(0);
    try testing.expectEqual(-1, window.available);
}

test "WINDOW_UPDATE frames bring a negative window back above zero, and sending resumes" {
    var window = Window.init(100);
    try window.consume(100);
    try window.adjust(-50);
    try testing.expectEqual(-50, window.available);
    try testing.expectEqual(0, window.sendable());
    try window.add(50);
    try testing.expectEqual(0, window.available);
    try testing.expectEqual(0, window.sendable());
    try window.add(30);
    try testing.expectEqual(30, window.sendable());
    try window.consume(30);
    try testing.expectEqual(0, window.available);
}

test "the largest window fully sent, then an initial window of 0, reaches the floor -window_max" {
    var window = Window.init(constants.window_max);
    try window.consume(constants.window_max);
    try window.adjust(initial_window_delta(constants.window_max, 0));
    try testing.expectEqual(-@as(i64, constants.window_max), window.available);
    try testing.expect(window.in_range());
    try testing.expectEqual(0, window.sendable());
    try window.add(constants.window_max);
    try testing.expectEqual(0, window.available);
}

test "a settings change past window_max is Overflow and the window does not move" {
    var window = Window.init(constants.window_initial);
    try testing.expectError(error.Overflow, window.adjust(constants.window_max));
    try testing.expectEqual(constants.window_initial, window.available);
    try window.adjust(initial_window_delta(constants.window_initial, constants.window_max));
    try testing.expectEqual(constants.window_max, window.available);
    try testing.expectError(error.Overflow, window.adjust(1));
    try testing.expectEqual(constants.window_max, window.available);
}

test "the initial-window delta is the new value minus the old, in both directions" {
    try testing.expectEqual(-49_151, initial_window_delta(65_535, 16_384));
    try testing.expectEqual(49_151, initial_window_delta(16_384, 65_535));
    try testing.expectEqual(0, initial_window_delta(65_535, 65_535));
    const largest_drop = -@as(i64, constants.window_max);
    try testing.expectEqual(largest_drop, initial_window_delta(constants.window_max, 0));
}

test "a receiver charges each DATA payload, and one past the window is Exceeded" {
    var receiver = Receiver.init(constants.window_initial);
    try receiver.receive(constants.window_update_threshold);
    const rest = constants.window_initial - constants.window_update_threshold;
    try testing.expectEqual(rest, receiver.window.available);
    try receiver.receive(rest);
    try testing.expectError(error.Exceeded, receiver.receive(1));
    try testing.expectEqual(0, receiver.window.available);
    try receiver.receive(0);
    try testing.expectEqual(constants.window_initial, receiver.unreleased);
    try testing.expectEqual(0, receiver.released);
}

test "a receive window reduced under RFC 9113 §6.9.3 goes negative and comes back on release" {
    var receiver = Receiver.init(constants.window_initial);
    try receiver.receive(constants.window_initial);
    const reduced = constants.window_update_threshold;
    try receiver.window.adjust(initial_window_delta(constants.window_initial, reduced));
    const negative = @as(i64, reduced) - @as(i64, constants.window_initial);
    try testing.expectEqual(negative, receiver.window.available);
    try testing.expect(receiver.in_range());
    try receiver.receive(0);
    try testing.expectError(error.Exceeded, receiver.receive(1));
    try testing.expectEqual(negative, receiver.window.available);
    try testing.expectEqual(constants.window_initial, receiver.release(constants.window_initial));
    try testing.expectEqual(reduced, receiver.window.available);
    try testing.expectEqual(0, receiver.unreleased);
}

test "released credit below the threshold accumulates and sends no WINDOW_UPDATE" {
    var receiver = Receiver.init(constants.window_initial);
    try receiver.receive(constants.window_update_threshold);
    try testing.expectEqual(null, receiver.release(1));
    try testing.expectEqual(null, receiver.release(constants.window_update_threshold - 2));
    try testing.expectEqual(constants.window_update_threshold - 1, receiver.released);
    try testing.expectEqual(1, receiver.unreleased);
    const charged = constants.window_initial - constants.window_update_threshold;
    try testing.expectEqual(charged, receiver.window.available);
}

test "released credit at the threshold goes back into the window and out as a WINDOW_UPDATE" {
    var receiver = Receiver.init(constants.window_initial);
    try receiver.receive(constants.window_update_threshold);
    try testing.expectEqual(null, receiver.release(constants.window_update_threshold - 1));
    try testing.expectEqual(constants.window_update_threshold, receiver.release(1));
    try testing.expectEqual(0, receiver.released);
    try testing.expectEqual(0, receiver.unreleased);
    try testing.expectEqual(constants.window_initial, receiver.window.available);
}

test "after a WINDOW_UPDATE the next release starts a new count" {
    var receiver = Receiver.init(constants.window_initial);
    try receiver.receive(constants.window_initial);
    const threshold = constants.window_update_threshold;
    try testing.expectEqual(threshold, receiver.release(threshold));
    try testing.expectEqual(null, receiver.release(1));
    try testing.expectEqual(1, receiver.released);
    try testing.expectEqual(constants.window_update_threshold, receiver.window.available);
}

test "a release past the threshold returns all of the credit, not just the threshold" {
    var receiver = Receiver.init(constants.window_initial);
    try receiver.receive(constants.window_initial);
    try testing.expectEqual(constants.window_initial, receiver.release(constants.window_initial));
    try testing.expectEqual(0, receiver.released);
    try testing.expectEqual(constants.window_initial, receiver.window.available);
}

test "the smallest window the contract admits, once filled and freed, earns a WINDOW_UPDATE" {
    var receiver = Receiver.init(constants.window_update_threshold);
    try receiver.receive(constants.window_update_threshold);
    try testing.expectEqual(0, receiver.window.available);
    const threshold = constants.window_update_threshold;
    try testing.expectEqual(threshold, receiver.release(constants.window_update_threshold));
    try testing.expectEqual(constants.window_update_threshold, receiver.window.available);
}
