//! The deadlines a server connection keeps over TCP (decision 110, design §8 step 20b), and the
//! limits behind them. colibri reads no clock (design §4.2): each deadline starts at an instant the
//! caller passed, and the caller wakes at `Connection.deadline_ns` and calls `on_instant` then.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// Which deadline ended a connection, or an h2 stream.
pub const Deadline = enum {
    /// No whole request head arrived in time after the connection opened, the TLS handshake
    /// included.
    first_request,
    /// No request began in time after the last response ended.
    idle,
    /// A request head began and did not end in time.
    head,
    /// A request body arrived under the minimum rate: in h11 the body, and in h2 a stream's body
    /// or the bodies of the connection's streams together.
    body_rate,
    /// A request body did not end within the cap on it.
    body,
    /// The peer took the connection's octets, or in h2 opened a stream's window, under the
    /// minimum rate.
    send_rate,
    /// The h2 peer did not acknowledge colibri's SETTINGS within `settings_timeout_ns` (RFC 9113
    /// §6.5.3).
    settings,
    /// The requests the connection held when the caller shut it down did not finish in time.
    drain,
};

/// Each deadline's limit, or null to turn it off.
///
/// A body arrives a unit at a time: an h2 DATA frame, or a TLS record, of up to 16,384 octets.
/// spec/lean/Colibri/Server/RateMeter.lean proves the exact bound. A peer that sends whole units at
/// twice the minimum rate or more, and starts before the grace period ends, is never short in a
/// window exactly when twice the rate over one window is a whole unit or more. The bound is on the
/// rate times the window before the quota rounds it up: a quota rounded up to half a unit can fall
/// short, and one of half a unit and one octet cannot. The defaults' 10,240 octets are past it. A
/// caller that lowers the rate or the window further may cut an honest peer that sends whole units.
pub const Deadlines = struct {
    first_request_ns: ?u64 = constants.first_request_timeout_ns,
    idle_ns: ?u64 = constants.idle_timeout_ns,
    head_ns: ?u64 = constants.head_timeout_ns,
    /// The octets a second a request body brings at least, over each window.
    body_rate_min: ?u32 = constants.body_rate_min,
    /// The first window of a rate takes this more, and each window lasts this long.
    rate_grace_ns: u64 = constants.rate_grace_ns,
    rate_window_ns: u64 = constants.rate_window_ns,
    /// The longest a request body takes to arrive, from the end of its head.
    body_ns: ?u64 = constants.body_timeout_ns,
    /// The octets a second the peer takes of what the connection sends, at least, over each
    /// window, and in h2 of what a stream's window lets through.
    send_rate_min: ?u32 = constants.send_rate_min,
    /// How long a connection that has ended waits for its last octets to go out before it closes.
    linger_ns: ?u64 = constants.close_linger_ns,
    /// How long the requests a connection holds have after `shutdown` before it closes.
    drain_ns: ?u64 = constants.drain_timeout_ns,

    /// Refuses a limit of 0, which null says better, and a span past `timeout_ns_max`.
    pub fn validate(deadlines: Deadlines) error{DeadlineInvalid}!void {
        const spans = [_]?u64{
            deadlines.first_request_ns, deadlines.idle_ns,        deadlines.head_ns,
            deadlines.rate_grace_ns,    deadlines.rate_window_ns, deadlines.body_ns,
            deadlines.linger_ns,        deadlines.drain_ns,
        };
        for (spans) |span| {
            const limit = span orelse continue;
            // RFC 9112 §9.5 leaves a server's timeout to the server, and decision 110 bounds it:
            // null turns a deadline off, and a limit stays within a day.
            if (limit == 0 or limit > constants.timeout_ns_max) return error.DeadlineInvalid;
        }
        // RFC 9112 §9.5 leaves a server's timeouts to the server, and decision 110 bounds its rates
        // too: a rate of 0 would check nothing, which null says.
        if (deadlines.body_rate_min == 0 or deadlines.send_rate_min == 0) return error.DeadlineInvalid;
    }

    /// The octets a window must bring for the body rate, at least 1, or null with no rate.
    pub fn body_quota(deadlines: *const Deadlines) ?u64 {
        const rate = deadlines.body_rate_min orelse return null;
        return quota(rate, deadlines.rate_window_ns);
    }

    /// The octets the peer must take each window for the send rate, at least 1, or null.
    pub fn send_quota(deadlines: *const Deadlines) ?u64 {
        const rate = deadlines.send_rate_min orelse return null;
        return quota(rate, deadlines.rate_window_ns);
    }
};

/// The octets `rate` octets a second bring over `window_ns`, rounded up so a window always owes
/// one at least.
pub fn quota(rate: u32, window_ns: u64) u64 {
    assert(rate > 0 and window_ns > 0);
    const product = @as(u128, rate) * window_ns;
    const octets: u64 = @intCast((product + constants.nanoseconds_per_second - 1) / constants.nanoseconds_per_second);
    assert(octets > 0);
    return octets;
}

const testing = std.testing;

test "decision 110: the defaults are valid, 0 and a limit past a day are refused, and null is off" {
    try (Deadlines{}).validate();
    try (Deadlines{ .first_request_ns = null, .idle_ns = null, .head_ns = null, .body_rate_min = null, .body_ns = null }).validate();
    try (Deadlines{ .idle_ns = constants.timeout_ns_max }).validate();
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .head_ns = 0 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .first_request_ns = constants.timeout_ns_max + 1 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .body_rate_min = 0 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .rate_grace_ns = 0 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .rate_window_ns = constants.timeout_ns_max + 1 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .body_ns = 0 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .send_rate_min = 0 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .linger_ns = 0 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .drain_ns = 0 }).validate());
    try (Deadlines{ .send_rate_min = null, .linger_ns = null }).validate();
}

test "decision 110: a window owes the rate times its length, rounded up" {
    try testing.expectEqual(10_240, (Deadlines{}).body_quota().?);
    try testing.expectEqual(10_240, (Deadlines{}).send_quota().?);
    try testing.expectEqual(null, (Deadlines{ .body_rate_min = null }).body_quota());
    // Half an octet rounds up to one.
    try testing.expectEqual(1, quota(1, constants.nanoseconds_per_second / 2));
    try testing.expectEqual(3, quota(2, constants.nanoseconds_per_second + 1));
}

test "decision 77: every quota vector of spec/lean is this quota" {
    // spec/lean/Colibri/Server/RateMeter.lean proves its theorems about this rounding, and its
    // outputs over the rates and windows below are here: each side of an octet a window and of a
    // second, the defaults, and the largest rate over a day.
    var lines = std.mem.splitScalar(u8, @embedFile("rate_vectors.txt"), '\n');
    var count: usize = 0;
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "quota ")) continue;
        var fields = std.mem.tokenizeScalar(u8, line["quota ".len..], ' ');
        const rate = try std.fmt.parseUnsigned(u32, fields.next().?, 10);
        const window_ns = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        const octets = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        try testing.expectEqual(octets, quota(rate, window_ns));
        count += 1;
    }
    // Nine rates over ten windows.
    try testing.expectEqual(90, count);
}
