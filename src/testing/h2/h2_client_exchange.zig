//! One exchange of the test-only h2 client: the request the caller asks for, what has happened
//! on its stream, and the request content it sends. Split off `h2_client_session.zig` for length.
//!
//! The content is a pattern and not a file, so a run reads nothing from disk and two runs send
//! the same octets. A peer that echoes a request returns octets whose checksum `content_crc32`
//! gives, which is how a run tells an echo from a reordered or truncated one.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const constants = @import("../constants.zig");

const Crc32 = std.hash.Crc32;

/// One exchange as the caller asks for it.
pub const Plan = struct {
    /// The request method (RFC 9110 §9).
    method: []const u8,
    /// The `:path` (RFC 9113 §8.3.1).
    path: []const u8,
    /// Octets of request content. 0 sends none, and the HEADERS frame carries END_STREAM (§8.1).
    content_len: u32,
};

/// How an exchange stands.
pub const Outcome = enum {
    /// The response has not ended.
    pending,
    /// The peer ended the stream after a final response (RFC 9113 §8.1).
    ended,
    /// The peer ended the stream with RST_STREAM, or colibri did (§6.4, §5.4.2).
    reset,
    /// The peer's GOAWAY left the stream unprocessed, or arrived before it opened (§6.8).
    abandoned,
    /// colibri refused to send the request: the plan names one §8.3.1 or §8.2 forbids.
    invalid,
};

/// One exchange: its plan, and what has happened on its stream.
pub const Exchange = struct {
    plan: Plan,
    /// The stream it opened, or 0 before it opened one (RFC 9113 §5.1.1).
    stream_id: u32,
    /// Octets of request content sent, and the checksum of them.
    content_sent: u32,
    sent_crc32: Crc32,
    /// Interim responses read before the final one (RFC 9110 §15.2).
    interim_count: u32,
    /// The final response's status code, or 0 before one arrived (RFC 9113 §8.3.2).
    status: u16,
    /// Octets of response content read, and the checksum of them.
    content_received: u64,
    received_crc32: Crc32,
    outcome: Outcome,
    /// The code of the RST_STREAM that ended the stream, when one did (RFC 9113 §7).
    error_code: u32,

    /// An exchange that has sent nothing and read nothing.
    pub fn init(plan: Plan) Exchange {
        assert(plan.method.len > 0 and plan.path.len > 0);
        assert(plan.content_len <= constants.request_content_len_max);
        return .{
            .plan = plan,
            .stream_id = 0,
            .content_sent = 0,
            .sent_crc32 = Crc32.init(),
            .interim_count = 0,
            .status = 0,
            .content_received = 0,
            .received_crc32 = Crc32.init(),
            .outcome = .pending,
            .error_code = h2.constants.error_no_error,
        };
    }
};

/// The request content: octet `i` is `i % request_content_period`, for several periods.
const content_pattern: [constants.request_content_pattern_len]u8 = blk: {
    @setEvalBranchQuota(constants.request_content_pattern_branches);
    var pattern: [constants.request_content_pattern_len]u8 = undefined;
    for (&pattern, 0..) |*octet, index| octet.* = @intCast(index % constants.request_content_period);
    break :blk pattern;
};

/// The request content from octet `offset` on: at most `left` octets, and at least one frame's
/// worth when that many are left, because the pattern holds more than a period past any start.
pub fn content_from(offset: u32, left: u32) []const u8 {
    assert(left > 0 and offset <= constants.request_content_len_max);
    const start = offset % constants.request_content_period;
    return content_pattern[start..][0..@min(left, content_pattern.len - start)];
}

/// The checksum of the first `len` octets of the request content, which is what a peer that echoes
/// a request returns.
pub fn content_crc32(len: u32) u32 {
    assert(len <= constants.request_content_len_max);
    var crc = Crc32.init();
    var done: u32 = 0;
    for (0..len / constants.request_content_pattern_len + 1) |_| {
        const take = @min(len - done, constants.request_content_pattern_len);
        crc.update(content_pattern[0..take]);
        done += take;
    }
    assert(done == len);
    return crc.final();
}

const testing = std.testing;

test "the content is its index modulo the period, wherever a slice of it starts" {
    const period = constants.request_content_period;
    for ([_]u32{ 0, 1, period - 1, period, period + 7, 3 * period + 250 }) |offset| {
        const slice = content_from(offset, period);
        try testing.expectEqual(period, slice.len);
        for (slice, 0..) |octet, index| {
            try testing.expectEqual((offset + index) % period, octet);
        }
    }
    // A short tail is cut to what is left.
    try testing.expectEqual(3, content_from(period, 3).len);
}

test "the checksum of the content is the checksum of the slices a session sends" {
    for ([_]u32{ 0, 1, 250, 251, 65_535, 100_000 }) |len| {
        var crc = Crc32.init();
        var sent: u32 = 0;
        // Slices of an awkward length, which is what a window leaves a session with.
        for (0..len + 1) |_| {
            if (sent == len) break;
            const slice = content_from(sent, @min(len - sent, 1_000));
            crc.update(slice);
            sent += @intCast(slice.len);
        }
        try testing.expectEqual(len, sent);
        try testing.expectEqual(crc.final(), content_crc32(len));
    }
}
