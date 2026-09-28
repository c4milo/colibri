//! One exchange of the test-only client, in h2 or h11: the request the command line asks for, and
//! the `client` module's exchange that carries it (design §8 step 17c). The client module copies
//! the response into the exchange's own memory, which `client_session.zig` places.
//!
//! The content is a pattern and not a file, so a run reads nothing from disk and two runs send the
//! same octets. A peer that echoes a request returns octets whose checksum `content_crc32` gives,
//! which is how a run tells an echo from a reordered or truncated one.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const constants = @import("../constants.zig");

const Crc32 = std.hash.Crc32;

/// One exchange as the caller asks for it.
pub const Plan = struct {
    /// The request method (RFC 9110 §9).
    method: []const u8,
    /// The `:path` in h2 (RFC 9113 §8.3.1), and the origin-form target in h11 (RFC 9112 §3.2.1).
    path: []const u8,
    /// Octets of request content. 0 sends none: in h2 the HEADERS frame carries END_STREAM
    /// (RFC 9113 §8.1).
    content_len: u32,
};

/// The field lines every request carries beside the ones `client` adds (RFC 9110 §10.1.5).
const request_fields = [_]client.Field{.{ .name = "user-agent", .value = constants.user_agent }};

/// One exchange: its plan, the module's exchange carrying it, and its id on the connection.
pub const Exchange = struct {
    plan: Plan,
    carried: client.Exchange,
    id: client.Id,
    /// Whether the exchange's `finished` event arrived.
    finished: bool,

    /// An exchange of `plan` whose response goes into `body`.
    pub fn init(plan: Plan, body: []u8) Exchange {
        assert(plan.method.len > 0 and plan.path.len > 0);
        assert(plan.content_len <= constants.request_content_len_max);
        return .{
            .plan = plan,
            .carried = .{
                .method = plan.method,
                .path = plan.path,
                .fields = &request_fields,
                .content = content[0..plan.content_len],
                .body = body,
            },
            .id = 0,
            .finished = false,
        };
    }

    /// Whether the exchange ended the way a working peer ends one: a final response read whole,
    /// with the request content sent whole.
    pub fn succeeded(exchange: *const Exchange) bool {
        if (!exchange.finished or exchange.carried.outcome != .response) return false;
        return exchange.carried.content_sent == exchange.plan.content_len;
    }

    /// The checksum of the content sent, which a peer that echoes it returns.
    pub fn sent_crc32(exchange: *const Exchange) u32 {
        return Crc32.hash(content[0..exchange.carried.content_sent]);
    }

    /// The checksum of the response's content.
    pub fn received_crc32(exchange: *const Exchange) u32 {
        return Crc32.hash(exchange.carried.body[0..exchange.carried.body_len]);
    }
};

/// The request content: octet `i` is `i % request_content_period`, as long as the longest content
/// a plan may ask for. Every exchange's content is a prefix of it. `fill_content` writes it once,
/// before the first connection opens.
var content: [constants.request_content_len_max]u8 = undefined;

pub fn fill_content() void {
    for (&content, 0..) |*octet, index| octet.* = @intCast(index % constants.request_content_period);
}

/// The checksum of the first `len` octets of the request content, which is what a peer that echoes
/// a request returns.
pub fn content_crc32(len: u32) u32 {
    assert(len <= constants.request_content_len_max);
    return Crc32.hash(content[0..len]);
}

const testing = std.testing;

test "the content is its index modulo the period, and its checksum is a prefix's" {
    fill_content();
    const period = constants.request_content_period;
    for ([_]u32{ 0, 1, period - 1, period, period + 7, 3 * period + 250 }) |index| {
        try testing.expectEqual(index % period, content[index]);
    }
    try testing.expectEqual(Crc32.hash(content[0..1000]), content_crc32(1000));
}
