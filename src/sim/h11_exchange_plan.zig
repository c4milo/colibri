//! One seed's exchanges for the h11 connection check (design §8 step 15b): the requests a colibri
//! client sends and the responses a colibri server answers them with, in order.
//!
//! A request carries no body, a fixed one or a chunked one; a response carries a fixed or chunked
//! body, none for HEAD, 204 and 304 (RFC 9112 §6.3 rule 1), or, as the last response, a body that
//! runs until the server closes (rule 8). One seed in `h11_exchange_close_one_in` ends the
//! connection early: a response carries `Connection: close`, and the requests after it go
//! unanswered (RFC 9112 §9.6). Otherwise the last request may carry the close itself. The server
//! holds each request for a few steps before it answers, while the requests pipelined behind it
//! arrive (decision 92).
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const sim = @import("sim");

const http = h11.http;
const Random = sim.Random;
const constants = sim.constants;
const Code = http.status.Code;

pub const BodyKind = enum { none, fixed, chunked, close_delimited };

pub const Exchange = struct {
    method: []const u8,
    target: []const u8,
    request_body: BodyKind,
    request_len: u32,
    status: u16,
    response_body: BodyKind,
    response_len: u32,
    /// The request carries `Connection: close` (RFC 9112 §9.6).
    request_close: bool,
    /// The response carries `Connection: close`, or runs until the close.
    response_close: bool,
    /// The steps the server holds the request, read whole, before it answers.
    response_delay: u32,
};

const methods = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS" };
const targets = [_][]const u8{ "/", "/a", "/b?c=d" };
const statuses = [_]u16{
    @intFromEnum(Code.ok),
    @intFromEnum(Code.created),
    @intFromEnum(Code.no_content),
    @intFromEnum(Code.not_modified),
    @intFromEnum(Code.not_found),
    @intFromEnum(Code.internal_server_error),
};

pub const Plan = struct {
    count: u32,
    exchanges: [constants.h11_exchange_count_max]Exchange,
    /// Each exchange's request and response body octets.
    request_octets: [constants.h11_exchange_count_max][constants.h11_exchange_body_len_max]u8,
    response_octets: [constants.h11_exchange_count_max][constants.h11_exchange_body_len_max]u8,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.count = @intCast(random.between(1, constants.h11_exchange_count_max));
        const early_close = random.below(constants.h11_exchange_close_one_in) == 0;
        const closing: u32 = if (early_close) @intCast(random.below(plan.count)) else plan.count;
        for (0..plan.count) |index| {
            plan.exchanges[index] = plan.draw_exchange(random, @intCast(index), closing);
        }
        const last = &plan.exchanges[plan.count - 1];
        // RFC 9112 §9.6: without an early close, the last request may carry the close itself.
        if (!early_close and random.below(constants.h11_exchange_last_close_one_in) == 0) last.request_close = true;
    }

    fn draw_exchange(plan: *Plan, random: *Random, index: u32, closing: u32) Exchange {
        const method = methods[random.below(methods.len)];
        const has_request_body = std.mem.eql(u8, method, "POST") or std.mem.eql(u8, method, "PUT");
        var exchange: Exchange = .{
            .method = method,
            .target = targets[random.below(targets.len)],
            .request_body = if (has_request_body) draw_kind(random) else .none,
            .request_len = 0,
            .status = statuses[random.below(statuses.len)],
            .response_body = draw_kind(random),
            .response_len = 0,
            .request_close = false,
            .response_close = index == closing,
            .response_delay = @intCast(random.below(constants.h11_exchange_response_delay_max + 1)),
        };
        if (exchange.request_body != .none) exchange.request_len = plan.fill(random, &plan.request_octets[index]);
        exchange.response_len = plan.fill(random, &plan.response_octets[index]);
        // RFC 9112 §6.3 rule 8: a body that runs until the close ends the connection, so only the
        // response that closes it may carry one.
        const last = index == closing or index + 1 == plan.count;
        // A HEAD, 204 or 304 response has no body to run until the close (RFC 9112 §6.3 rule 1).
        if (last and response_has_body(method, exchange.status) and random.below(constants.h11_exchange_last_close_one_in) == 0) {
            exchange.response_body = .close_delimited;
            exchange.response_close = true;
        }
        return exchange;
    }

    fn fill(plan: *const Plan, random: *Random, octets: []u8) u32 {
        _ = plan;
        const len = random.between(1, octets.len);
        for (octets[0..len]) |*octet| octet.* = @truncate(random.next());
        return @intCast(len);
    }

    /// The exchanges the server answers: through the one that closes the connection.
    pub fn answered(plan: *const Plan) u32 {
        for (plan.exchanges[0..plan.count], 0..) |exchange, index| {
            if (exchange.response_close or exchange.request_close) return @intCast(index + 1);
        }
        return plan.count;
    }
};

fn draw_kind(random: *Random) BodyKind {
    const kinds = [_]BodyKind{ .fixed, .chunked };
    return kinds[random.below(kinds.len)];
}

/// Whether a response to `method` with `status` carries a body (RFC 9112 §6.3 rule 1).
pub fn response_has_body(method: []const u8, status: u16) bool {
    if (std.mem.eql(u8, method, "HEAD")) return false;
    return status != @intFromEnum(Code.no_content) and status != @intFromEnum(Code.not_modified);
}
