//! What one seed of the TCP trace run does (https://github.com/c4milo/colibri/issues/79): the
//! constants of `spec/tla/h2_connection` the seed runs under, whether it runs over TLS, the
//! requests its client makes, and the actions it draws once the client's first flight has gone.
//!
//! The first flight carries the client's preface, its SETTINGS and the requests the plan makes
//! before the first send, and the server reads it in one delivery. Over TLS the handshake runs
//! first, and the flight goes out with the client's Finished. A request the plan answers at once
//! gets its final head the moment the server reports it, inside that delivery: the case e3126a9
//! fixed, where the server answered a request read with the preface before it wrote its own
//! SETTINGS. cocuyo found it over TLS.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const Random = sim.Random;
const limits = sim.constants.tcp_trace;

/// A stream, the model's index from 1, and whether a write ends its message.
pub const Target = struct {
    stream: u32,
    end: bool,
};

/// One action the run draws. A server action on a stream whose request the server has not read,
/// or one the model's constants leave out, does nothing.
pub const Action = union(enum) {
    /// The client makes its next request.
    request,
    /// The client cancels the request on a stream, which h2 resets with CANCEL (RFC 9113 §6.4).
    client_cancel: u32,
    /// The server's caller answers a stream with an interim head, 103 (RFC 9110 §15.2.4).
    server_interim: u32,
    /// The server's caller answers with the final head, 200, ending the response when `end`.
    server_final: Target,
    /// The server's caller writes a piece of the response's content, the last one when `end`.
    server_data: Target,
    /// The server's caller ends the response with a trailer section.
    server_trailers: u32,
    /// The server's caller cancels the request on a stream, which h2 resets with CANCEL.
    server_cancel: u32,
    /// The server's caller shuts the connection down, which h2 says with GOAWAY (RFC 9113 §6.8).
    server_shutdown,
    /// Each side's caller hands its socket what the connection wrote.
    client_send,
    server_send,
    /// Each side reads every octet the other handed out.
    deliver_to_server,
    deliver_to_client,
};

/// Each kind of action: `Action`'s tag.
pub const Kind = std.meta.Tag(Action);

/// How often each kind of action is drawn, against the others. Sends and deliveries weigh most, so
/// frames do not pile up, and requests, cancels and the shutdown least.
const weights: std.EnumArray(Kind, u64) = .init(.{
    .request = weight_rare,
    .client_cancel = weight_rare,
    .server_interim = weight_common,
    .server_final = weight_common,
    .server_data = weight_common,
    .server_trailers = weight_rare,
    .server_cancel = weight_rare,
    .server_shutdown = weight_rare,
    .client_send = weight_delivery,
    .server_send = weight_delivery,
    .deliver_to_server = weight_delivery,
    .deliver_to_client = weight_delivery,
});
const weight_rare: u64 = 1;
const weight_common: u64 = 3;
const weight_delivery: u64 = 4;
const weights_total: u64 = total: {
    var sum: u64 = 0;
    for (weights.values) |weight| sum += weight;
    break :total sum;
};

/// One write in this many ends its message, one request in this many carries content when the
/// plan's `Content` allows any, and one in this many is answered at once.
const end_one_in: u64 = 2;
const request_content_one_in: u64 = 2;
const answer_at_once_one_in: u64 = 2;

pub const Plan = struct {
    /// The model's `N`, `Content`, `Interims`, `MaxGoaways` and `Resets`.
    streams: u32,
    content: u32,
    interims: u32,
    goaways: u32,
    resets: bool,
    /// Whether the connection runs over TLS, with h2 chosen by ALPN (RFC 9113 §3.2).
    tls: bool,
    /// Whether each request carries content, which goes out as one DATA frame.
    request_content: [limits.streams_max]bool,
    /// Whether the server's caller answers each request the moment the server reports it, with a
    /// final head that ends the response.
    answer_at_once: [limits.streams_max]bool,
    /// Requests the client makes before its first send: one at least.
    first_flight: u32,
    /// Actions the run draws after the first flight.
    actions: u32,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.streams = @intCast(random.between(1, limits.streams_max));
        plan.content = @intCast(random.below(limits.content_max + 1));
        plan.interims = @intCast(random.below(limits.interims_max + 1));
        plan.goaways = @intCast(random.below(limits.goaways_max + 1));
        plan.resets = random.below(limits.no_resets_one_in) != 0;
        plan.tls = random.below(limits.tls_one_in) == 0;
        for (&plan.request_content, &plan.answer_at_once) |*carries, *at_once| {
            carries.* = plan.content > 0 and random.below(request_content_one_in) == 0;
            at_once.* = random.below(answer_at_once_one_in) == 0;
        }
        plan.first_flight = @intCast(random.between(1, plan.streams));
        plan.actions = @intCast(random.between(limits.actions_min, limits.actions_max));
        assert(plan.streams >= 1 and plan.streams <= limits.streams_max);
        assert(plan.first_flight >= 1 and plan.first_flight <= plan.streams);
    }

    /// The next action, drawn from `random`.
    pub fn next_action(plan: *const Plan, random: *Random) Action {
        const stream: u32 = @intCast(random.between(1, plan.streams));
        const target: Target = .{ .stream = stream, .end = random.below(end_one_in) == 0 };
        var drawn = random.below(weights_total);
        for (std.enums.values(Kind)) |kind| {
            const weight = weights.get(kind);
            if (drawn < weight) return action_of(kind, target);
            drawn -= weight;
        }
        unreachable;
    }
};

fn action_of(kind: Kind, target: Target) Action {
    return switch (kind) {
        .request => .request,
        .client_cancel => .{ .client_cancel = target.stream },
        .server_interim => .{ .server_interim = target.stream },
        .server_final => .{ .server_final = target },
        .server_data => .{ .server_data = target },
        .server_trailers => .{ .server_trailers = target.stream },
        .server_cancel => .{ .server_cancel = target.stream },
        .server_shutdown => .server_shutdown,
        .client_send => .client_send,
        .server_send => .server_send,
        .deliver_to_server => .deliver_to_server,
        .deliver_to_client => .deliver_to_client,
    };
}

comptime {
    // Every kind of action can be drawn.
    for (weights.values) |weight| assert(weight > 0);
}

const testing = std.testing;

test "a plan stays inside the model's constants, its first flight carries a request, and every kind of action is drawn" {
    var drawn: std.EnumArray(Kind, bool) = .initFill(false);
    for (0..limits.actions_max) |seed| {
        var random = Random.init(seed);
        var plan: Plan = undefined;
        plan.draw(&random);
        try testing.expect(plan.content <= limits.content_max and plan.interims <= limits.interims_max);
        try testing.expect(plan.first_flight >= 1 and plan.first_flight <= plan.streams);
        for (plan.request_content) |carries| try testing.expect(!carries or plan.content > 0);
        drawn.set(std.meta.activeTag(plan.next_action(&random)), true);
    }
    for (drawn.values) |seen| try testing.expect(seen);
}
