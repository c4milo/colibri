//! The plan of one seed of the content-coding check (design §8 step 17e, decision 101): the
//! protocol, the codings each side's configuration names in its order, and each exchange: its
//! method, whether its caller names Accept-Encoding itself, whether the server's caller marks the
//! response codable, its status, its content and the body memory the client gives it.
//!
//! `expect` says what decision 101 makes of an exchange: the coding the server applies, whether
//! the client removes it, and how the exchange ends.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const client = @import("client");

const Random = sim.Random;
const limits = sim.constants.content_coding;
const Coding = client.Coding;

pub const Protocol = enum { h11, h2 };

/// The Accept-Encoding the client's caller names itself, which the client sends as it is.
pub const OwnOffer = enum {
    /// None: the client offers its configuration's codings.
    none,
    /// `gzip`, which the client does not decode, since it made no offer of its own.
    gzip,
    /// `br`, a coding no colibri server applies.
    br,

    pub fn value(own: OwnOffer) ?[]const u8 {
        return switch (own) {
            .none => null,
            .gzip => "gzip",
            .br => "br",
        };
    }
};

pub const Exchange = struct {
    head: bool,
    own_offer: OwnOffer,
    codable: bool,
    status: u16,
    content_len: u32,
    /// Content DEFLATE shrinks: runs of text. Otherwise the tests' source, which it cannot.
    compressible: bool,
    /// The body memory is one octet shorter than the content.
    body_short: bool,
};

pub const Plan = struct {
    protocol: Protocol,
    server_codings: [coding_count]Coding,
    server_codings_len: u8,
    client_codings: [coding_count]Coding,
    client_codings_len: u8,
    exchanges: [limits.exchanges_max]Exchange,
    exchanges_len: u8,

    pub fn server_offers(plan: *const Plan) []const Coding {
        return plan.server_codings[0..plan.server_codings_len];
    }

    pub fn client_offers(plan: *const Plan) []const Coding {
        return plan.client_codings[0..plan.client_codings_len];
    }
};

/// The codings colibri codes.
const coding_count = @typeInfo(Coding).@"enum".fields.len;

pub const ok: u16 = 200;
pub const no_content: u16 = 204;
pub const partial_content: u16 = 206;

pub fn draw(random: *Random) Plan {
    var plan: Plan = undefined;
    plan.protocol = if (coin(random)) .h11 else .h2;
    plan.server_codings_len = draw_codings(random, &plan.server_codings);
    plan.client_codings_len = draw_codings(random, &plan.client_codings);
    plan.exchanges_len = @intCast(random.between(1, limits.exchanges_max));
    for (plan.exchanges[0..plan.exchanges_len]) |*exchange| exchange.* = draw_exchange(random);
    return plan;
}

/// One or both codings in a drawn order, or rarely none.
fn draw_codings(random: *Random, codings: *[coding_count]Coding) u8 {
    const first: Coding = if (coin(random)) .gzip else .deflate;
    codings.* = .{ first, if (first == .gzip) .deflate else .gzip };
    if (rare(random)) return 0;
    return @intCast(random.between(1, coding_count));
}

fn draw_exchange(random: *Random) Exchange {
    const own_offer: OwnOffer = if (rare(random)) (if (coin(random)) .gzip else .br) else .none;
    const status: u16 = if (rare(random)) (if (coin(random)) no_content else partial_content) else ok;
    return .{
        .head = rare(random),
        .own_offer = own_offer,
        .codable = random.below(limits.rare_one_in) != 0,
        .status = status,
        .content_len = @intCast(if (status == no_content) 0 else random.below(limits.content_len_max + 1)),
        .compressible = coin(random),
        .body_short = rare(random),
    };
}

fn rare(random: *Random) bool {
    return random.below(limits.rare_one_in) == 0;
}

/// One of two outcomes, each as likely.
fn coin(random: *Random) bool {
    return random.below(coin_sides) == 0;
}

const coin_sides: u64 = 2;

/// What decision 101 makes of one exchange.
pub const Expected = struct {
    /// The coding the server applies to the content, or null.
    coded: ?Coding,
    /// The client removes it, and reports it.
    decoded: bool,
    /// The response's content does not fit the body memory, which the check makes one short.
    too_large: bool,
};

/// Whether the plan's body memory for `exchange` is one octet short of its content: only for
/// content the client decodes or takes as it came, which fits a body sized to the content.
pub fn expect_short(exchange: *const Exchange) bool {
    return exchange.body_short and !exchange.head and exchange.content_len > 0 and exchange.own_offer == .none;
}

pub fn expect(plan: *const Plan, exchange: *const Exchange) Expected {
    const coded = applied(plan, exchange);
    // Decision 101: the client decodes a coding it offered, and makes no offer when its caller
    // names Accept-Encoding.
    const decoded = coded != null and exchange.own_offer == .none;
    return .{ .coded = coded, .decoded = decoded, .too_large = expect_short(exchange) };
}

/// The coding the server applies to the exchange's content (decision 101), or null.
fn applied(plan: *const Plan, exchange: *const Exchange) ?Coding {
    if (plan.server_codings_len == 0 or !exchange.codable) return null;
    // RFC 9110 §9.3.2, §15.3.5 and decision 101: no content to code, and a 206 is never coded.
    if (exchange.head or exchange.status != ok or exchange.content_len == 0) return null;
    return switch (exchange.own_offer) {
        .gzip => if (std.mem.indexOfScalar(Coding, plan.server_offers(), .gzip) != null) .gzip else null,
        .br => null,
        // RFC 9110 §12.5.3: the client weighs its first coding highest, so the server applies
        // the first of the client's codings it has.
        .none => for (plan.client_offers()) |offered| {
            if (std.mem.indexOfScalar(Coding, plan.server_offers(), offered) != null) break offered;
        } else null,
    };
}

const testing = std.testing;

test "decision 101: the server applies the client's first coding it has, and only to content" {
    var plan: Plan = .{
        .protocol = .h2,
        .server_codings = .{ .gzip, .deflate },
        .server_codings_len = 2,
        .client_codings = .{ .deflate, .gzip },
        .client_codings_len = 2,
        .exchanges = undefined,
        .exchanges_len = 1,
    };
    const get: Exchange = .{ .head = false, .own_offer = .none, .codable = true, .status = ok, .content_len = 10, .compressible = true, .body_short = false };
    try testing.expectEqual(Coding.deflate, expect(&plan, &get).coded.?);
    try testing.expect(expect(&plan, &get).decoded);
    var head = get;
    head.head = true;
    try testing.expectEqual(null, expect(&plan, &head).coded);
    var own = get;
    own.own_offer = .gzip;
    own.body_short = true;
    // The client passes gzip on, so the coded content goes into memory the plan does not shorten.
    try testing.expectEqual(Expected{ .coded = .gzip, .decoded = false, .too_large = false }, expect(&plan, &own));
    var short = get;
    short.body_short = true;
    try testing.expect(expect(&plan, &short).too_large);
    plan.server_codings_len = 0;
    try testing.expectEqual(null, expect(&plan, &get).coded);
}
