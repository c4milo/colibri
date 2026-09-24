//! What one seed of the h3 check exchanges (design §8 step 12): each endpoint's QPACK settings and
//! grease value, and up to `h3_check_exchanges_max` requests with their responses, which the
//! client sends in rounds of `h3_check_round_len`.
//!
//! A message is its pseudo-header fields, up to `h3_check_lines_max` regular lines and some
//! content. Lines repeat across exchanges on purpose: names come from a pool that mixes
//! static-table names with names the static table lacks, and values from a few the seed draws, so
//! a table the peer allows is used. Some responses have an interim response before them, and some
//! messages trailers after their content. Content octets are a function of the exchange, the
//! direction and the offset, so the receiver checks each one without a copy of what was sent.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h3 = @import("h3");

const Random = sim.Random;
const constants = sim.constants;

/// Names the regular lines use: some the static table holds, some it does not.
const names = [_][]const u8{ "content-type", "cache-control", "user-agent", "accept", "x-a", "x-b", "cookie" };

/// The octets a drawn value is made of.
const value_alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-";

/// The status codes a final response draws from, and the interim one (RFC 9110 §15).
const statuses = [_][]const u8{ "200", "201", "204", "404", "500" };
pub const interim_status = "103";

pub const Line = struct {
    name: []const u8,
    value: []const u8,
};

/// One message's regular lines, content and trailers.
pub const Message = struct {
    lines: [constants.h3_check_lines_max]Line,
    len: u32,
    content_len: u32,
    trailers: bool,

    pub fn regular(message: *const Message) []const Line {
        return message.lines[0..message.len];
    }
};

pub const Exchange = struct {
    request: Message,
    response: Message,
    /// The final response's status, which is 204 only when the response has no content.
    status: []const u8,
    /// Whether a 103 response comes before the final one (RFC 9114 §4.1).
    interim: bool,
};

/// Which way a message travels, which content octets depend on.
pub const Direction = enum(u1) { request, response };

/// How large a seed's plan may be: the normal check's, or the long check's.
pub const Shape = struct {
    exchanges_max: u32,
    content_len_max: u32,

    pub const normal: Shape = .{ .exchanges_max = constants.h3_check_exchanges_max, .content_len_max = constants.h3_check_content_len_max };
    pub const long: Shape = .{ .exchanges_max = constants.h3_long_check_exchanges_max, .content_len_max = constants.h3_long_check_content_len_max };
};

pub const Plan = struct {
    client: h3.connection.Options,
    server: h3.connection.Options,
    exchanges: [constants.h3_long_check_exchanges_max]Exchange,
    len: u32,
    /// The values the seed drew, which the lines point into.
    value_octets: [constants.h3_check_values][constants.h3_check_value_len_max]u8,
    value_lens: [constants.h3_check_values]u32,

    /// Draws a plan into `plan`, which is too large for a stack frame.
    pub fn draw(plan: *Plan, random: *Random, shape: Shape) void {
        assert(shape.exchanges_max <= plan.exchanges.len);
        plan.client = .{ .role = .client, .qpack = draw_settings(random), .grease = random.next() };
        plan.server = .{ .role = .server, .qpack = draw_settings(random), .grease = random.next() };
        for (&plan.value_octets, &plan.value_lens) |*octets, *len| {
            len.* = @intCast(random.between(1, constants.h3_check_value_len_max));
            for (octets[0..len.*]) |*octet| octet.* = value_alphabet[random.below(value_alphabet.len)];
        }
        plan.len = @intCast(random.between(1, shape.exchanges_max));
        for (plan.exchanges[0..plan.len]) |*exchange| plan.draw_exchange(exchange, random, shape);
        assert(plan.len > 0);
    }

    fn draw_exchange(plan: *const Plan, exchange: *Exchange, random: *Random, shape: Shape) void {
        plan.draw_message(&exchange.request, random, shape);
        plan.draw_message(&exchange.response, random, shape);
        exchange.status = statuses[random.below(statuses.len)];
        // RFC 9110 §15.3.5: a 204 has no content.
        if (std.mem.eql(u8, exchange.status, "204")) {
            exchange.response.content_len = 0;
            exchange.response.trailers = false;
        }
        exchange.interim = random.below(constants.h3_check_interim_one_in) == 0;
    }

    fn draw_message(plan: *const Plan, message: *Message, random: *Random, shape: Shape) void {
        message.len = @intCast(random.below(constants.h3_check_lines_max + 1));
        for (message.lines[0..message.len]) |*line| {
            line.* = .{ .name = names[random.below(names.len)], .value = plan.draw_value(random) };
        }
        message.content_len = @intCast(random.below(shape.content_len_max + 1));
        message.trailers = random.below(constants.h3_check_trailers_one_in) == 0;
    }

    fn draw_value(plan: *const Plan, random: *Random) []const u8 {
        const index = random.below(constants.h3_check_values);
        return plan.value_octets[index][0..plan.value_lens[index]];
    }
};

fn draw_settings(random: *Random) h3.qpack.decoder.Settings {
    const capacities = constants.h3_check_capacities;
    const blocked = constants.h3_check_blocked_counts;
    return .{
        .max_table_capacity = capacities[random.below(capacities.len)],
        .blocked_streams = blocked[random.below(blocked.len)],
    };
}

/// How a content octet is chosen from its offset, exchange and direction, so an octet read at the
/// wrong offset or on the wrong stream shows.
const octet_stride: u64 = 7;
const octet_seed: u64 = 0x2b;
const exchange_stride: u64 = 2;

/// The content octet of exchange `index`'s message going `direction` at `offset`.
pub fn content_octet(index: u32, direction: Direction, offset: u64) u8 {
    return @truncate(offset *% octet_stride +% octet_seed +% index *% exchange_stride +% @intFromEnum(direction));
}

/// The trailer line every message with trailers carries.
pub const trailer_line: Line = .{ .name = "x-checksum", .value = "sim" };

const testing = std.testing;

/// The plan the tests draw, placed outside any stack frame. Test-only.
var test_plan: Plan = undefined;

test "a seed draws the same plan every time, and a 204 carries no content" {
    for (0..constants.check_seeds_default) |seed| {
        var first = Random.init(seed);
        test_plan.draw(&first, .normal);
        const exchanges = test_plan.len;
        var again = Random.init(seed);
        test_plan.draw(&again, .normal);
        try testing.expectEqual(exchanges, test_plan.len);
        try testing.expectEqual(first.draws, again.draws);
        for (test_plan.exchanges[0..test_plan.len]) |exchange| {
            if (std.mem.eql(u8, exchange.status, "204")) try testing.expectEqual(0, exchange.response.content_len);
        }
    }
}
