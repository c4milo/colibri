//! What one seed of the QPACK check encodes (design §8 step 11): the peer's two settings, the
//! Huffman choice, and a list of field sections on a few request streams.
//!
//! Lines repeat on purpose. Names come from a pool that mixes static-table names with names the
//! static table lacks, and values from the static table's own values and a handful the seed draws,
//! so later sections can reference what earlier ones inserted. Value lengths reach
//! `qpack_check_value_len_max`, so small tables must evict.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const qpack = @import("qpack");

const Random = sim.Random;
const constants = sim.constants;
const Indexing = qpack.encoder.Indexing;

/// Names the lines use: some the static table holds, some it does not.
const names = [_][]const u8{
    ":method",    ":path", ":authority", "content-type", "cache-control",
    "user-agent", "x-a",   "x-b",        "x-c",          "cookie",
};

/// Values the static table holds, so some lines are whole static entries.
const static_values = [_][]const u8{ "GET", "/", "text/html; charset=utf-8", "no-cache", "" };

const capacities = constants.qpack_check_capacities;
const blocked_counts = constants.qpack_check_blocked_counts;

comptime {
    // `sim` cannot import `qpack`, so its lists end at `qpack`'s limits written out, and this
    // module, which imports both, holds them in step.
    assert(capacities[capacities.len - 1] == qpack.constants.dynamic_table_capacity_max);
    assert(blocked_counts[blocked_counts.len - 1] == qpack.constants.blocked_streams_max);
}

/// The octets a drawn value is made of.
const value_alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-";

pub const Line = struct {
    name: []const u8,
    value: []const u8,
    indexing: Indexing,
};

pub const Section = struct {
    stream_id: u64,
    lines: [constants.qpack_check_lines_max]Line,
    len: u32,
};

pub const Plan = struct {
    settings: qpack.decoder.Settings,
    huffman: qpack.encoder.HuffmanUse,
    sections: [constants.qpack_check_sections_max]Section,
    len: u32,
    /// The values the seed drew, which the lines point into.
    value_octets: [constants.qpack_check_values][constants.qpack_check_value_len_max]u8,
    value_lens: [constants.qpack_check_values]u32,

    /// Draws a plan into `plan`, which is too large for a stack frame.
    pub fn draw(plan: *Plan, random: *Random) void {
        plan.settings = .{
            .max_table_capacity = capacities[random.below(capacities.len)],
            .blocked_streams = blocked_counts[random.below(blocked_counts.len)],
        };
        plan.huffman = @enumFromInt(random.below(std.meta.fields(qpack.encoder.HuffmanUse).len));
        for (&plan.value_octets, &plan.value_lens) |*octets, *len| {
            len.* = @intCast(random.below(constants.qpack_check_value_len_max + 1));
            for (octets[0..len.*]) |*octet| octet.* = value_alphabet[random.below(value_alphabet.len)];
        }
        plan.len = @intCast(random.between(1, constants.qpack_check_sections_max));
        for (plan.sections[0..plan.len]) |*section| plan.draw_section(section, random);
        assert(plan.len > 0);
    }

    fn draw_section(plan: *const Plan, section: *Section, random: *Random) void {
        section.stream_id = random.below(constants.qpack_check_streams) * constants.qpack_check_stream_id_step;
        section.len = @intCast(random.between(1, constants.qpack_check_lines_max));
        for (section.lines[0..section.len]) |*line| {
            line.* = .{
                .name = names[random.below(names.len)],
                .value = plan.draw_value(random),
                .indexing = draw_indexing(random),
            };
        }
    }

    fn draw_value(plan: *const Plan, random: *Random) []const u8 {
        const choice = random.below(static_values.len + constants.qpack_check_values);
        if (choice < static_values.len) return static_values[choice];
        const index = choice - static_values.len;
        return plan.value_octets[index][0..plan.value_lens[index]];
    }

    pub fn lines(plan: *const Plan, index: u32) []const Line {
        const section = &plan.sections[index];
        return section.lines[0..section.len];
    }
};

fn draw_indexing(random: *Random) Indexing {
    if (random.below(constants.qpack_check_no_insert_one_in) == 0) return .no_insert;
    if (random.below(constants.qpack_check_never_indexed_one_in) == 0) return .never_indexed;
    return .may_insert;
}

const testing = std.testing;

/// The plan the tests draw, placed outside any stack frame. Test-only.
var test_plan: Plan = undefined;

test "a seed draws the same plan every time" {
    var first = Random.init(1);
    test_plan.draw(&first);
    const settings = test_plan.settings;
    const sections = test_plan.len;
    var again = Random.init(1);
    test_plan.draw(&again);
    try testing.expectEqual(settings, test_plan.settings);
    try testing.expectEqual(sections, test_plan.len);
    try testing.expectEqual(first.draws, again.draws);
    for (0..test_plan.len) |index| {
        try testing.expect(test_plan.sections[index].len > 0);
        try testing.expectEqual(0, test_plan.sections[index].stream_id % constants.qpack_check_stream_id_step);
    }
}
