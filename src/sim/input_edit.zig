//! The edits the input checks make to octets one of colibri's writers produced, so a reader gets
//! hostile input that reaches past its first octet. They stand where the fuzzer would: Zig 0.16.0
//! cannot build its fuzz mode (design §8 step 1), and `core.fuzz.sweep` covers only inputs of two
//! octets. `qpack_input_check.zig` and `quic_input_check.zig` share them.
const std = @import("std");
const assert = std.debug.assert;
const Random = @import("random.zig").Random;

/// The edits: an octet changed, inserted or removed, the end cut off at the drawn offset, or an
/// octet moved up or down by one. The last is what takes a value at a bound one past it.
pub const Edit = enum { change, insert, remove, cut, nudge };

/// The two ways a nudge moves an octet: up by one or down by one.
const nudge_directions = 2;

/// Copies `base` into `input`, makes up to `edits_max` edits drawn from `random`, and returns the
/// edited octets. An insert into a full `input` and a change or removal past the end do nothing.
pub fn edit(random: *Random, input: []u8, base: []const u8, edits_max: u64) []const u8 {
    assert(input.len > 0);
    var len: usize = @min(base.len, input.len);
    @memcpy(input[0..len], base[0..len]);
    const edits = random.below(edits_max + 1);
    for (0..edits) |_| {
        const at = random.below(len + 1);
        const kind: Edit = @enumFromInt(random.below(std.meta.fields(Edit).len));
        len = apply(random, input, len, at, kind);
    }
    assert(len <= input.len);
    return input[0..len];
}

/// Makes one edit at `at` to the first `len` octets of `input`, and returns their new length.
fn apply(random: *Random, input: []u8, len: usize, at: usize, kind: Edit) usize {
    assert(at <= len and len <= input.len);
    switch (kind) {
        .change => if (at < len) {
            input[at] = @truncate(random.next());
        },
        .insert => if (len < input.len) {
            std.mem.copyBackwards(u8, input[at + 1 .. len + 1], input[at..len]);
            input[at] = @truncate(random.next());
            return len + 1;
        },
        .remove => if (at < len) {
            std.mem.copyForwards(u8, input[at .. len - 1], input[at + 1 .. len]);
            return len - 1;
        },
        .cut => return at,
        .nudge => if (at < len) nudge(random, &input[at]),
    }
    return len;
}

/// Moves one octet up or down by one, wrapping at either end.
fn nudge(random: *Random, octet: *u8) void {
    if (random.below(nudge_directions) == 0) octet.* +%= 1 else octet.* -%= 1;
}

const testing = std.testing;

/// The buffer the test edits into, and how many seeds it draws edits from. Test-only.
const test_input_len = 8;
const test_seeds = 256;

test "no edit leaves the octets as they were, and every edit stays inside the buffer" {
    var input: [test_input_len]u8 = @splat(0);
    var random = Random.init(1);
    try testing.expectEqualSlices(u8, "abc", edit(&random, &input, "abc", 0));
    for (0..test_seeds) |seed| {
        random = Random.init(seed);
        const edited = edit(&random, &input, "abcdefgh", test_input_len);
        try testing.expect(edited.len <= input.len);
    }
}
