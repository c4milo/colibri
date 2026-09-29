//! One coded response (decision 101, design §8 step 17e): the slot of the encoder pool it holds
//! until its last coded octet is written, or for h3 acknowledged, and how far its content has come.
//! The encoder writes into the slot's ring after the octets held there. h11 and h2 copy the octets
//! out and free them at once (`code` and `finish`), and h3 frames each octet run the encoder wrote
//! and frees it once the peer acknowledges it (`step`).
const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const http = @import("http");
const event = @import("../event.zig");
const coding_pool = @import("coding_pool.zig");
const coding_ring = @import("coding_ring.zig");
const coding_rules = @import("coding_rules.zig");
const coding_fields = @import("coding_fields.zig");

const Encoders = coding_pool.Encoders;

/// The head a final response goes out with, and the slot its coded content holds, if any.
pub const Head = struct {
    fields: []const http.field.Field,
    slot: ?coding_pool.Index,
};

/// Plans the final `response` to a request that asked `asked`: its field lines, rewritten into
/// `into`, and an encoder taken for its content when it is coded. With every encoder taken, the
/// content goes uncoded (decision 101). The caller gives the slot back if the head fails to go out.
pub fn plan_head(encoders: Encoders, asked: coding_rules.Asked, response: event.Response, into: *coding_fields.Rewritten) coding_fields.Error!Head {
    var plan = coding_rules.plan(asked, response);
    const slot = if (plan.encodes) encoders.take(plan.coding.?) else null;
    if (plan.encodes and slot == null) plan = .{ .vary = plan.vary };
    errdefer if (slot) |index| encoders.give_back(index);
    const fields = try coding_fields.rewrite(response.fields, plan, into);
    return .{ .fields = fields, .slot = slot };
}

pub const Coded = struct {
    /// The slot of the pool the response holds.
    slot: coding_pool.Index,
    ring: coding_ring.Ring = .{},
    /// The caller's content ended, so the encoder takes `finish` and no input from here on (stdx's
    /// decision 11).
    finishing: bool = false,
    /// A trailer section ends the content, so the response's end is the trailer section's to
    /// write.
    trailers: bool = false,
    /// The encoder wrote its last octet.
    finished: bool = false,

    /// Codes `input` into the ring's room, or once `finishing` ends the coding, and returns what
    /// the encoder did and the octets it wrote, now the ring's newest.
    pub fn step(coded: *Coded, encoders: Encoders, input: []const u8) Stepped {
        assert(!coded.finished);
        assert(!coded.finishing or input.len == 0);
        const room = coded.ring.room(encoders.ring(coded.slot));
        assert(room.len > 0);
        const flush: codec.Flush = if (coded.finishing) .finish else .none;
        const progress = encoders.encode(coded.slot, input, room, flush);
        coded.ring.wrote(progress.written);
        if (progress.status == .done) coded.finished = true;
        return .{ .consumed = progress.consumed, .written = room[0..progress.written] };
    }

    /// Codes as much of `input` as the ring has room for, and returns the octets taken.
    pub fn code(coded: *Coded, encoders: Encoders, input: []const u8) usize {
        assert(!coded.finishing);
        var consumed: usize = 0;
        // The room ends at the ring's end or at its oldest octet held, so two steps fill it.
        for (0..steps_max) |_| {
            if (consumed == input.len or coded.room_len(encoders) == 0) break;
            consumed += coded.step(encoders, input[consumed..]).consumed;
        }
        return consumed;
    }

    /// Ends the coding as far as the ring's room allows.
    pub fn finish(coded: *Coded, encoders: Encoders) void {
        assert(coded.finishing);
        for (0..steps_max) |_| {
            if (coded.finished or coded.room_len(encoders) == 0) break;
            _ = coded.step(encoders, &.{});
        }
    }

    /// Octets of room the ring has after the octets held, up to its end.
    pub fn room_len(coded: *const Coded, encoders: Encoders) usize {
        return coded.ring.room(encoders.ring(coded.slot)).len;
    }
};

/// What one `step` did.
pub const Stepped = struct {
    consumed: usize,
    written: []const u8,
};

/// The steps that fill a ring's room: to the ring's end, then from its start.
pub const steps_max: usize = 2;

const testing = std.testing;
const gzip = @import("gzip");
const constants = @import("../constants.zig");

/// A pool, and a decoder that reads its output back, outside any stack frame. Test-only.
const TestPool = coding_pool.EncoderPool(1, 1);
threadlocal var test_pool: TestPool align(@alignOf(TestPool)) = undefined;
threadlocal var test_decoder: gzip.Decoder align(@alignOf(gzip.Decoder)) = undefined;
threadlocal var test_coded_octets: [test_coded_len]u8 = undefined;
threadlocal var test_decoded: [test_input_len]u8 = undefined;
threadlocal var test_input: [test_input_len]u8 = undefined;
/// Three rings of input, which deflate cannot shrink, so the coded octets pass the ring's end.
const test_input_len: usize = test_input_rings * constants.encoder_ring_len;
const test_coded_len: usize = (test_input_rings + 1) * constants.encoder_ring_len;
const test_input_rings: usize = 3;

/// Fills the test input with SplitMix64's output, which deflate cannot shrink.
fn test_fill() void {
    var state: u64 = test_seed;
    for (&test_input) |*octet| {
        state +%= test_increment;
        var mixed = state;
        mixed = (mixed ^ (mixed >> test_shift_first)) *% test_multiplier_first;
        mixed = (mixed ^ (mixed >> test_shift_second)) *% test_multiplier_second;
        octet.* = @truncate(mixed ^ (mixed >> test_shift_third));
    }
}

const test_seed: u64 = 0x636f_6c69_6272_6921;
const test_increment: u64 = 0x9e37_79b9_7f4a_7c15;
const test_multiplier_first: u64 = 0xbf58_476d_1ce4_e5b9;
const test_multiplier_second: u64 = 0x94d0_49bb_1331_11eb;
const test_shift_first: u6 = 30;
const test_shift_second: u6 = 27;
const test_shift_third: u6 = 31;

/// Copies every octet the ring holds to the test's coded octets, as h11 and h2 do.
fn copy_held(coded: *Coded, encoders: Encoders, copied: *usize) void {
    for (0..steps_max) |_| {
        const held = coded.ring.oldest(encoders.ring(coded.slot));
        @memcpy(test_coded_octets[copied.*..][0..held.len], held);
        copied.* += held.len;
        coded.ring.free(held.len);
    }
}

test "decision 101: content past the ring's room waits for the ring to empty, and decodes whole" {
    test_fill();
    test_pool.reset(.none());
    const encoders = test_pool.encoders();
    var coded: Coded = .{ .slot = encoders.take(.gzip).? };
    var taken: usize = 0;
    var copied: usize = 0;
    // Bounded: each pass empties the ring, so the encoder takes input or finishes.
    for (0..test_input_len) |_| {
        taken += coded.code(encoders, test_input[taken..]);
        if (taken == test_input_len) break;
        // A full ring takes no more until its octets leave.
        try testing.expectEqual(0, coded.code(encoders, test_input[taken..]));
        copy_held(&coded, encoders, &copied);
    }
    coded.finishing = true;
    for (0..test_input_len) |_| {
        coded.finish(encoders);
        copy_held(&coded, encoders, &copied);
        if (coded.finished) break;
    }
    try testing.expect(coded.finished and coded.ring.held() == 0);
    try testing.expect(coded.ring.written > constants.encoder_ring_len);
    gzip.init(&test_decoder, .none());
    const decoded = try gzip.decode_all(&test_decoder, test_coded_octets[0..copied], &test_decoded);
    try testing.expectEqualSlices(u8, &test_input, test_decoded[0..decoded.written]);
    encoders.give_back(coded.slot);
}
