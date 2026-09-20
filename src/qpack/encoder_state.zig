//! What an encoder must remember about a decoder that has not caught up: RFC 9204 §2.1.1's
//! outstanding references, §2.1.2's blocked streams and §2.1.4's Known Received Count. Part of
//! design §8 step 11.
//!
//! None of this exists in HPACK, and [decision 12](../../docs/decisions.md) records why: RFC
//! 9204 §2.2 puts the table mutations on a stream of their own, so at any instant the decoder's
//! dynamic table is somewhere behind the encoder's and the encoder does not know exactly where.
//! Three numbers bound the gap.
//!
//! **The Known Received Count** (§2.1.4) is how many insertions the decoder has acknowledged. An
//! entry at or below it can be referenced with no risk of blocking anything.
//!
//! **A blocked stream** (§2.1.2) is one whose field section references an entry the decoder has
//! not received. An encoder MUST hold the number that *could* block to the peer's
//! `SETTINGS_QPACK_BLOCKED_STREAMS` at all times, and a decoder that meets more than it promised
//! MUST close the connection. So the limit is checked before a section is sent, not after.
//!
//! **An outstanding section** (§2.1.1) is one the decoder has not acknowledged, whose references
//! keep entries from being evicted. Sections on one stream are acknowledged oldest first
//! (§2.2.2.1), which is why they are held in arrival order per stream.
//!
//! It reads no clock and holds no octets: every number here is the caller's own bookkeeping.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const Error = error{
    /// RFC 9204 §6's QPACK_DECODER_STREAM_ERROR: the encoder could not interpret an instruction
    /// the decoder sent. §4.4.1 and §4.4.3 name the two that produce it.
    DecoderStreamError,
    /// colibri's own bound reached: more field sections with dynamic references are outstanding
    /// than `outstanding_sections_max`. Nothing is recorded, and the caller sends a section that
    /// references no dynamic entry instead.
    TooManyOutstanding,
};

/// One field section sent and not yet acknowledged (RFC 9204 §2.1.1).
const Outstanding = struct {
    stream_id: u64,
    /// §4.5.1: what the decoder's insert count must reach before it can decode the section.
    required_insert_count: u64,
};

pub const EncoderState = struct {
    /// RFC 9204 §2.1.4's Known Received Count.
    known_received: u64,
    /// §2.1.2's `SETTINGS_QPACK_BLOCKED_STREAMS`, which the peer advertised.
    blocked_streams_max: u64,
    /// The sections sent and not acknowledged, oldest first. One flat list rather than a list
    /// per stream: §2.2.2.1 acknowledges the earliest on a given stream, which a scan finds, and
    /// a table per stream would cost a bound per stream.
    outstanding: [constants.outstanding_sections_max]Outstanding,
    len: usize,

    pub fn init(state: *EncoderState, blocked_streams_max: u64) void {
        state.known_received = 0;
        state.blocked_streams_max = blocked_streams_max;
        state.len = 0;
    }

    /// How many distinct streams hold a section the decoder cannot yet decode (RFC 9204 §2.1.2).
    pub fn blocked_count(state: *const EncoderState) u64 {
        var count: u64 = 0;
        // Bounded by `outstanding_sections_max`, which is a named limit.
        for (state.outstanding[0..state.len], 0..) |held, index| {
            if (held.required_insert_count <= state.known_received) continue;
            if (state.has_blocked_before(index, held.stream_id)) continue;
            count += 1;
        }
        return count;
    }

    /// Whether a section needing `required_insert_count` may be sent on `stream_id` without
    /// passing §2.1.2's limit. An encoder MUST hold the number that could block at all times, so
    /// this is asked before the section goes out and not after.
    pub fn may_send(state: *const EncoderState, stream_id: u64, required_insert_count: u64) bool {
        // A section that references no entry the decoder lacks blocks nothing, whatever the
        // limit is: §2.1.2 counts streams that could become blocked.
        if (required_insert_count <= state.known_received) return true;
        // A stream already counted does not count twice.
        if (state.is_blocked(stream_id)) return state.blocked_count() <= state.blocked_streams_max;
        return state.blocked_count() + 1 <= state.blocked_streams_max;
    }

    /// Records a field section that references the dynamic table (RFC 9204 §2.1.1). A section
    /// with a Required Insert Count of zero references nothing and is not recorded, which is
    /// also why §2.2.2.1 has the decoder acknowledge only the ones that do.
    pub fn on_section_sent(state: *EncoderState, stream_id: u64, required_insert_count: u64) Error!void {
        if (required_insert_count == 0) return;
        if (state.len == constants.outstanding_sections_max) return Error.TooManyOutstanding;
        state.outstanding[state.len] = .{
            .stream_id = stream_id,
            .required_insert_count = required_insert_count,
        };
        state.len += 1;
    }

    /// RFC 9204 §4.4.1's Section Acknowledgment, which §2.2.2.1 says acknowledges the earliest
    /// unacknowledged section on that stream.
    pub fn on_section_acknowledgment(state: *EncoderState, stream_id: u64) Error!void {
        const at = state.earliest_of(stream_id) orelse {
            // §4.4.1: an acknowledgment for a stream on which every section with a non-zero
            // Required Insert Count has already been acknowledged MUST be a connection error of
            // QPACK_DECODER_STREAM_ERROR.
            return Error.DecoderStreamError;
        };
        // §2.1.4: an acknowledgment implies the decoder received all the state the section
        // needed, so the Known Received Count rises to its Required Insert Count.
        state.known_received = @max(state.known_received, state.outstanding[at].required_insert_count);
        state.remove(at);
    }

    /// RFC 9204 §4.4.2's Stream Cancellation: every reference on that stream is gone. It says
    /// nothing about the Known Received Count, because a cancelled stream's section was never
    /// decoded and acknowledges nothing.
    pub fn on_stream_cancellation(state: *EncoderState, stream_id: u64) void {
        var at: usize = 0;
        // Bounded by `outstanding_sections_max`, which is a named limit.
        while (at < state.len) {
            if (state.outstanding[at].stream_id == stream_id) {
                state.remove(at);
                continue;
            }
            at += 1;
        }
    }

    /// RFC 9204 §4.4.3's Insert Count Increment. `inserted` is how many entries this encoder has
    /// inserted, which bounds what the decoder can have received.
    pub fn on_insert_count_increment(state: *EncoderState, increment: u64, inserted: u64) Error!void {
        // §4.4.3: an Increment of zero, or one that takes the Known Received Count beyond what
        // the encoder has sent, MUST be a connection error of QPACK_DECODER_STREAM_ERROR.
        if (increment == 0) return Error.DecoderStreamError;
        const raised = state.known_received +| increment;
        if (raised > inserted) return Error.DecoderStreamError;
        state.known_received = raised;
    }

    /// The oldest absolute index a reference still keeps alive, or null when none does. RFC 9204
    /// §2.1.1: an entry with an outstanding reference cannot be evicted, so this is the floor a
    /// caller must not evict below.
    pub fn referenced_floor(state: *const EncoderState) ?u64 {
        var floor: ?u64 = null;
        // Bounded by `outstanding_sections_max`, which is a named limit.
        for (state.outstanding[0..state.len]) |held| {
            if (floor == null or held.required_insert_count < floor.?) {
                floor = held.required_insert_count;
            }
        }
        return floor;
    }

    fn is_blocked(state: *const EncoderState, stream_id: u64) bool {
        // Bounded by `outstanding_sections_max`, which is a named limit.
        for (state.outstanding[0..state.len]) |held| {
            if (held.stream_id != stream_id) continue;
            if (held.required_insert_count > state.known_received) return true;
        }
        return false;
    }

    /// Whether a blocked section for `stream_id` appears before `index`, so a stream with two of
    /// them counts once.
    fn has_blocked_before(state: *const EncoderState, index: usize, stream_id: u64) bool {
        // Bounded by `index`, which is below `outstanding_sections_max`.
        for (state.outstanding[0..index]) |earlier| {
            if (earlier.stream_id != stream_id) continue;
            if (earlier.required_insert_count > state.known_received) return true;
        }
        return false;
    }

    /// The earliest unacknowledged section on a stream (RFC 9204 §2.2.2.1). They are held in the
    /// order they were sent, so the first match is the earliest.
    fn earliest_of(state: *const EncoderState, stream_id: u64) ?usize {
        // Bounded by `outstanding_sections_max`, which is a named limit.
        for (state.outstanding[0..state.len], 0..) |held, index| {
            if (held.stream_id == stream_id) return index;
        }
        return null;
    }

    /// Takes one section out, keeping the rest in the order they were sent.
    fn remove(state: *EncoderState, at: usize) void {
        assert(at < state.len);
        // Bounded by `outstanding_sections_max`, which is a named limit.
        for (at + 1..state.len) |index| state.outstanding[index - 1] = state.outstanding[index];
        state.len -= 1;
    }
};

const testing = std.testing;

/// The state the tests drive, placed outside any stack frame. Test-only.
var test_state: EncoderState = undefined;
/// A blocked-stream limit small enough to reach by hand, and two stream identifiers.
const test_blocked_max: u64 = 2;
const stream_a: u64 = 0;
const stream_b: u64 = 4;
const stream_c: u64 = 8;

test "§2.1.4: an acknowledgment raises the Known Received Count to what the section needed" {
    test_state.init(test_blocked_max);
    try testing.expectEqual(0, test_state.known_received);
    try test_state.on_section_sent(stream_a, 5);
    try testing.expectEqual(0, test_state.known_received);
    try test_state.on_section_acknowledgment(stream_a);
    try testing.expectEqual(5, test_state.known_received);
    // §2.1.4: it rises to the Required Insert Count, and never falls back to a smaller one.
    try test_state.on_section_sent(stream_b, 3);
    try test_state.on_section_acknowledgment(stream_b);
    try testing.expectEqual(5, test_state.known_received);
}

test "§2.2.2.1: sections on a stream are acknowledged oldest first" {
    test_state.init(test_blocked_max);
    try test_state.on_section_sent(stream_a, 3);
    try test_state.on_section_sent(stream_a, 7);
    // A stream may carry several sections — interim responses, trailers — and each
    // acknowledgment takes the earliest that is still outstanding.
    try test_state.on_section_acknowledgment(stream_a);
    try testing.expectEqual(3, test_state.known_received);
    try test_state.on_section_acknowledgment(stream_a);
    try testing.expectEqual(7, test_state.known_received);
    // §4.4.1: one more, with nothing outstanding on that stream, is a connection error.
    try testing.expectError(Error.DecoderStreamError, test_state.on_section_acknowledgment(stream_a));
    try testing.expectError(Error.DecoderStreamError, test_state.on_section_acknowledgment(stream_b));
}

test "§2.2.2.1: taking a section out keeps the rest in the order they were sent" {
    test_state.init(test_blocked_max);
    // Two sections on one stream with others interleaved. Taking one out must not move a later
    // section of a stream ahead of an earlier one, or the next acknowledgment for that stream
    // would take the wrong one and raise the Known Received Count too far.
    try test_state.on_section_sent(stream_b, 5);
    try test_state.on_section_sent(stream_a, 3);
    try test_state.on_section_sent(stream_c, 6);
    try test_state.on_section_sent(stream_a, 7);
    try test_state.on_section_acknowledgment(stream_b);
    try testing.expectEqual(5, test_state.known_received);
    // The next acknowledgment for stream A must take the section needing 3, not the one needing
    // 7, so the count does not move past what the decoder has actually confirmed.
    try test_state.on_section_acknowledgment(stream_a);
    try testing.expectEqual(5, test_state.known_received);
    try test_state.on_section_acknowledgment(stream_a);
    try testing.expectEqual(7, test_state.known_received);
}

test "§2.1.1: a section with no dynamic reference is not outstanding" {
    test_state.init(test_blocked_max);
    // A Required Insert Count of zero means the section references nothing in the dynamic
    // table, so §2.2.2.1 has the decoder acknowledge nothing and there is nothing to track.
    try test_state.on_section_sent(stream_a, 0);
    try testing.expectEqual(0, test_state.len);
    try testing.expectEqual(null, test_state.referenced_floor());
    try testing.expectError(Error.DecoderStreamError, test_state.on_section_acknowledgment(stream_a));
}

test "§2.1.2: the encoder holds the number of streams that could block" {
    test_state.init(test_blocked_max);
    // Nothing is outstanding, so a section needing entries the decoder lacks may go out.
    try testing.expect(test_state.may_send(stream_a, 5));
    try test_state.on_section_sent(stream_a, 5);
    try testing.expectEqual(1, test_state.blocked_count());
    // A second stream reaches the limit, and a third would pass it.
    try testing.expect(test_state.may_send(stream_b, 6));
    try test_state.on_section_sent(stream_b, 6);
    try testing.expectEqual(2, test_state.blocked_count());
    try testing.expect(!test_state.may_send(stream_c, 7));
    // A section that needs nothing the decoder lacks blocks nothing, so it may always go out.
    try testing.expect(test_state.may_send(stream_c, 0));
    // A stream already counted does not count twice, so a second section on it is allowed.
    try testing.expect(test_state.may_send(stream_a, 7));
    try test_state.on_section_sent(stream_a, 7);
    try testing.expectEqual(2, test_state.blocked_count());
    // Once the decoder catches up, the streams stop counting and a third may go out.
    try test_state.on_insert_count_increment(7, 10);
    try testing.expectEqual(0, test_state.blocked_count());
    try testing.expect(test_state.may_send(stream_c, 8));
}

test "§4.4.3: an Insert Count Increment is checked against what the encoder has sent" {
    test_state.init(test_blocked_max);
    try test_state.on_insert_count_increment(3, 10);
    try testing.expectEqual(3, test_state.known_received);
    try test_state.on_insert_count_increment(7, 10);
    try testing.expectEqual(10, test_state.known_received);
    // §4.4.3: an Increment that takes the count beyond what the encoder inserted MUST be a
    // connection error of QPACK_DECODER_STREAM_ERROR.
    try testing.expectError(Error.DecoderStreamError, test_state.on_insert_count_increment(1, 10));
    try testing.expectEqual(10, test_state.known_received);
    // And so MUST an Increment of zero, which says nothing and would otherwise be ignored.
    try testing.expectError(Error.DecoderStreamError, test_state.on_insert_count_increment(0, 10));
}

test "§4.4.2: cancelling a stream drops every reference it held" {
    test_state.init(test_blocked_max);
    try test_state.on_section_sent(stream_a, 3);
    try test_state.on_section_sent(stream_b, 5);
    try test_state.on_section_sent(stream_a, 7);
    try testing.expectEqual(3, test_state.len);
    test_state.on_stream_cancellation(stream_a);
    try testing.expectEqual(1, test_state.len);
    // §4.4.2 says nothing about the Known Received Count: a cancelled section was never decoded
    // and acknowledges nothing.
    try testing.expectEqual(0, test_state.known_received);
    try testing.expectEqual(5, test_state.referenced_floor());
    // What is left is the other stream's, and it still acknowledges normally.
    try test_state.on_section_acknowledgment(stream_b);
    try testing.expectEqual(5, test_state.known_received);
    try testing.expectEqual(0, test_state.len);
    // Cancelling a stream that holds nothing changes nothing.
    test_state.on_stream_cancellation(stream_c);
    try testing.expectEqual(0, test_state.len);
}

test "§2.1.1: the oldest outstanding reference is the floor an eviction may not pass" {
    test_state.init(test_blocked_max);
    try testing.expectEqual(null, test_state.referenced_floor());
    try test_state.on_section_sent(stream_a, 9);
    try test_state.on_section_sent(stream_b, 4);
    try test_state.on_section_sent(stream_c, 6);
    // §2.1.1: an entry with an outstanding reference cannot be evicted, so the smallest count
    // still outstanding is the floor — whatever order the sections were sent in.
    try testing.expectEqual(4, test_state.referenced_floor());
    try test_state.on_section_acknowledgment(stream_b);
    try testing.expectEqual(6, test_state.referenced_floor());
}

test "colibri's own bound on outstanding sections fails closed" {
    test_state.init(constants.outstanding_sections_max);
    for (0..constants.outstanding_sections_max) |step| {
        try test_state.on_section_sent(@intCast(step), 1);
    }
    // RFC 9204 bounds this at nothing, so the bound is colibri's: past it a section is refused
    // and the caller sends one that references no dynamic entry instead.
    try testing.expectError(Error.TooManyOutstanding, test_state.on_section_sent(stream_a, 1));
    try testing.expectEqual(constants.outstanding_sections_max, test_state.len);
    // A section referencing nothing is still free, because it is not recorded at all.
    try test_state.on_section_sent(stream_a, 0);
}
