//! RFC 9204 §4.5.1.1's Required Insert Count, encoded and decoded. Part of design §8 step 11.
//!
//! The Required Insert Count says which dynamic table state a field section needs before it can
//! be decoded. Sending it as it stands would make the field section prefix grow without bound on
//! a long-lived connection, so §4.5.1.1 sends it modulo twice `MaxEntries` and has the decoder
//! rebuild it from how many entries it has actually received.
//!
//! **The rebuilding is where a decoder can be attacked, and §4.5.1.1 says so**: a value a
//! conformant encoder could not have produced MUST be a connection error of
//! QPACK_DECOMPRESSION_FAILED. The three checks below are exactly the three the RFC's own
//! pseudocode makes, in its order, and each one carries the line it came from.
//!
//! `MaxEntries` is the decoder's advertised capacity over §3.2.1's smallest entry, which
//! `dynamic_table.max_entries` computes. A decoder that permits no dynamic table has a
//! `MaxEntries` of zero, and then the only Required Insert Count it can accept is zero.
const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// RFC 9204 §4.5.1.1: an encoded value no conformant encoder could have produced, which
    /// §6 makes a connection error of QPACK_DECOMPRESSION_FAILED.
    DecompressionFailed,
};

/// What an encoder puts in the field section prefix (RFC 9204 §4.5.1.1).
pub fn encode(required: u64, max_entries: u64) u64 {
    // §4.5.1.1: `if ReqInsertCount == 0: EncInsertCount = 0`. Zero is sent as zero, which is why
    // the other branch adds one: it keeps the two apart.
    if (required == 0) return 0;
    const full_range = full_range_of(max_entries);
    assert(full_range > 0);
    return (required % full_range) + 1;
}

/// What a decoder rebuilds it as, given how many entries it has received (RFC 9204 §4.5.1.1).
/// `total_inserts` is the RFC's `TotalNumberOfInserts`: the decoder's own insert count.
pub fn decode(encoded: u64, total_inserts: u64, max_entries: u64) Error!u64 {
    if (encoded == 0) return 0;
    const full_range = full_range_of(max_entries);
    // §4.5.1.1: `if EncodedInsertCount > FullRange: Error`. With no dynamic table permitted the
    // full range is zero, so every non-zero value fails here, which is the same rule and not a
    // special case.
    if (encoded > full_range) return Error.DecompressionFailed;
    const max_value = total_inserts + max_entries;
    // §4.5.1.1: `MaxWrapped` is the largest value that is 0 mod FullRange.
    const max_wrapped = (max_value / full_range) * full_range;
    var required = max_wrapped + encoded - 1;
    // §4.5.1.1: if it exceeds MaxValue the encoder's value must have wrapped one fewer time.
    if (required > max_value) {
        if (required <= full_range) return Error.DecompressionFailed;
        required -= full_range;
    }
    // §4.5.1.1: `Value of 0 must be encoded as 0`, so rebuilding zero from a non-zero encoding
    // means the encoder was not conformant.
    if (required == 0) return Error.DecompressionFailed;
    return required;
}

/// RFC 9204 §4.5.1.1's `FullRange` is twice `MaxEntries`, which is what leaves room for a
/// Required Insert Count on either side of what the decoder has received.
const full_range_factor: u64 = 2;

fn full_range_of(max_entries: u64) u64 {
    return max_entries *| full_range_factor;
}

const testing = std.testing;

/// RFC 9204 §4.5.1.1's own example: a dynamic table of 100 octets, so `MaxEntries` is 3 and the
/// Required Insert Count is encoded modulo 6. Test-only.
const example_max_entries: u64 = 3;
const example_full_range: u64 = 6;

test "§4.5.1.1: the RFC's own example rebuilds 9 from an encoded 4" {
    // "if a decoder has received 10 inserts, then an encoded value of 4 indicates that the
    // Required Insert Count is 9 for the field section."
    try testing.expectEqual(9, try decode(4, 10, example_max_entries));
    // And the encoder that produced it: 9 mod 6 is 3, plus one is 4.
    try testing.expectEqual(4, encode(9, example_max_entries));
}

test "§4.5.1.1: zero goes out as zero and comes back as zero" {
    try testing.expectEqual(0, encode(0, example_max_entries));
    try testing.expectEqual(0, try decode(0, 0, example_max_entries));
    try testing.expectEqual(0, try decode(0, 100, example_max_entries));
    // A decoder that permits no dynamic table has a MaxEntries of zero, and zero is then the
    // only count it can accept.
    try testing.expectEqual(0, encode(0, 0));
    try testing.expectEqual(0, try decode(0, 0, 0));
    try testing.expectError(Error.DecompressionFailed, decode(1, 0, 0));
}

test "§4.5.1.1: every count a decoder could hold survives the round trip" {
    // The encoding is lossy on its own and exact given the decoder's insert count. The window
    // it is exact over is what §4.5.1.1's arithmetic admits: the decoder rebuilds a value in
    // `(MaxValue - FullRange, MaxValue]`, which is the counts within MaxEntries either side of
    // what it has received. A count further back than that names entries §3.2.2 may already
    // have evicted, so no conformant encoder sends one.
    var total: u64 = 0;
    while (total <= 4 * example_full_range) : (total += 1) {
        var required = @max(1, (total + 1) -| example_max_entries);
        while (required <= total + example_max_entries) : (required += 1) {
            const encoded = encode(required, example_max_entries);
            try testing.expectEqual(required, try decode(encoded, total, example_max_entries));
        }
    }
}

test "§4.5.1.1: a value no conformant encoder could produce is refused" {
    // Above the full range, which is the first check the RFC's pseudocode makes.
    try testing.expectError(Error.DecompressionFailed, decode(example_full_range + 1, 10, example_max_entries));
    // An encoder never produces more than the full range: the remainder is below it and one is
    // added, so the largest encoding is the full range itself and nothing above it is legal.
    try testing.expectEqual(example_full_range, encode(example_full_range - 1, example_max_entries));
    try testing.expectEqual(1, encode(example_full_range, example_max_entries));
    _ = try decode(example_full_range, 10, example_max_entries);
    // A value that rebuilds to zero, which §4.5.1.1 refuses because zero must be encoded as zero.
    try testing.expectError(Error.DecompressionFailed, decode(1, 0, example_max_entries));
    // A decoder that has received fewer inserts than MaxEntries is the case where undoing the
    // wrap would take the count below zero. §4.5.1.1 refuses it rather than wrapping: with
    // nothing received, an encoded 6 means a count of 5, which is further ahead than MaxEntries
    // lets an encoder reference.
    try testing.expectError(Error.DecompressionFailed, decode(example_full_range, 0, example_max_entries));
    try testing.expectError(Error.DecompressionFailed, decode(5, 0, example_max_entries));
    // One step further on, the decoder has enough history for the same encoding to resolve.
    try testing.expectEqual(5, try decode(example_full_range, 4, example_max_entries));
}

test "§4.5.1.1: the wrap is undone against the decoder's own insert count" {
    // The same encoded value means different counts to decoders at different points, which is
    // the whole mechanism: the encoded value alone carries only the remainder.
    try testing.expectEqual(3, try decode(4, 4, example_max_entries));
    try testing.expectEqual(9, try decode(4, 10, example_max_entries));
    try testing.expectEqual(15, try decode(4, 16, example_max_entries));
    // A count the decoder has not reached yet is still accepted when it is within MaxEntries of
    // what it has: §2.1.2's blocked streams exist for exactly that gap.
    try testing.expectEqual(12, try decode(1, 10, example_max_entries));
    try testing.expect(12 <= 10 + example_max_entries);
}

test "decision 77: every vector of spec/lean's proved decode is this decode's answer" {
    // spec/lean/Colibri/Qpack/InsertCount.lean proves its `decode` round-trips every count in the
    // protocol's window; its outputs over every input in range are here, and must be this one's.
    var lines = std.mem.splitScalar(u8, @embedFile("insert_count_vectors.txt"), '\n');
    var count: usize = 0;
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const encoded = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        const total = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        const max_entries = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        const answer = fields.next().?;
        if (std.mem.eql(u8, answer, "error")) {
            try testing.expectError(Error.DecompressionFailed, decode(encoded, total, max_entries));
        } else {
            try testing.expectEqual(try std.fmt.parseUnsigned(u64, answer, 10), try decode(encoded, total, max_entries));
        }
        count += 1;
    }
    // Every MaxEntries from 0 to 8, every total to 4 * MaxEntries + 2, every encoded value to
    // 2 * MaxEntries + 2.
    try testing.expectEqual(2361, count);
}
