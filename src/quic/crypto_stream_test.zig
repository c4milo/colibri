//! The tests of `crypto_stream.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const crypto = @import("crypto");
const constants = @import("constants.zig");
const crypto_stream = @import("crypto_stream.zig");

const testing = std.testing;
const CryptoStream = crypto_stream.CryptoStream;
const Levels = crypto_stream.Levels;

/// The stream the tests drive, placed outside any stack frame: its window is larger than a stack
/// frame should hold.
var test_stream: CryptoStream = undefined;
var test_levels: Levels = undefined;

test "RFC 9000 §19.6: frames in order are readable as they arrive" {
    test_stream.init();
    try testing.expectEqual(0, test_stream.readable().len);
    try test_stream.receive(0, "hello ");
    try testing.expectEqualStrings("hello ", test_stream.readable());
    try test_stream.receive(6, "world");
    try testing.expectEqualStrings("hello world", test_stream.readable());
    // Nothing has been read yet, so the stream has consumed nothing.
    try testing.expectEqual(0, test_stream.consumed_len());
}

test "RFC 9000 §7.5: a gap holds the octets after it until the gap is filled" {
    test_stream.init();
    // The second frame arrives first, which is what §7.5's buffer exists for.
    try test_stream.receive(6, "world");
    try testing.expectEqual(0, test_stream.readable().len);
    try test_stream.receive(0, "hello ");
    try testing.expectEqualStrings("hello world", test_stream.readable());
}

test "a retransmitted frame changes nothing, whether it is read or buffered" {
    test_stream.init();
    try test_stream.receive(0, "abcdef");
    test_stream.consume(3);
    try testing.expectEqualStrings("def", test_stream.readable());
    try testing.expectEqual(3, test_stream.consumed_len());
    // RFC 9002 §6.2 retransmits a lost frame's octets, so the same offsets arrive again. The
    // first three are below the window now and the next three are already there.
    try test_stream.receive(0, "abcdef");
    try testing.expectEqualStrings("def", test_stream.readable());
    try testing.expectEqual(3, test_stream.consumed_len());
    // One that straddles the base keeps only the part at or above it.
    try test_stream.receive(2, "cdefgh");
    try testing.expectEqualStrings("defgh", test_stream.readable());
}

test "an overlapping frame writes the octets it shares with the same value" {
    test_stream.init();
    try test_stream.receive(0, "abcd");
    try test_stream.receive(2, "cdef");
    try testing.expectEqualStrings("abcdef", test_stream.readable());
    // And one wholly inside what is present changes nothing.
    try test_stream.receive(1, "bcde");
    try testing.expectEqualStrings("abcdef", test_stream.readable());
}

test "consume slides the window, and what was buffered above it comes with it" {
    test_stream.init();
    // A gap, with data beyond it.
    try test_stream.receive(0, "abc");
    try test_stream.receive(6, "ghi");
    try testing.expectEqualStrings("abc", test_stream.readable());
    test_stream.consume(3);
    try testing.expectEqual(0, test_stream.readable().len);
    try testing.expectEqual(3, test_stream.consumed_len());
    // The buffered run moved down with the window, so filling the gap makes it all readable.
    try test_stream.receive(3, "def");
    try testing.expectEqualStrings("defghi", test_stream.readable());
    test_stream.consume(test_stream.readable().len);
    try testing.expectEqual(9, test_stream.consumed_len());
    try testing.expectEqual(0, test_stream.readable().len);
}

test "RFC 9000 §7.5: data past the window is CRYPTO_BUFFER_EXCEEDED, and the window itself is not" {
    test_stream.init();
    // The last octet the window holds is admitted, at the far end of a gap.
    const last: u64 = constants.crypto_buffer_len - 1;
    try test_stream.receive(last, "x");
    // One octet past it is more than §7.5 obliges colibri to buffer.
    try testing.expectError(
        error.CryptoBufferExceeded,
        test_stream.receive(constants.crypto_buffer_len, "x"),
    );
    // A frame that starts inside the window and ends past it is refused whole: §7.5 is about
    // what an endpoint buffers, and a partial write would leave a gap nothing will fill.
    try testing.expectError(
        error.CryptoBufferExceeded,
        test_stream.receive(last, "xy"),
    );
    // The window moves with the reading, so the same offset is admitted once the base advances.
    try test_stream.receive(0, "a");
    test_stream.consume(1);
    try test_stream.receive(constants.crypto_buffer_len, "x");
}

test "a frame carrying no octets is neither an error nor a change" {
    test_stream.init();
    try test_stream.receive(0, "ab");
    try test_stream.receive(2, "");
    try testing.expectEqualStrings("ab", test_stream.readable());
    // RFC 9000 §19.6 does not forbid an empty CRYPTO frame, and one past the window carries
    // nothing to buffer, so it is not the overflow §7.5 names.
    try test_stream.receive(constants.crypto_buffer_len * 2, "");
    try testing.expectEqualStrings("ab", test_stream.readable());
}

test "RFC 9000 §19.6: each encryption level is a separate stream starting at offset 0" {
    test_levels.init();
    const levels = [_]crypto.suite.Level{ .initial, .handshake, .application };
    for (levels) |level| {
        try testing.expectEqual(0, test_levels.at(level).readable().len);
        try testing.expectEqual(0, test_levels.at(level).consumed_len());
    }
    // Writing one leaves the others untouched, which is what "separate" means here.
    try test_levels.at(.handshake).receive(0, "only handshake");
    try testing.expectEqualStrings("only handshake", test_levels.at(.handshake).readable());
    try testing.expectEqual(0, test_levels.at(.initial).readable().len);
    try testing.expectEqual(0, test_levels.at(.application).readable().len);
    // And each numbers its own octets from zero, so the same offset means a different octet.
    try test_levels.at(.initial).receive(0, "only initial");
    try testing.expectEqualStrings("only initial", test_levels.at(.initial).readable());
    try testing.expectEqualStrings("only handshake", test_levels.at(.handshake).readable());
}

test "a whole window of octets arriving backwards is reassembled" {
    test_stream.init();
    // Every chunk out of order, the last one first, filling the window exactly.
    const chunk_len: usize = 256;
    const chunks: usize = constants.crypto_buffer_len / chunk_len;
    var payload: [chunk_len]u8 = undefined;
    var index = chunks;
    // Bounded by the chunk count, which the window and the chunk length fix.
    while (index > 0) {
        index -= 1;
        @memset(&payload, @intCast(index));
        try test_stream.receive(index * chunk_len, &payload);
    }
    try testing.expectEqual(constants.crypto_buffer_len, test_stream.readable().len);
    // Every octet is the chunk it came from, so nothing was written at the wrong offset.
    const readable = test_stream.readable();
    for (0..chunks) |chunk| {
        for (readable[chunk * chunk_len ..][0..chunk_len]) |octet| {
            try testing.expectEqual(@as(u8, @intCast(chunk)), octet);
        }
    }
}
