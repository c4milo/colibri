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

/// Fills the send window from the provider's side, as `connection_crypto.write_crypto` does.
fn produce(stream: *CryptoStream, octet: u8, len: usize) void {
    const room = stream.send_room();
    const written = @min(room.len, len);
    @memset(room[0..written], octet);
    stream.produced(written);
}

test "RFC 9000 §19.6: the send window hands out what was produced and not yet framed" {
    test_stream.init();
    try testing.expectEqual(0, test_stream.unsent().len);
    try testing.expectEqual(constants.crypto_send_buffer_len, test_stream.send_room().len);

    produce(&test_stream, first_octet, short_len);
    try testing.expectEqual(short_len, test_stream.unsent().len);
    // The Offset a frame carries is what was framed, not what was produced (§19.6).
    try testing.expectEqual(0, test_stream.sent_len);
    test_stream.framed(part_len);
    try testing.expectEqual(part_len, test_stream.sent_len);
    try testing.expectEqual(short_len - part_len, test_stream.unsent().len);
    try testing.expectEqual(first_octet, test_stream.unsent()[0]);

    // More may be produced beside what is waiting, and it joins the same run.
    produce(&test_stream, second_octet, short_len);
    try testing.expectEqual(short_len - part_len + short_len, test_stream.unsent().len);
}

test "RFC 9000 §17.2.5.3: a flight that fits can be sent again from offset 0" {
    test_stream.init();
    produce(&test_stream, first_octet, short_len);
    test_stream.framed(short_len);
    try testing.expectEqual(0, test_stream.unsent().len);

    try testing.expect(test_stream.can_rewind());
    test_stream.rewind();
    // "A client MUST use the same cryptographic handshake message it included in this packet":
    // the octets are the ones already produced, and the provider is not asked for them again.
    try testing.expectEqual(0, test_stream.sent_len);
    try testing.expectEqual(short_len, test_stream.unsent().len);
    try testing.expectEqual(first_octet, test_stream.unsent()[0]);
}

test "RFC 9000 §17.2.5.3: a flight that fits is not forgotten when more room is asked for" {
    test_stream.init();
    produce(&test_stream, first_octet, short_len);
    test_stream.framed(short_len);
    // The next packet asks for room before it frames anything, and the window still reaches 0:
    // §13.3 and §17.2.5.3 can only send again what the window holds.
    _ = test_stream.send_room();
    try testing.expect(test_stream.can_rewind());
    test_stream.rewind();
    try testing.expectEqual(short_len, test_stream.unsent().len);
}

test "RFC 9000 §13.3: a flight larger than the window forgets only what it has framed" {
    test_stream.init();
    // Fill the window and frame all of it, which is the only state that may forget anything.
    produce(&test_stream, first_octet, constants.crypto_send_buffer_len);
    try testing.expectEqual(0, test_stream.send_room().len);
    try testing.expect(test_stream.can_rewind());
    test_stream.framed(constants.crypto_send_buffer_len);

    // Asking for room is what forgets, and only then.
    try testing.expectEqual(constants.crypto_send_buffer_len, test_stream.send_room().len);
    try testing.expect(!test_stream.can_rewind());
    produce(&test_stream, second_octet, short_len);
    // The flow carries on at the offset it reached: §19.6 numbers the octets, not the window.
    try testing.expectEqual(constants.crypto_send_buffer_len, test_stream.sent_len);
    try testing.expectEqual(short_len, test_stream.unsent().len);
    try testing.expectEqual(second_octet, test_stream.unsent()[0]);
}

/// Octets the send-window cases write, distinct so a run that took the wrong one cannot pass.
const first_octet: u8 = 0xa1;
const second_octet: u8 = 0xb2;
const short_len: usize = 32;
const part_len: usize = 12;
