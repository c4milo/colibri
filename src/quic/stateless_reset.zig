//! Stateless Reset (RFC 9000 §10.3). Part of design §8 step 9d.
//!
//! A Stateless Reset is what an endpoint sends when it has lost the state of a connection its
//! peer is still talking to — after a crash or a restart. It is a UDP datagram whose last 16
//! octets are a token the peer issued, and §10.3 shapes it to be indistinguishable from an
//! ordinary short-header packet, so the two sides of it are not symmetric.
//!
//! **Detecting one is colibri's.** §10.3.1 states when the comparison must happen and against
//! what, and both are rules rather than choices, so `Tokens` holds them.
//!
//! **Sending one is split, and every part that needs a secret is the caller's.** §10.3 requires
//! the octets before the token to be indistinguishable from random, and colibri draws no random
//! number (invariant 5). §10.3.2 derives the token from a static key over the connection ID, and
//! colibri holds no key (non-negotiable 2). The datagram that provokes one is by definition one
//! no connection could be found for, and colibri owns no socket to find that out with
//! (non-negotiable 1). So the caller decides to send, supplies the entropy and the token, and
//! `write` lays out the octets — the same division a Retry packet has, where colibri writes the
//! packet around a token it did not mint.
//!
//! **`write` takes no `Connection`, and that is load-bearing.** RFC 9000 §9 forbids answering a
//! peer's apparent migration with a Stateless Reset, because a third party could then close
//! connections by spoofing traffic. A migration is something that happens to a connection, and a
//! function that cannot see one cannot be reached from there, so
//! [invariant 20](../../docs/invariants.md) holds by the shape of this file rather than by what
//! its declarations are called.
//!
//! The comparison runs in constant time, which §10.3.1 requires: one that stopped at the first
//! differing octet would leak the token through timing. Writing it here does not break
//! non-negotiable 2, which keeps ciphers and keys out of this tree; comparing two octet strings
//! without branching on their contents is arithmetic, and the caller has nothing to add to it.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const Token = [constants.stateless_reset_token_len]u8;

/// The tokens a datagram is compared against (RFC 9000 §10.3.1). It is not every token the peer
/// issued: §10.3.1 says an endpoint MUST NOT check tokens of connection IDs it has not used or
/// that have been retired, so a token enters this set when its connection ID is first sent to
/// and leaves when the ID is retired.
pub const Tokens = struct {
    held: [constants.connection_ids_max]Token,
    len: usize,

    pub fn init(tokens: *Tokens) void {
        tokens.held = @splat(@splat(0));
        tokens.len = 0;
    }

    /// Remembers the token of a connection ID this endpoint has now sent to (RFC 9000 §10.3.1).
    /// A token already held is not held twice.
    pub fn use(tokens: *Tokens, token: Token) void {
        for (tokens.held[0..tokens.len]) |held| {
            if (std.mem.eql(u8, &held, &token)) return;
        }
        if (tokens.len == tokens.held.len) return;
        tokens.held[tokens.len] = token;
        tokens.len += 1;
    }

    /// Forgets the token of a connection ID that has been retired (RFC 9000 §10.3, §19.16:
    /// retiring a connection ID invalidates the token associated with it).
    pub fn retire(tokens: *Tokens, token: Token) void {
        for (tokens.held[0..tokens.len], 0..) |held, index| {
            if (!std.mem.eql(u8, &held, &token)) continue;
            for (index + 1..tokens.len) |at| tokens.held[at - 1] = tokens.held[at];
            tokens.len -= 1;
            return;
        }
    }

    pub fn count(tokens: *const Tokens) usize {
        return tokens.len;
    }

    /// Whether `datagram` is a Stateless Reset for this connection (RFC 9000 §10.3.1): whether
    /// its last 16 octets equal a token held here. A match means the peer has lost the
    /// connection's state, and §10.3.1 has this endpoint enter the draining period and send
    /// nothing further.
    ///
    /// Every token is compared, and each comparison reads every octet, so the time taken
    /// depends on how many tokens are held and not on which octets matched. §10.3.1 asks for
    /// that, and adds that an endpoint is not expected to hide the number of tokens it holds.
    pub fn matches(tokens: *const Tokens, datagram: []const u8) bool {
        if (datagram.len < constants.stateless_reset_token_len) return false;
        const trailing = datagram[datagram.len - constants.stateless_reset_token_len ..];
        var found = false;
        for (tokens.held[0..tokens.len]) |held| {
            found = equal_in_constant_time(&held, trailing) or found;
        }
        return found;
    }
};

/// Whether two tokens are equal, reading every octet whatever they hold (RFC 9000 §10.3.1).
fn equal_in_constant_time(held: *const Token, trailing: []const u8) bool {
    assert(trailing.len == constants.stateless_reset_token_len);
    var differences: u8 = 0;
    for (held, trailing) |left, right| differences |= left ^ right;
    return differences == 0;
}

/// The lengths a Stateless Reset answering `triggered_by_len` octets may take (RFC 9000
/// §10.3.3), or null when none may be sent. The caller fills the octets before the token,
/// because §10.3 requires them to be indistinguishable from random.
pub const PermittedLen = struct {
    /// The shortest that is still a Stateless Reset: the token, and enough before it to look
    /// like a short header (RFC 9000 §10.3).
    min: usize,
    /// The longest. RFC 9000 §10.3.3 makes it smaller than the packet that triggered it, so a
    /// loop ends in packets too small to answer, and §10.3 keeps it under three times that
    /// packet so the answer cannot be used for amplification. The first bound is the tighter
    /// of the two for every packet, and both are stated because each rule stands alone.
    max: usize,
};

/// Why no Stateless Reset was written.
pub const Refused = enum {
    /// RFC 9000 §10.3.3: every Stateless Reset "is smaller than the packet that triggered it", so
    /// a datagram at or under §10.3's 21-octet minimum leaves no room for one. This is what ends
    /// the loop §10.3.3 describes: "in the event of a loop, this results in packets eventually
    /// being too small to trigger a response".
    triggered_by_too_small,
    /// The caller offered fewer unpredictable octets than §10.3's shape needs, or `output` cannot
    /// hold the shortest Stateless Reset.
    too_short,
};

pub const Answer = union(enum) {
    /// Octets of `output` the datagram occupies. A Stateless Reset "uses an entire UDP datagram",
    /// so this is the whole of what the caller sends.
    written: usize,
    refused: Refused,
};

/// Lays out one Stateless Reset in the front of `output` (RFC 9000 §10.3's Figure 10).
///
/// `triggered_by_len` is the datagram that provoked it, which §10.3.3 bounds the answer by.
/// `unpredictable` is the octets the caller drew — §10.3 wants them "indistinguishable from
/// random" and invariant 5 forbids colibri a random number — and how many are offered is what
/// chooses the size within the bounds §10.3.3 admits. `token` is the one §10.3.2 derives from a
/// static key colibri does not hold.
pub fn write(triggered_by_len: usize, unpredictable: []const u8, token: Token, output: []u8) Answer {
    const permitted = permitted_len(triggered_by_len) orelse
        return .{ .refused = .triggered_by_too_small };
    const offered = unpredictable.len +| constants.stateless_reset_token_len;
    const len = @min(permitted.max, @min(output.len, offered));
    if (len < permitted.min) return .{ .refused = .too_short };
    const bits_len = len - constants.stateless_reset_token_len;
    @memcpy(output[0..bits_len], unpredictable[0..bits_len]);
    // §10.3's Figure 10: "Fixed Bits (2) = 1". Those two are RFC 8999 §5.1's Header Form and
    // RFC 9000 §17.2's Fixed Bit, so a Stateless Reset "will appear to be a packet with a short
    // header" to every entity but its intended recipient.
    output[0] = (output[0] & ~header_bits) | constants.fixed_bit;
    // §10.3: "The last 16 bytes of the datagram contain a stateless reset token."
    @memcpy(output[bits_len..len], &token);
    assert(output[0] & header_bits == constants.fixed_bit);
    // §10.3.3 and §10.3 again, as the two bounds `permitted_len` computed.
    assert(len < triggered_by_len);
    return .{ .written = len };
}

/// The two bits RFC 9000 §10.3's Figure 10 fixes, which every other bit of byte 0 is the
/// caller's.
const header_bits: u8 = constants.header_form_bit | constants.fixed_bit;

pub fn permitted_len(triggered_by_len: usize) ?PermittedLen {
    const min = constants.stateless_reset_len_min;
    // RFC 9000 §10.3.3: smaller than what triggered it, so `triggered_by_len` itself is out.
    if (triggered_by_len <= min) return null;
    // RFC 9000 §10.3: and never three times or more what it answers, so a datagram that cannot
    // be associated with a connection cannot be used for amplification either.
    const amplification_max = triggered_by_len *| constants.stateless_reset_amplification_factor;
    return .{ .min = min, .max = @min(triggered_by_len - 1, amplification_max -| 1) };
}

const testing = std.testing;

/// The tokens the tests drive, and three distinct ones. Test-only.
var test_tokens: Tokens = undefined;
const octet_a = 0x11;
const octet_b = 0x22;
const octet_c = 0x33;
const token_a: Token = @splat(octet_a);
const token_b: Token = @splat(octet_b);
const token_c: Token = @splat(octet_c);

test "§10.3.1: a datagram ending in a held token is a Stateless Reset" {
    test_tokens.init();
    // Nothing is held, so nothing matches, however the datagram ends.
    try testing.expect(!test_tokens.matches(&token_a));
    test_tokens.use(token_a);
    test_tokens.use(token_b);
    try testing.expectEqual(2, test_tokens.count());
    // The comparison is of the last 16 octets, whatever comes before them.
    const padded = [_]u8{0xff} ** 8 ++ token_b;
    try testing.expect(test_tokens.matches(&padded));
    try testing.expect(test_tokens.matches(&token_a));
    try testing.expect(!test_tokens.matches(&token_c));
    // A datagram that begins with a token but does not end with one is not a reset.
    const trailing_other = token_a ++ [_]u8{0x00} ** constants.stateless_reset_token_len;
    try testing.expect(!test_tokens.matches(&trailing_other));
}

test "§10.3.1: a datagram too short to hold a token is not one" {
    test_tokens.init();
    test_tokens.use(token_a);
    for (0..constants.stateless_reset_token_len) |len| {
        try testing.expect(!test_tokens.matches(token_a[0..len]));
    }
    try testing.expect(test_tokens.matches(&token_a));
}

test "§10.3.1: a token is checked only while its connection ID is used and not retired" {
    test_tokens.init();
    // RFC 9000 §10.3.1: an endpoint MUST NOT check tokens for connection IDs it has not used.
    try testing.expect(!test_tokens.matches(&token_a));
    test_tokens.use(token_a);
    try testing.expect(test_tokens.matches(&token_a));
    // Using the same one twice holds it once.
    test_tokens.use(token_a);
    try testing.expectEqual(1, test_tokens.count());
    // RFC 9000 §19.16: retiring the connection ID invalidates its token.
    test_tokens.retire(token_a);
    try testing.expectEqual(0, test_tokens.count());
    try testing.expect(!test_tokens.matches(&token_a));
    // Retiring one never held changes nothing, and the others are untouched.
    test_tokens.use(token_a);
    test_tokens.use(token_b);
    test_tokens.retire(token_c);
    test_tokens.retire(token_a);
    try testing.expectEqual(1, test_tokens.count());
    try testing.expect(test_tokens.matches(&token_b));
    try testing.expect(!test_tokens.matches(&token_a));
}

test "§10.3.1: every held token is compared, so the time does not follow the match" {
    test_tokens.init();
    // A token that differs in its last octet alone must still be found, which a comparison
    // stopping at the first difference would also do — what this pins is that the match does
    // not depend on where the difference is.
    var late: Token = @splat(octet_a);
    late[late.len - 1] = octet_c;
    test_tokens.use(late);
    try testing.expect(test_tokens.matches(&late));
    try testing.expect(!test_tokens.matches(&token_a));
    // A token that differs in its first octet alone is refused too.
    var early: Token = @splat(octet_a);
    early[0] = octet_c;
    try testing.expect(!test_tokens.matches(&early));
    // The one held last is found as readily as the one held first.
    test_tokens.use(token_b);
    try testing.expect(test_tokens.matches(&token_b));
    try testing.expect(test_tokens.matches(&late));
}

test "§10.3.3: a Stateless Reset is smaller than what triggered it" {
    // RFC 9000 §10.3.3: smaller than the packet that triggered it, so a loop dies out.
    const answering = permitted_len(constants.stateless_reset_len_min + 10).?;
    try testing.expectEqual(constants.stateless_reset_len_min, answering.min);
    try testing.expectEqual(constants.stateless_reset_len_min + 9, answering.max);
    try testing.expect(answering.max < constants.stateless_reset_len_min + 10);
    // A packet at or below the smallest reset leaves no room for one, which is how the loop
    // ends rather than continuing with ever smaller datagrams.
    try testing.expectEqual(null, permitted_len(constants.stateless_reset_len_min));
    try testing.expectEqual(null, permitted_len(0));
    // One octet above it admits exactly the smallest.
    const tightest = permitted_len(constants.stateless_reset_len_min + 1).?;
    try testing.expectEqual(tightest.min, tightest.max);
}

/// Octets a caller drew for the bits RFC 9000 §10.3 wants indistinguishable from random. Fixed
/// here, because invariant 5 forbids colibri a random number and a test states what it uses.
const bits_octet: u8 = 0xa5;
/// More octets than any case below asks for, so what bounds an answer is the rule under test.
const bits_len_plenty: usize = 64;
const bits_plenty: [bits_len_plenty]u8 = @splat(bits_octet);
var reset_output: [bits_len_plenty]u8 = undefined;
/// A datagram long enough that §10.3.3 admits an answer of every length these cases ask for.
const triggering_len: usize = 60;

test "§10.3: a Stateless Reset is a short header, unpredictable bits and the token" {
    const answer = write(triggering_len, &bits_plenty, token_a, &reset_output);
    const len = answer.written;
    // §10.3.3: "smaller than the packet that triggered it", and §10.3 keeps it under three times
    // that packet; the first bound is the tighter one for every packet.
    try testing.expectEqual(triggering_len - 1, len);
    // Figure 10's "Fixed Bits (2) = 1": Header Form 0 and Fixed Bit 1, so it reads as a 1-RTT
    // packet to anything but its recipient.
    try testing.expectEqual(constants.fixed_bit, reset_output[0] & header_bits);
    // The remainder of byte 0 is the caller's octets, untouched.
    try testing.expectEqual(bits_octet & ~header_bits, reset_output[0] & ~header_bits);
    // §10.3: "The last 16 bytes of the datagram contain a stateless reset token."
    try testing.expectEqualSlices(u8, &token_a, reset_output[len - token_a.len ..][0..token_a.len]);
    // Everything between byte 0 and the token is what the caller drew.
    for (reset_output[1 .. len - token_a.len]) |octet| try testing.expectEqual(bits_octet, octet);
    // §10.3.1 reads it back as one: a datagram ending in a held token.
    test_tokens.init();
    test_tokens.use(token_a);
    try testing.expect(test_tokens.matches(reset_output[0..len]));
}

test "§10.3.3: the answer is bounded by what triggered it, and by what the caller offered" {
    // "An endpoint MUST ensure that every Stateless Reset that it sends is smaller than the
    // packet that triggered it", so a datagram at the minimum leaves no room for one and the
    // loop ends there.
    try testing.expectEqual(
        Refused.triggered_by_too_small,
        write(constants.stateless_reset_len_min, &bits_plenty, token_a, &reset_output).refused,
    );
    // One octet above it admits exactly the shortest Stateless Reset.
    const tightest = write(constants.stateless_reset_len_min + 1, &bits_plenty, token_a, &reset_output);
    try testing.expectEqual(constants.stateless_reset_len_min, tightest.written);

    // How many unpredictable octets the caller offered is what chooses the size under that bound.
    const offered_len: usize = 8;
    const shorter = write(triggering_len, bits_plenty[0..offered_len], token_a, &reset_output);
    try testing.expectEqual(offered_len + constants.stateless_reset_token_len, shorter.written);
}

test "§10.3: a Stateless Reset that will not fit is not written" {
    // Fewer unpredictable octets than §10.3's shape needs. "the Unpredictable Bits field needs to
    // include at least 38 bits of data (or 5 bytes, less the two fixed bits)."
    const bits_short = bits_plenty[0 .. constants.stateless_reset_unpredictable_len_min - 1];
    try testing.expectEqual(
        Refused.too_short,
        write(triggering_len, bits_short, token_a, &reset_output).refused,
    );
    // And an output that cannot hold the shortest one.
    var small: [constants.stateless_reset_len_min - 1]u8 = undefined;
    try testing.expectEqual(
        Refused.too_short,
        write(triggering_len, &bits_plenty, token_a, &small).refused,
    );
}

test "§10.3: a Stateless Reset answering a short packet is one octet shorter than it" {
    // "An endpoint that sends a Stateless Reset in response to a packet that is 43 bytes or
    // shorter SHOULD send a Stateless Reset that is one byte shorter than the packet it responds
    // to." §10.3.3's MUST is the same bound, so meeting it meets this.
    // RFC 9000 §10.3's "43 bytes or shorter".
    const short_trigger: usize = 40;
    const answer = write(short_trigger, &bits_plenty, token_a, &reset_output);
    try testing.expectEqual(short_trigger - 1, answer.written);
}
