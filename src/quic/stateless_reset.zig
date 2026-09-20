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
//! **Sending one is the caller's.** §10.3 requires the octets before the token to be
//! indistinguishable from random, and colibri draws no random number (invariant 5). What
//! colibri supplies is the shape: `permitted_len` gives the sizes §10.3.3 admits, which is the
//! part that is arithmetic rather than entropy.
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
