//! A path and what may be sent on it (RFC 9000 §8): the anti-amplification limit of §8 and the
//! path validation of §8.2. Part of design §8 step 9d.
//!
//! A path is an address pair, and what this file holds about one is whether the peer has been
//! shown to be reachable at it and how much may be sent there before it has. The addresses
//! themselves are the caller's: colibri owns no socket (non-negotiable 1), so it never learns an
//! address and never compares two.
//!
//! The two rules are one mechanism seen from two sides. Until a path is validated a server must
//! not send more than three times what it received there ([invariant
//! 18](../../docs/invariants.md)), which is what stops a spoofed source address turning this
//! endpoint into an amplifier; validating the path is what lifts the limit. A client
//! establishing a connection is exempt (§21.1.1.1), which is what `Start` names. §8.2.3 is
//! explicit that a PATH_RESPONSE validates the path the PATH_CHALLENGE went out on, whichever
//! path it came back over, so the two are not the same question.
//!
//! Every instant is a parameter and the challenge data is the caller's, because it must be
//! unpredictable (§8.2.1) and colibri draws no random number (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const PeerAddress = @import("peer_address.zig").PeerAddress;

/// How far a path has got (RFC 9000 §8, §8.2). It is what a caller reports, and is derived:
/// whether the path is validated and whether a probe is outstanding are independent, because
/// §8.2.1 lets an endpoint validate a path at any time, and §8.2.3 requires a second validation
/// of a path already validated when the first datagram was too small to test the MTU.
pub const State = enum {
    /// Nothing has shown the peer is there, and the limit of §8 applies.
    unvalidated,
    /// A PATH_CHALLENGE is outstanding and the path is not yet validated (§8.2.1).
    challenging,
    /// A PATH_RESPONSE matched, so the peer is reachable at this address (§8.2.3).
    validated,
    /// The last attempt was abandoned, which §8.2.4 makes the only way validation fails.
    abandoned,
};

/// Whether the peer is already known to be reachable when the path begins, which decides whether
/// §8's limit applies to it at all.
pub const Start = enum {
    /// RFC 9000 §8.1: "Prior to validating the client address, servers MUST NOT send more than
    /// three times as many bytes as the number of bytes they have received." A server is handed
    /// an address it has no reason to believe, so its path begins here.
    unvalidated,
    /// RFC 9000 §21.1.1.1: "The anti-amplification limit does not apply to clients when
    /// establishing a new connection." §8.1 says why a client is safe to exempt: it chose the
    /// Destination Connection ID the server's Initial keys derive from, so any packet it can
    /// read at all came from the address it sent to.
    validated,
};

/// The PATH_CHALLENGE this endpoint is waiting on (RFC 9000 §8.2.1).
const Challenge = struct {
    data: [constants.path_challenge_len]u8,
    sent_ns: u64,
    /// How long the attempt is given before §8.2.4 abandons it.
    timeout_ns: u64,
    /// RFC 9000 §8.2.1: whether the datagram this went out in reached the 1,200 octets the
    /// section asks for. §8.2.3 reads it when the response arrives, because a challenge sent in
    /// a smaller datagram validates the address and not the path MTU.
    expanded: bool,
};

pub const Path = struct {
    /// The peer's address on this path, as the caller names it (decision 72). Nothing here reads
    /// it: `connection_migration` compares it with the address each datagram came from.
    address: PeerAddress,
    /// RFC 9000 §8.2.3: set once a PATH_RESPONSE matched, and never cleared — a peer shown to
    /// be at an address is not unshown by a later probe going unanswered.
    validated: bool,
    /// RFC 9000 §8.2.3: whether the datagram that validated it was large enough to test the
    /// path MTU as well as the address.
    mtu_validated: bool,
    /// RFC 9000 §8.2.2: the PATH_CHALLENGE data this endpoint must echo, or null when it owes
    /// none. Only the last is kept: a peer that challenges twice before colibri answers gets one
    /// response, and §8.2.1 lets it challenge again to evoke another.
    response_owed: ?[constants.path_challenge_len]u8,
    /// RFC 9000 §8.2.1: the PATH_CHALLENGE this endpoint means to send, or null when it means to
    /// send none. The data is the caller's: §8.2.1 wants it unpredictable and invariant 5 forbids
    /// colibri a random number.
    challenge_owed: ?[constants.path_challenge_len]u8,
    /// Whether the last attempt ran out of time (§8.2.4). It is read only while no probe is
    /// outstanding, so a new one needs no clearing: the probe itself is what `state` reports.
    abandoned: bool,
    /// Octets received on this path, and sent on it, which §8's limit compares.
    received: u64,
    sent: u64,
    challenge: ?Challenge,

    pub fn init(path: *Path, start: Start) void {
        path.* = .{
            .address = .{},
            .validated = start == .validated,
            .mtu_validated = false,
            .abandoned = false,
            .received = 0,
            .sent = 0,
            .challenge = null,
            .response_owed = null,
            .challenge_owed = null,
        };
    }

    /// RFC 9000 §8.2.2: "On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by echoing
    /// the data contained in the PATH_CHALLENGE frame in a PATH_RESPONSE frame." The octets are
    /// kept rather than the packet they arrived in, and the send path writes them.
    pub fn take_challenge(path: *Path, data: [constants.path_challenge_len]u8) void {
        path.response_owed = data;
    }

    /// Asks for a PATH_CHALLENGE to go out (RFC 9000 §8.2.1). `data` must be unpredictable, which
    /// is why the caller draws it: §8.2.1 says "The endpoint MUST use unpredictable data in every
    /// PATH_CHALLENGE frame so that it can associate the peer's response with the corresponding
    /// PATH_CHALLENGE", and invariant 5 forbids colibri a random number.
    pub fn owe_challenge(path: *Path, data: [constants.path_challenge_len]u8) void {
        path.challenge_owed = data;
    }

    /// Takes the PATH_RESPONSE this endpoint owes, leaving none. §8.2.2: "An endpoint MUST NOT
    /// send more than one PATH_RESPONSE frame in response to one PATH_CHALLENGE frame."
    pub fn take_response_owed(path: *Path) ?[constants.path_challenge_len]u8 {
        const owed = path.response_owed orelse return null;
        path.response_owed = null;
        return owed;
    }

    /// Takes the PATH_CHALLENGE this endpoint means to send, leaving none. §8.2.1 lets an
    /// endpoint send more to guard against loss, which is another call to `owe_challenge`.
    pub fn take_challenge_owed(path: *Path) ?[constants.path_challenge_len]u8 {
        const owed = path.challenge_owed orelse return null;
        path.challenge_owed = null;
        return owed;
    }

    /// What a caller reports about the path.
    pub fn state(path: *const Path) State {
        if (path.validated) return .validated;
        if (path.challenge != null) return .challenging;
        return if (path.abandoned) .abandoned else .unvalidated;
    }

    /// Counts a datagram that arrived on this path, which is what §8's limit is measured
    /// against. RFC 9000 §8: the limit counts octets received from the address, so a datagram
    /// this endpoint could not decrypt still counts — it still came from there.
    pub fn on_datagram_received(path: *Path, len: u64) void {
        path.received +|= len;
    }

    /// Counts a datagram sent on this path.
    pub fn on_datagram_sent(path: *Path, len: u64) void {
        assert(len <= path.send_allowance());
        path.sent +|= len;
    }

    /// Octets this endpoint may still send on the path. RFC 9000 §8: before the address is
    /// validated an endpoint MUST limit what it sends to three times what it received, and a
    /// validated path has no such limit.
    pub fn send_allowance(path: *const Path) u64 {
        if (path.validated) return std.math.maxInt(u64);
        const permitted = path.received *| constants.anti_amplification_factor;
        return permitted -| path.sent;
    }

    /// Whether §8's limit is what stops a datagram of `len` going out.
    pub fn is_amplification_limited(path: *const Path, len: u64) bool {
        return len > path.send_allowance();
    }

    /// Records the PATH_CHALLENGE this endpoint sent (RFC 9000 §8.2.1). `data` must be
    /// unpredictable, which is why the caller draws it. `datagram_len` is the length of the
    /// datagram it went out in, because §8.2.1's expansion is about the datagram and not the
    /// packet. `timeout_ns` is what §8.2.4 recommends: three times the larger of the current
    /// Probe Timeout and the new path's.
    pub fn on_challenge_sent(
        path: *Path,
        data: [constants.path_challenge_len]u8,
        datagram_len: usize,
        now_ns: u64,
        timeout_ns: u64,
    ) void {
        // RFC 9000 §8.2.1: path validation can be used at any time by either endpoint, so a
        // path already validated is challenged again — which §8.2.3 requires when the first
        // datagram was too small to test the MTU.
        path.challenge = .{
            .data = data,
            .sent_ns = now_ns,
            .timeout_ns = timeout_ns,
            // §8.2.1: "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to
            // at least the smallest allowed maximum datagram size of 1200 bytes." The caller
            // says how long the datagram was and the comparison is colibri's, so the threshold
            // is written once, here, and never at a call site.
            .expanded = datagram_len >= constants.datagram_len_min,
        };
    }

    /// A Handshake packet from the peer that this endpoint opened and processed. RFC 9000 §8.1:
    /// "Once an endpoint has successfully processed a Handshake packet from the peer, it can
    /// consider the peer address to have been validated", because a packet under Handshake keys
    /// shows the peer read an Initial sent to that address.
    pub fn on_handshake_processed(path: *Path) void {
        path.validated = true;
    }

    /// Takes a PATH_RESPONSE. RFC 9000 §8.2.3: validation succeeds when the frame carries the
    /// data of a PATH_CHALLENGE sent before, and a response arriving on any path validates the
    /// one its challenge went out on.
    pub fn on_response(path: *Path, data: [constants.path_challenge_len]u8) bool {
        const outstanding = path.challenge orelse return false;
        if (!std.mem.eql(u8, &outstanding.data, &data)) return false;
        path.challenge = null;
        path.validated = true;
        // RFC 9000 §8.2.3: "If an endpoint sends a PATH_CHALLENGE frame in a datagram that is not
        // expanded to at least 1200 bytes and if the response to it validates the peer address,
        // the path is validated but not the path MTU." A later expanded challenge settles it, and
        // an unexpanded one after does not unsettle it.
        path.mtu_validated = path.mtu_validated or outstanding.expanded;
        return true;
    }

    /// Echoes a PATH_CHALLENGE this endpoint received (RFC 9000 §8.2.2): an endpoint MUST
    /// respond by echoing the data, on the path the challenge arrived on.
    pub fn response_for(data: [constants.path_challenge_len]u8) [constants.path_challenge_len]u8 {
        return data;
    }

    /// The instant RFC 9000 §8.2.4 abandons the outstanding attempt, or null while none is.
    pub fn challenge_deadline_ns(path: *const Path) ?u64 {
        const outstanding = path.challenge orelse return null;
        return outstanding.sent_ns +| outstanding.timeout_ns;
    }

    /// Abandons an attempt whose timer has run out (RFC 9000 §8.2.4), which is the only way
    /// path validation fails. Returns whether it was abandoned now.
    pub fn on_instant(path: *Path, now_ns: u64) bool {
        const outstanding = path.challenge orelse return false;
        assert(now_ns >= outstanding.sent_ns);
        if (now_ns - outstanding.sent_ns < outstanding.timeout_ns) return false;
        path.challenge = null;
        path.abandoned = true;
        return true;
    }

    /// Whether a second validation is owed, with a datagram large enough to test the MTU
    /// (RFC 9000 §8.2.1, §8.2.3).
    pub fn owes_mtu_validation(path: *const Path) bool {
        return path.validated and !path.mtu_validated;
    }
};

const testing = std.testing;

/// RFC 9000 §8.2.1's expansion, as the two answers a datagram can give to it: one that reached
/// "the smallest allowed maximum datagram size of 1200 bytes" and one that fell an octet short.
const expanded_len: usize = constants.datagram_len_min;
const small_len: usize = constants.datagram_len_min - 1;

/// The path the tests drive, and what they measure against. Test-only.
var test_path: Path = undefined;
const challenge_octet_a = 0xa5;
const challenge_octet_b = 0x5a;
const challenge_a: [constants.path_challenge_len]u8 = @splat(challenge_octet_a);
const challenge_b: [constants.path_challenge_len]u8 = @splat(challenge_octet_b);
const test_timeout_ns = 300_000_000;
const test_datagram = 100;

test "§8: an unvalidated path takes three times what it gave, and no more" {
    test_path.init(.unvalidated);
    // Nothing received, so nothing may be sent: an endpoint cannot amplify from zero.
    try testing.expectEqual(0, test_path.send_allowance());
    try testing.expect(test_path.is_amplification_limited(1));
    test_path.on_datagram_received(test_datagram);
    const allowance = constants.anti_amplification_factor * test_datagram;
    try testing.expectEqual(allowance, test_path.send_allowance());
    // RFC 9000 §8: three times what arrived may be sent, so exactly that much is permitted.
    try testing.expect(!test_path.is_amplification_limited(allowance));
    try testing.expect(test_path.is_amplification_limited(allowance + 1));
    test_path.on_datagram_sent(test_datagram);
    try testing.expectEqual(2 * test_datagram, test_path.send_allowance());
    test_path.on_datagram_sent(2 * test_datagram);
    try testing.expectEqual(0, test_path.send_allowance());
    try testing.expect(test_path.is_amplification_limited(1));
    // More arriving gives more room, in the same proportion.
    test_path.on_datagram_received(test_datagram);
    try testing.expectEqual(constants.anti_amplification_factor * test_datagram, test_path.send_allowance());
}

test "§21.1.1.1: a path that begins validated is unlimited from its first octet" {
    // The client's case. It has received nothing, so an unvalidated path would permit nothing.
    test_path.init(.validated);
    try testing.expectEqual(0, test_path.received);
    try testing.expectEqual(State.validated, test_path.state());
    try testing.expect(!test_path.is_amplification_limited(std.math.maxInt(u32)));
    // RFC 9000 §8.2.3 keeps the path MTU a separate question, which nothing here has settled.
    try testing.expect(!test_path.mtu_validated);
}

test "§8: a validated path has no limit" {
    test_path.init(.unvalidated);
    test_path.on_datagram_received(test_datagram);
    test_path.on_challenge_sent(challenge_a, expanded_len, 0, test_timeout_ns);
    // While the challenge is outstanding the limit still holds.
    try testing.expect(test_path.is_amplification_limited(constants.datagram_len_min));
    try testing.expect(test_path.on_response(challenge_a));
    try testing.expectEqual(State.validated, test_path.state());
    try testing.expect(!test_path.is_amplification_limited(std.math.maxInt(u32)));
    try testing.expect(!test_path.owes_mtu_validation());
}

test "§8.2.3: only the data of the challenge that went out validates the path" {
    test_path.init(.unvalidated);
    // A response with nothing outstanding validates nothing.
    try testing.expect(!test_path.on_response(challenge_a));
    try testing.expectEqual(State.unvalidated, test_path.state());
    test_path.on_challenge_sent(challenge_a, expanded_len, 0, test_timeout_ns);
    // RFC 9000 §8.2.3: the frame must carry the data of a PATH_CHALLENGE sent before.
    try testing.expect(!test_path.on_response(challenge_b));
    try testing.expectEqual(State.challenging, test_path.state());
    try testing.expect(test_path.on_response(challenge_a));
    // A second response changes nothing, because nothing is outstanding.
    try testing.expect(!test_path.on_response(challenge_a));
}

test "§8.2.3: a challenge in a small datagram validates the address and not the MTU" {
    test_path.init(.unvalidated);
    test_path.on_challenge_sent(challenge_a, small_len, 0, test_timeout_ns);
    try testing.expect(test_path.on_response(challenge_a));
    try testing.expectEqual(State.validated, test_path.state());
    // RFC 9000 §8.2.3: the endpoint MUST initiate another validation with an expanded datagram.
    try testing.expect(test_path.owes_mtu_validation());
    test_path.on_challenge_sent(challenge_b, expanded_len, 0, test_timeout_ns);
    try testing.expect(test_path.on_response(challenge_b));
    try testing.expect(!test_path.owes_mtu_validation());

    // A small datagram afterwards does not unsettle what the expanded one showed: §8.2.3 asks
    // for the path MTU to be verified once, not for every probe to verify it again.
    test_path.on_challenge_sent(challenge_a, small_len, 0, test_timeout_ns);
    try testing.expect(test_path.on_response(challenge_a));
    try testing.expect(!test_path.owes_mtu_validation());
}

test "§8.2.4: a challenge is abandoned on its timer, which is the only way it fails" {
    test_path.init(.unvalidated);
    test_path.on_challenge_sent(challenge_a, expanded_len, 0, test_timeout_ns);
    try testing.expect(!test_path.on_instant(test_timeout_ns - 1));
    try testing.expectEqual(State.challenging, test_path.state());
    try testing.expect(test_path.on_instant(test_timeout_ns));
    try testing.expectEqual(State.abandoned, test_path.state());
    // An abandoned path is not validated by a response that arrives afterwards.
    try testing.expect(!test_path.on_response(challenge_a));
    try testing.expectEqual(State.abandoned, test_path.state());
    // A path with nothing outstanding is not abandoned by time passing.
    test_path.init(.unvalidated);
    try testing.expect(!test_path.on_instant(std.math.maxInt(u32)));
    try testing.expectEqual(State.unvalidated, test_path.state());
    // Nor is a validated one.
    test_path.on_challenge_sent(challenge_a, expanded_len, 0, test_timeout_ns);
    _ = test_path.on_response(challenge_a);
    try testing.expect(!test_path.on_instant(std.math.maxInt(u32)));
    try testing.expectEqual(State.validated, test_path.state());
}

test "§8.2.1, §8.2.3: a validated path is challenged again and stays validated throughout" {
    test_path.init(.unvalidated);
    test_path.on_challenge_sent(challenge_a, small_len, 0, test_timeout_ns);
    try testing.expect(test_path.on_response(challenge_a));
    try testing.expect(test_path.owes_mtu_validation());
    // RFC 9000 §8.2.1: validation may be used at any time, so the second probe goes out while
    // the path is validated — and §8's limit stays lifted while it is outstanding.
    test_path.on_challenge_sent(challenge_b, expanded_len, 0, test_timeout_ns);
    try testing.expectEqual(State.validated, test_path.state());
    try testing.expect(!test_path.is_amplification_limited(std.math.maxInt(u32)));
    // A second probe that is abandoned does not unvalidate what the first showed.
    try testing.expect(test_path.on_instant(test_timeout_ns));
    try testing.expectEqual(State.validated, test_path.state());
    try testing.expect(test_path.owes_mtu_validation());
    // An unexpanded response after an expanded one does not take the MTU back either.
    test_path.on_challenge_sent(challenge_a, expanded_len, 0, test_timeout_ns);
    try testing.expect(test_path.on_response(challenge_a));
    test_path.on_challenge_sent(challenge_b, expanded_len, 0, test_timeout_ns);
    try testing.expect(test_path.on_response(challenge_b));
    try testing.expect(!test_path.owes_mtu_validation());
}

test "§8.2.2: a challenge is answered by echoing its data" {
    // RFC 9000 §8.2.2: an endpoint MUST respond by echoing the data it received.
    try testing.expectEqualSlices(u8, &challenge_a, &Path.response_for(challenge_a));
    try testing.expectEqualSlices(u8, &challenge_b, &Path.response_for(challenge_b));
}
