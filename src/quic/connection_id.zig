//! The connection IDs of one connection (RFC 9000 §5.1). Part of design §8 step 9d.
//!
//! Each endpoint holds two sets, and they are not symmetric. The ones the peer issued are what
//! this endpoint writes into the Destination Connection ID field it sends; the ones this
//! endpoint issued are what it accepts there. A NEW_CONNECTION_ID frame adds to the first and a
//! RETIRE_CONNECTION_ID frame retires from the second, so the two sets are worked on from
//! opposite directions and get their own type.
//!
//! §5.1.1's ordering is the part that is easy to get wrong, and it is written out in `offer`.
//! A frame carries a Retire Prior To, and §5.1.2 requires an endpoint to retire the connection
//! IDs below it **before** adding the one the frame carries. Doing it the other way round can
//! push the count past the peer's `active_connection_id_limit` for an instant, which §5.1.1
//! makes a CONNECTION_ID_LIMIT_ERROR — so the order is not housekeeping, it is the rule.
//!
//! A repeated frame is not an error. §19.15 says so outright, because retransmission makes it
//! ordinary: the same sequence number with the same connection ID changes nothing, while the
//! same sequence number with a different one is a PROTOCOL_VIOLATION.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const error_code = @import("error_code.zig");

/// One connection ID, with what RFC 9000 §5.1.1 and §19.15 attach to it.
pub const Entry = struct {
    sequence_number: u64,
    len: u8,
    octets: [constants.connection_id_len_max]u8,
    /// RFC 9000 §19.15: the token that resets a connection this ID names, invalidated when the
    /// ID is retired (§19.16).
    stateless_reset_token: [constants.stateless_reset_token_len]u8,

    pub fn value(entry: *const Entry) []const u8 {
        return entry.octets[0..entry.len];
    }
};

/// Why a frame about connection IDs ended the connection.
pub const Error = error{
    /// RFC 9000 §5.1.1: more active connection IDs than the endpoint's
    /// `active_connection_id_limit` permits.
    ConnectionIdLimitExceeded,
    /// RFC 9000 §19.15: the same sequence number was used for a different connection ID.
    SequenceNumberReused,
    /// RFC 9000 §19.16: a sequence number greater than any this endpoint ever issued.
    RetiredUnissued,
    /// RFC 9000 §19.15, §19.16: an endpoint using a zero-length connection ID received a frame
    /// about connection IDs, which it can have none of.
    ZeroLengthConnectionId,
};

/// RFC 9000 §20.1: the code each refusal closes the connection with.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        error.ConnectionIdLimitExceeded => error_code.connection_id_limit_error,
        error.SequenceNumberReused, error.RetiredUnissued, error.ZeroLengthConnectionId => error_code.protocol_violation,
    };
}

/// The connection IDs a peer issued, which this endpoint sends packets to (RFC 9000 §5.1.2).
pub const Remote = struct {
    /// Active entries, by the order they were offered. RFC 9000 §5.1.1: every one is valid for
    /// use at any time, in any packet type, until it is retired.
    entries: [constants.connection_ids_max]Entry,
    len: usize,
    /// The largest Retire Prior To the peer has sent, below which nothing is active (§5.1.2).
    retire_prior_to: u64,
    /// The largest sequence number offered, so a repeat is told from something new (§19.15).
    highest_offered: ?u64,
    /// Sequence numbers retired and not yet acknowledged by a RETIRE_CONNECTION_ID frame going
    /// out, which the caller drains (§5.1.2).
    retiring: [constants.connection_ids_max]u64,
    retiring_len: usize,
    /// Sequence numbers a RETIRE_CONNECTION_ID frame was already owed for, so §19.15's "unless
    /// it has already done so" holds after the queue above has drained.
    reported: [constants.connection_ids_max]u64,
    reported_len: usize,
    /// Whether the peer gave this endpoint a zero-length connection ID, which RFC 9000 §19.15
    /// and §19.16 make frames about connection IDs impossible under.
    zero_length: bool,

    pub fn init(remote: *Remote, zero_length: bool) void {
        remote.entries = undefined;
        remote.len = 0;
        remote.retire_prior_to = 0;
        remote.highest_offered = null;
        remote.retiring_len = 0;
        remote.reported = @splat(0);
        remote.reported_len = 0;
        remote.zero_length = zero_length;
    }

    pub fn active_len(remote: *const Remote) usize {
        return remote.len;
    }

    /// Takes a NEW_CONNECTION_ID frame (RFC 9000 §19.15). `limit` is this endpoint's
    /// `active_connection_id_limit` (§18.2), which §5.1.1 measures the result against.
    pub fn offer(remote: *Remote, entry: Entry, retire_prior_to: u64, limit: u64) Error!void {
        assert(retire_prior_to <= entry.sequence_number);
        assert(entry.len >= constants.connection_id_len_min and entry.len <= constants.connection_id_len_max);
        // RFC 9000 §19.15: an endpoint sending packets with a zero-length Destination Connection
        // ID treats receipt of a NEW_CONNECTION_ID frame as a connection error.
        if (remote.zero_length) return error.ZeroLengthConnectionId;
        if (try remote.is_active(entry)) return;
        // RFC 9000 §5.1.2: the connection IDs below Retire Prior To are retired **before** the
        // new one is added, so the count never passes the limit even for an instant.
        remote.raise_retire_prior_to(retire_prior_to);
        // RFC 9000 §19.15: an endpoint that receives a connection ID whose sequence number is
        // below a Retire Prior To it already saw MUST send a RETIRE_CONNECTION_ID for it,
        // unless it has already done so. It is never added back (§5.1.2).
        if (entry.sequence_number < remote.retire_prior_to) {
            remote.record_retiring(entry.sequence_number);
            return;
        }
        const past_limit = remote.len == remote.entries.len or remote.len + 1 > limit;
        // RFC 9000 §5.1.1: if the number of active connection IDs exceeds the value advertised
        // in its active_connection_id_limit, after adding and retiring, an endpoint MUST close
        // the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
        if (past_limit) return error.ConnectionIdLimitExceeded;
        remote.entries[remote.len] = entry;
        remote.len += 1;
        remote.highest_offered = @max(remote.highest_offered orelse 0, entry.sequence_number);
    }

    /// Whether this connection ID is one already active. RFC 9000 §19.15: the same frame
    /// arriving twice is ordinary and not an error, while the same sequence number carrying a
    /// different connection ID is a PROTOCOL_VIOLATION. A sequence number already retired is
    /// not answered here: §19.15 has it retired again, which `offer` does.
    fn is_active(remote: *const Remote, entry: Entry) Error!bool {
        for (remote.entries[0..remote.len]) |held| {
            if (held.sequence_number != entry.sequence_number) continue;
            const differs = !std.mem.eql(u8, held.value(), entry.value());
            // RFC 9000 §19.15: an endpoint MAY treat one sequence number used for different
            // connection IDs as a connection error of PROTOCOL_VIOLATION.
            if (differs) return error.SequenceNumberReused;
            return true;
        }
        return false;
    }

    /// Retires every active connection ID below `mark` (RFC 9000 §5.1.2).
    fn raise_retire_prior_to(remote: *Remote, mark: u64) void {
        if (mark <= remote.retire_prior_to) return;
        remote.retire_prior_to = mark;
        var index: usize = 0;
        // Each turn either drops an entry or steps past one, so the array bounds the walk.
        for (0..remote.entries.len) |_| {
            if (index == remote.len) return;
            if (remote.entries[index].sequence_number >= mark) {
                index += 1;
                continue;
            }
            remote.record_retiring(remote.entries[index].sequence_number);
            remote.remove(index);
        }
    }

    /// Owes a RETIRE_CONNECTION_ID frame for `sequence_number`, unless one is already owed or
    /// was already sent (RFC 9000 §19.15). `reported` remembers the recent ones, because the
    /// queue itself drains; past what it holds a duplicate frame can go out, which the peer
    /// takes as a retransmission the way §19.15 describes.
    fn record_retiring(remote: *Remote, sequence_number: u64) void {
        for (remote.reported[0..remote.reported_len]) |held| {
            if (held == sequence_number) return;
        }
        if (remote.reported_len == remote.reported.len) {
            for (1..remote.reported_len) |index| remote.reported[index - 1] = remote.reported[index];
            remote.reported_len -= 1;
        }
        remote.reported[remote.reported_len] = sequence_number;
        remote.reported_len += 1;
        if (remote.retiring_len == remote.retiring.len) return;
        remote.retiring[remote.retiring_len] = sequence_number;
        remote.retiring_len += 1;
    }

    fn remove(remote: *Remote, index: usize) void {
        assert(index < remote.len);
        for (index + 1..remote.len) |at| remote.entries[at - 1] = remote.entries[at];
        remote.len -= 1;
    }

    /// The sequence number of the next RETIRE_CONNECTION_ID frame this endpoint owes, or null
    /// when it owes none (RFC 9000 §5.1.2, §19.16).
    pub fn next_retire_frame(remote: *Remote) ?u64 {
        if (remote.retiring_len == 0) return null;
        const sequence_number = remote.retiring[0];
        for (1..remote.retiring_len) |index| remote.retiring[index - 1] = remote.retiring[index];
        remote.retiring_len -= 1;
        return sequence_number;
    }

    /// An active connection ID to send to, or null when the peer has left none. RFC 9000
    /// §5.1.1: any active one is valid at any time, in any packet type.
    pub fn active(remote: *const Remote) ?*const Entry {
        if (remote.len == 0) return null;
        return &remote.entries[0];
    }
};

/// One connection ID this endpoint issued, with the sequence number RFC 9000 §5.1.1 gives it.
/// The octets are kept because §19.16 asks which connection ID a packet was addressed to, and
/// only the octets on the wire can answer that.
pub const Issued = struct {
    sequence_number: u64,
    len: u8,
    octets: [constants.connection_id_len_max]u8,

    pub fn value(issued: *const Issued) []const u8 {
        return issued.octets[0..issued.len];
    }
};

/// The connection IDs this endpoint issued, which it accepts packets to (RFC 9000 §5.1.1).
pub const Local = struct {
    /// The sequence number of the next one issued. RFC 9000 §5.1.1: the first is 0 and each
    /// MUST increase by 1.
    next_sequence_number: u64,
    /// Those issued and not retired, with their octets.
    active: [constants.connection_ids_max]Issued,
    len: usize,
    /// Whether this endpoint issued a zero-length connection ID, under which RFC 9000 §19.16
    /// makes a RETIRE_CONNECTION_ID frame impossible.
    zero_length: bool,

    pub fn init(local: *Local, zero_length: bool) void {
        local.next_sequence_number = 0;
        local.active = @splat(.{ .sequence_number = 0, .len = 0, .octets = @splat(0) });
        local.len = 0;
        local.zero_length = zero_length;
    }

    /// Records one this endpoint issued, and returns its sequence number (RFC 9000 §5.1.1). The
    /// octets are the caller's: §5.1 wants a connection ID unpredictable and invariant 5 forbids
    /// colibri a random number.
    pub fn issue(local: *Local, octets: []const u8) ?u64 {
        assert(octets.len <= constants.connection_id_len_max);
        // RFC 9000 §5.1: a zero-length connection ID is issued once, by an endpoint that uses no
        // connection ID at all, and it is never one a RETIRE_CONNECTION_ID can name (§19.16).
        assert((octets.len == 0) == local.zero_length);
        if (local.len == local.active.len) return null;
        const sequence_number = local.next_sequence_number;
        var issued: Issued = .{ .sequence_number = sequence_number, .len = @intCast(octets.len), .octets = @splat(0) };
        @memcpy(issued.octets[0..octets.len], octets);
        local.active[local.len] = issued;
        local.len += 1;
        local.next_sequence_number = sequence_number + 1;
        return sequence_number;
    }

    /// The sequence number of the connection ID `octets` names, or null when this endpoint did
    /// not issue it or has retired it. RFC 9000 §19.16 asks it of the Destination Connection ID
    /// a packet carried, to refuse a frame retiring the very ID it arrived on.
    pub fn sequence_number_of(local: *const Local, octets: []const u8) ?u64 {
        // Bounded by the set, which §5.1.1 caps at the endpoint's active_connection_id_limit.
        for (local.active[0..local.len]) |issued| {
            if (std.mem.eql(u8, issued.value(), octets)) return issued.sequence_number;
        }
        return null;
    }

    /// Takes a RETIRE_CONNECTION_ID frame (RFC 9000 §19.16). `in_use` is the sequence number of
    /// the connection ID the packet carrying the frame was addressed to, which §19.16 forbids
    /// the frame from naming.
    pub fn retire(local: *Local, sequence_number: u64, in_use: ?u64) Error!void {
        // RFC 9000 §19.16: an endpoint that provides a zero-length connection ID treats receipt
        // of this frame as a connection error.
        if (local.zero_length) return error.ZeroLengthConnectionId;
        // RFC 9000 §19.16: a sequence number greater than any previously sent to the peer is a
        // connection error of PROTOCOL_VIOLATION.
        if (sequence_number >= local.next_sequence_number) return error.RetiredUnissued;
        // RFC 9000 §19.16: the frame must not name the Destination Connection ID of the packet
        // it arrived in.
        if (in_use != null and in_use.? == sequence_number) return error.RetiredUnissued;
        for (local.active[0..local.len], 0..) |held, index| {
            if (held.sequence_number != sequence_number) continue;
            for (index + 1..local.len) |at| {
                local.active[at - 1] = local.active[at];
            }
            local.len -= 1;
            return;
        }
        // Already retired: a retransmitted frame, which §19.15's reasoning covers.
    }

    pub fn active_len(local: *const Local) usize {
        return local.len;
    }
};

const testing = std.testing;

/// The sets the tests drive. Test-only.
var test_remote: Remote = undefined;
/// Connection IDs a test issues. RFC 9000 §5.1 wants them unpredictable and invariant 5 forbids
/// colibri a random number, so a test states them.
const issued_len: usize = 4;
const issued_a_octet: u8 = 0xa1;
const issued_b_octet: u8 = 0xb2;
const issued_c_octet: u8 = 0xc3;
const issued_a: [issued_len]u8 = @splat(issued_a_octet);
const issued_b: [issued_len]u8 = @splat(issued_b_octet);
const issued_c: [issued_len]u8 = @splat(issued_c_octet);
const issued_each = [_][]const u8{ &issued_a, &issued_b, &issued_c };

var test_local: Local = undefined;
/// A limit a test measures against, at the floor RFC 9000 §18.2 puts under it. Test-only.
const test_limit = constants.active_connection_id_limit_min;

/// Octets of the connection IDs the tests use. Test-only.
const test_connection_id_len = 4;

/// A connection ID whose octets are `seed` repeated, at sequence `sequence_number`. Test-only.
fn entry_of(sequence_number: u64, seed: u8) Entry {
    var entry: Entry = .{
        .sequence_number = sequence_number,
        .len = test_connection_id_len,
        .octets = @splat(0),
        .stateless_reset_token = @splat(seed),
    };
    for (entry.octets[0..entry.len]) |*octet| octet.* = seed;
    return entry;
}

test "§5.1.1: connection IDs the peer offers are active until they are retired" {
    test_remote.init(false);
    try testing.expectEqual(null, test_remote.active());
    try test_remote.offer(entry_of(1, 0xa1), 0, test_limit);
    try testing.expectEqual(1, test_remote.active_len());
    try testing.expectEqual(1, test_remote.active().?.sequence_number);
    try test_remote.offer(entry_of(2, 0xa2), 0, test_limit);
    try testing.expectEqual(2, test_remote.active_len());
    // RFC 9000 §19.15: the same frame arriving twice is ordinary and changes nothing.
    try test_remote.offer(entry_of(2, 0xa2), 0, test_limit);
    try testing.expectEqual(2, test_remote.active_len());
    // RFC 9000 §19.15: the same sequence number with a different connection ID is refused.
    try testing.expectError(error.SequenceNumberReused, test_remote.offer(entry_of(2, 0xbb), 0, test_limit));
}

test "§5.1.1: more active connection IDs than the limit ends the connection" {
    test_remote.init(false);
    try test_remote.offer(entry_of(1, 0xa1), 0, test_limit);
    try test_remote.offer(entry_of(2, 0xa2), 0, test_limit);
    // RFC 9000 §5.1.1: the third would pass a limit of two.
    try testing.expectError(error.ConnectionIdLimitExceeded, test_remote.offer(entry_of(3, 0xa3), 0, test_limit));
    // RFC 9000 §20.1: CONNECTION_ID_LIMIT_ERROR is 0x09.
    try testing.expectEqual(0x09, connection_error_code(error.ConnectionIdLimitExceeded));
}

test "§5.1.2: the ones below Retire Prior To go before the new one arrives" {
    test_remote.init(false);
    try test_remote.offer(entry_of(1, 0xa1), 0, test_limit);
    try test_remote.offer(entry_of(2, 0xa2), 0, test_limit);
    // A frame at the limit that retires both below it fits, because the retiring happens first.
    // Adding before retiring would make three active and fail §5.1.1.
    try test_remote.offer(entry_of(3, 0xa3), 3, test_limit);
    try testing.expectEqual(1, test_remote.active_len());
    try testing.expectEqual(3, test_remote.active().?.sequence_number);
    // RFC 9000 §5.1.2: the retired ones are named in RETIRE_CONNECTION_ID frames.
    try testing.expectEqual(1, test_remote.next_retire_frame().?);
    try testing.expectEqual(2, test_remote.next_retire_frame().?);
    try testing.expectEqual(null, test_remote.next_retire_frame());
    // RFC 9000 §19.15: one below the mark arriving late is retired rather than added back, and
    // a RETIRE_CONNECTION_ID frame is owed for it.
    try test_remote.offer(entry_of(0, 0xa0), 0, test_limit);
    try testing.expectEqual(1, test_remote.active_len());
    try testing.expectEqual(0, test_remote.next_retire_frame().?);
    // §19.15: unless it has already done so — the same late frame owes no second frame.
    try test_remote.offer(entry_of(0, 0xa0), 0, test_limit);
    try testing.expectEqual(null, test_remote.next_retire_frame());
    // And neither does one this endpoint already retired when the mark rose.
    try test_remote.offer(entry_of(1, 0xa1), 0, test_limit);
    try testing.expectEqual(null, test_remote.next_retire_frame());
}

test "§5.1.2: Retire Prior To retires below itself and keeps the one at it" {
    test_remote.init(false);
    try test_remote.offer(entry_of(1, 0xa1), 0, test_limit);
    try test_remote.offer(entry_of(2, 0xa2), 0, test_limit);
    // A frame at sequence 3 retiring prior to 2 drops sequence 1 and keeps sequence 2, which
    // is at the mark and not below it.
    try test_remote.offer(entry_of(3, 0xa3), 2, test_limit);
    try testing.expectEqual(2, test_remote.active_len());
    try testing.expectEqual(2, test_remote.active().?.sequence_number);
    try testing.expectEqual(1, test_remote.next_retire_frame().?);
    try testing.expectEqual(null, test_remote.next_retire_frame());
}

test "§19.15: an endpoint with a zero-length connection ID takes no such frame" {
    test_remote.init(true);
    try testing.expectError(error.ZeroLengthConnectionId, test_remote.offer(entry_of(1, 0xa1), 0, test_limit));
    // RFC 9000 §20.1: PROTOCOL_VIOLATION is 0x0a.
    try testing.expectEqual(0x0a, connection_error_code(error.ZeroLengthConnectionId));
}

test "§5.1.1: this endpoint's own connection IDs start at 0 and rise by one" {
    test_local.init(false);
    try testing.expectEqual(0, test_local.issue(&issued_a).?);
    try testing.expectEqual(1, test_local.issue(&issued_b).?);
    try testing.expectEqual(2, test_local.issue(&issued_c).?);
    try testing.expectEqual(3, test_local.active_len());
}

test "§19.16: a peer retires only what this endpoint issued, and not the one in use" {
    test_local.init(false);
    for (0..3) |index| _ = test_local.issue(issued_each[index]).?;
    // RFC 9000 §19.16: a sequence number greater than any issued is a connection error, and
    // the last one issued is not greater than any.
    try testing.expectError(error.RetiredUnissued, test_local.retire(3, null));
    try test_local.retire(2, null);
    try testing.expectEqual(2, test_local.active_len());
    // RFC 9000 §19.16: the frame must not name the connection ID its own packet was sent to.
    try testing.expectError(error.RetiredUnissued, test_local.retire(1, 1));
    try test_local.retire(1, 2);
    try testing.expectEqual(1, test_local.active_len());
    // A retransmitted frame retires nothing a second time and is no error.
    try test_local.retire(1, 2);
    try testing.expectEqual(1, test_local.active_len());
    // An endpoint that issued a zero-length connection ID cannot take the frame at all.
    test_local.init(true);
    try testing.expectError(error.ZeroLengthConnectionId, test_local.retire(0, null));
}
