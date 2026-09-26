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
const frame_latest = @import("frame/frame_latest.zig");

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
    /// `active_connection_id_limit` permits, or, under §5.1.2, more retired ones awaiting
    /// acknowledgment than `connection_ids_max`.
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
    /// Connection IDs retired and owed a RETIRE_CONNECTION_ID frame, until the peer acknowledges
    /// one (§5.1.2, §13.3).
    retiring: [constants.connection_ids_max]Retirement,
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

    /// Takes the connection ID the peer put in the Source Connection ID field of its first
    /// packets, which RFC 9000 §5.1.1 gives sequence number 0. It is active like any other: it
    /// counts against the limit, and a Retire Prior To above 0 retires it (§5.1.2). A peer that
    /// sent a zero-length one has no other to offer (§19.15). The ID carries no Stateless Reset
    /// Token here: §10.3 gives a client's none, and a server's travels in its transport
    /// parameters (§18.2).
    pub fn hold_initial(remote: *Remote, octets: []const u8) void {
        assert(remote.len == 0);
        assert(octets.len <= constants.connection_id_len_max);
        if (octets.len == 0) {
            remote.zero_length = true;
            return;
        }
        var entry: Entry = .{
            .sequence_number = 0,
            .len = @intCast(octets.len),
            .octets = @splat(0),
            .stateless_reset_token = @splat(0),
        };
        @memcpy(entry.octets[0..octets.len], octets);
        remote.entries[0] = entry;
        remote.len = 1;
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
        try remote.raise_retire_prior_to(retire_prior_to);
        // RFC 9000 §19.15: an endpoint that receives a connection ID whose sequence number is
        // below a Retire Prior To it already saw MUST send a RETIRE_CONNECTION_ID for it,
        // unless it has already done so. It is never added back (§5.1.2).
        if (entry.sequence_number < remote.retire_prior_to) {
            try remote.record_retiring(entry.sequence_number);
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
    fn raise_retire_prior_to(remote: *Remote, mark: u64) Error!void {
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
            try remote.record_retiring(remote.entries[index].sequence_number);
            remote.remove(index);
        }
    }

    /// Owes a RETIRE_CONNECTION_ID frame for `sequence_number`, unless one is already owed or
    /// was already sent (RFC 9000 §19.15). `reported` remembers the recent ones, because the
    /// queue itself drains; past what it holds a duplicate frame can go out, which the peer
    /// takes as a retransmission the way §19.15 describes.
    fn record_retiring(remote: *Remote, sequence_number: u64) Error!void {
        for (remote.reported[0..remote.reported_len]) |held| {
            if (held == sequence_number) return;
        }
        if (remote.reported_len == remote.reported.len) {
            for (1..remote.reported_len) |index| remote.reported[index - 1] = remote.reported[index];
            remote.reported_len -= 1;
        }
        // RFC 9000 §5.1.2: "An endpoint MUST NOT forget a connection ID without retiring it,
        // though it MAY choose to treat having connection IDs in need of retirement that exceed
        // this limit as a connection error of type CONNECTION_ID_LIMIT_ERROR."
        if (remote.retiring_len == remote.retiring.len) return error.ConnectionIdLimitExceeded;
        remote.reported[remote.reported_len] = sequence_number;
        remote.reported_len += 1;
        remote.retiring[remote.retiring_len] = .{ .sequence_number = sequence_number, .frame = .{ .owed = true } };
        remote.retiring_len += 1;
    }

    fn remove(remote: *Remote, index: usize) void {
        assert(index < remote.len);
        for (index + 1..remote.len) |at| remote.entries[at - 1] = remote.entries[at];
        remote.len -= 1;
    }

    /// The retirements this endpoint has yet to see acknowledged, whose frames the send path
    /// writes (RFC 9000 §5.1.2, §19.16).
    pub fn retirements(remote: *Remote) []Retirement {
        return remote.retiring[0..remote.retiring_len];
    }

    /// Drops every retirement whose most recent RETIRE_CONNECTION_ID packet `number` carried: the
    /// peer has it, and nothing more is owed.
    pub fn on_packet_acknowledged(remote: *Remote, number: u64) void {
        var index: usize = 0;
        // Each turn either drops an entry or steps past one, so the array bounds the walk.
        for (0..remote.retiring.len) |_| {
            if (index == remote.retiring_len) return;
            if (!remote.retiring[index].frame.carried_by(number)) {
                index += 1;
                continue;
            }
            for (index + 1..remote.retiring_len) |at| remote.retiring[at - 1] = remote.retiring[at];
            remote.retiring_len -= 1;
        }
    }

    /// Owes again each RETIRE_CONNECTION_ID frame whose most recent copy packet `number` carried
    /// (RFC 9000 §13.3: "retired connection IDs are sent in RETIRE_CONNECTION_ID frames and
    /// retransmitted if the packet containing them is lost").
    pub fn on_packet_lost(remote: *Remote, number: u64) void {
        for (remote.retiring[0..remote.retiring_len]) |*retirement| retirement.frame.on_lost(number);
    }

    /// An active connection ID to send to, or null when the peer has left none. RFC 9000
    /// §5.1.1: any active one is valid at any time, in any packet type.
    pub fn active(remote: *const Remote) ?*const Entry {
        if (remote.len == 0) return null;
        return &remote.entries[0];
    }
};

/// A connection ID this endpoint retired, and the RETIRE_CONNECTION_ID frame that tells the peer
/// (RFC 9000 §19.16).
pub const Retirement = struct {
    sequence_number: u64,
    frame: frame_latest.Latest,
};

/// One connection ID this endpoint issued, with the sequence number RFC 9000 §5.1.1 gives it.
/// The octets are kept because §19.16 asks which connection ID a packet was addressed to, and
/// only the octets on the wire can answer that.
pub const Issued = struct {
    sequence_number: u64,
    len: u8,
    octets: [constants.connection_id_len_max]u8,
    /// The Stateless Reset Token its NEW_CONNECTION_ID frame carries (RFC 9000 §19.15), which the
    /// caller derives: §10.3.2 derives one from a key, and colibri holds none (non-negotiable 2).
    stateless_reset_token: [constants.stateless_reset_token_len]u8,
    /// The NEW_CONNECTION_ID frame that tells the peer of it. §13.3: "New connection IDs are sent
    /// in NEW_CONNECTION_ID frames and retransmitted if the packet containing them is lost."
    new_frame: frame_latest.Latest,

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
        local.active = @splat(.{
            .sequence_number = 0,
            .len = 0,
            .octets = @splat(0),
            .stateless_reset_token = @splat(0),
            .new_frame = .{},
        });
        local.len = 0;
        local.zero_length = zero_length;
    }

    /// Records one this endpoint issued, and returns its sequence number (RFC 9000 §5.1.1). The
    /// octets are the caller's: §5.1 wants a connection ID unpredictable and invariant 5 forbids
    /// colibri a random number. Every one after the first owes a NEW_CONNECTION_ID frame carrying
    /// `token`; the first went out in the handshake's Source Connection ID field (§5.1.1).
    pub fn issue(local: *Local, octets: []const u8, token: ?*const [constants.stateless_reset_token_len]u8) ?u64 {
        assert(octets.len <= constants.connection_id_len_max);
        // RFC 9000 §5.1: a zero-length connection ID is issued once, by an endpoint that uses no
        // connection ID at all, and it is never one a RETIRE_CONNECTION_ID can name (§19.16).
        assert((octets.len == 0) == local.zero_length);
        if (local.len == local.active.len) return null;
        const sequence_number = local.next_sequence_number;
        assert((token == null) == (sequence_number == 0));
        var issued: Issued = .{
            .sequence_number = sequence_number,
            .len = @intCast(octets.len),
            .octets = @splat(0),
            .stateless_reset_token = if (token) |held| held.* else @splat(0),
            .new_frame = .{ .owed = token != null },
        };
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

    /// The connection IDs issued and not retired, whose NEW_CONNECTION_ID frames the send path
    /// writes.
    pub fn active_ids(local: *Local) []Issued {
        return local.active[0..local.len];
    }

    /// Owes again each NEW_CONNECTION_ID frame whose most recent copy packet `number` carried
    /// (RFC 9000 §13.3). "Retransmissions of this frame carry the same sequence number value",
    /// which the entry keeps.
    pub fn on_packet_lost(local: *Local, number: u64) void {
        for (local.active[0..local.len]) |*held| held.new_frame.on_lost(number);
    }
};

test {
    _ = @import("connection_id_test.zig");
}
