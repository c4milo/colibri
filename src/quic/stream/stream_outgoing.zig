//! The offsets of what this endpoint sends on one stream (RFC 9000 §2.2, §3.1, §4.5). Part of
//! design §8 step 9e.
//!
//! colibri holds none of the octets. The caller keeps them and a stream provider reads them back
//! ([decision 57](../../../docs/decisions.md)), so what a stream holds here is four numbers: how
//! far the caller's octets reach, how far colibri has framed them, how many the peer has
//! acknowledged, and whether the stream ends where the caller's octets do.
//!
//! **The acknowledged count is exact because each octet is in one place.** An octet colibri has
//! framed is in one packet in flight, in the lost table, or acknowledged, and never in two
//! ([invariant 29](../../../docs/invariants.md)). So adding each acknowledged range once counts
//! each octet once, in whatever order the acknowledgments arrive.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Error = error{
    /// RFC 9000 §19.8: the sum of a STREAM frame's offset and length "cannot exceed 2^62-1", so a
    /// stream cannot reach past it. Nothing changed.
    OffsetTooLarge,
};

pub const Outgoing = struct {
    /// One past the last octet the caller has supplied, which the stream provider can read.
    supplied_end: u64 = 0,
    /// One past the last octet framed at least once. From here to `supplied_end`, nothing has
    /// gone out.
    framed_end: u64 = 0,
    /// Octets the peer has acknowledged, each counted once.
    acknowledged_len: u64 = 0,
    /// Whether the caller ended the stream at `supplied_end`, which fixes the final size (RFC 9000
    /// §4.5).
    finished: bool = false,
    /// Whether a STREAM frame carrying the FIN went out, and whether the peer acknowledged one.
    fin_framed: bool = false,
    fin_acknowledged: bool = false,

    /// Raises how far the caller's octets reach to `end`, and ends the stream there when `fin` is
    /// set. The octets stay the caller's (decision 57).
    pub fn supply(outgoing: *Outgoing, end: u64, fin: bool) Error!void {
        // RFC 9000 §4.5: once the final size is known it does not change, and a caller that ended
        // the stream has nothing more to supply.
        assert(!outgoing.finished);
        assert(end >= outgoing.supplied_end);
        // RFC 9000 §19.8: an offset past 2^62-1 cannot be written in a STREAM frame.
        if (end > constants.stream_offset_max) return Error.OffsetTooLarge;
        outgoing.supplied_end = end;
        outgoing.finished = fin;
    }

    /// Octets the caller supplied that have never been framed.
    pub fn unframed_len(outgoing: *const Outgoing) u64 {
        assert(outgoing.framed_end <= outgoing.supplied_end);
        return outgoing.supplied_end - outgoing.framed_end;
    }

    /// Whether the FIN is still to go out for the first time (RFC 9000 §3.1: the FIN is what
    /// enters "Data Sent").
    pub fn owes_fin(outgoing: *const Outgoing) bool {
        return outgoing.finished and !outgoing.fin_framed;
    }

    /// Records that a STREAM frame carried the next `len` unframed octets, and the FIN with them
    /// when `fin` is set.
    pub fn on_framed(outgoing: *Outgoing, len: u64, fin: bool) void {
        assert(len <= outgoing.unframed_len());
        outgoing.framed_end += len;
        if (!fin) return;
        // RFC 9000 §4.5: the FIN marks the final size, so it goes out with the last octet or
        // after it, never before.
        assert(outgoing.finished and outgoing.framed_end == outgoing.supplied_end);
        outgoing.fin_framed = true;
    }

    /// Counts `len` octets the peer acknowledged, and the FIN when `fin` is set.
    pub fn on_acknowledged(outgoing: *Outgoing, len: u64, fin: bool) void {
        outgoing.acknowledged_len += len;
        // Invariant 29: each octet is counted once, so the count never passes what was framed.
        assert(outgoing.acknowledged_len <= outgoing.framed_end);
        if (!fin) return;
        assert(outgoing.fin_framed);
        outgoing.fin_acknowledged = true;
    }

    /// RFC 9000 §3.1: "Once all stream data has been successfully acknowledged, the sending part
    /// of the stream enters the "Data Recvd" state". All of it means every octet and the FIN.
    pub fn is_all_acknowledged(outgoing: *const Outgoing) bool {
        // An acknowledged FIN was framed, and only an ended stream frames one.
        if (!outgoing.fin_acknowledged) return false;
        return outgoing.acknowledged_len == outgoing.supplied_end;
    }
};

const testing = std.testing;

/// How many octets the tests supply, in two halves. Test-only.
const test_len: u64 = 1_000;
const test_half_len: u64 = 500;

test "§3.1: a stream is all acknowledged once every octet and the FIN are" {
    var outgoing: Outgoing = .{};
    try outgoing.supply(test_len, true);
    try testing.expectEqual(test_len, outgoing.unframed_len());
    try testing.expect(outgoing.owes_fin());
    outgoing.on_framed(test_half_len, false);
    outgoing.on_framed(test_half_len, true);
    try testing.expectEqual(0, outgoing.unframed_len());
    try testing.expect(!outgoing.owes_fin());

    // The second half and the FIN arrive first, which the count does not mind.
    outgoing.on_acknowledged(test_half_len, true);
    try testing.expect(!outgoing.is_all_acknowledged());
    outgoing.on_acknowledged(test_half_len, false);
    try testing.expect(outgoing.is_all_acknowledged());
}

test "§3.1: every octet acknowledged is not all, while the FIN is not" {
    var outgoing: Outgoing = .{};
    try outgoing.supply(test_len, true);
    outgoing.on_framed(test_len, false);
    outgoing.on_acknowledged(test_len, false);
    try testing.expect(!outgoing.is_all_acknowledged());
    // §4.5: a FIN may go out alone, after the last octet, and it is what completes the stream.
    outgoing.on_framed(0, true);
    outgoing.on_acknowledged(0, true);
    try testing.expect(outgoing.is_all_acknowledged());
}

test "§3.1: a stream the caller has not ended is never all acknowledged" {
    var outgoing: Outgoing = .{};
    try outgoing.supply(test_len, false);
    try testing.expect(!outgoing.owes_fin());
    outgoing.on_framed(test_len, false);
    outgoing.on_acknowledged(test_len, false);
    try testing.expect(!outgoing.is_all_acknowledged());
    // More octets reach further, and the stream can still be ended after them.
    try outgoing.supply(test_len + test_half_len, true);
    try testing.expectEqual(test_half_len, outgoing.unframed_len());
}

test "§19.8: a stream cannot reach past 2^62-1" {
    var outgoing: Outgoing = .{};
    try testing.expectError(Error.OffsetTooLarge, outgoing.supply(constants.stream_offset_max + 1, false));
    try testing.expectEqual(0, outgoing.supplied_end);
    try outgoing.supply(constants.stream_offset_max, true);
    try testing.expect(outgoing.finished);
}
