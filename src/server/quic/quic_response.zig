//! What one h3 response holds until the peer acknowledges it (decisions 79 and 103): the frames the
//! connection keeps, and the runs of the caller's octets `write_body` took, which stay the
//! caller's. QUIC reads the stream back by offset through the stream provider, as often as it
//! resends a lost run (decision 57), so a run leaves only once every octet of it is acknowledged
//! (RFC 9000 §3.1).
//!
//! The kept frames sit in `kept` in stream order, so the runs acknowledged first are at its front,
//! and dropping them moves the rest down.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// One run of the stream's octets: kept frames, or the caller's octets.
pub const Piece = struct {
    /// Where the run starts on the stream, and its length.
    offset: u64,
    len: usize,
    /// The caller's octets, or null for kept frames, which start at `kept_start` in `kept`.
    caller: ?[*]const u8,
    kept_start: usize,

    fn end(piece: Piece) u64 {
        return piece.offset + piece.len;
    }
};

pub const Pieces = struct {
    kept: [constants.quic_response_kept_len]u8,
    kept_len: usize,
    runs: [constants.quic_response_pieces_max]Piece,
    runs_len: usize,
    /// One past the stream's last octet the runs hold.
    end: u64,

    pub fn init(pieces: *Pieces) void {
        pieces.kept_len = 0;
        pieces.runs_len = 0;
        pieces.end = 0;
    }

    /// Where the next kept frame is written.
    pub fn kept_room(pieces: *Pieces) []u8 {
        return pieces.kept[pieces.kept_len..];
    }

    /// Whether a run can be added.
    pub fn has_room(pieces: *const Pieces) bool {
        return pieces.runs_len < pieces.runs.len;
    }

    /// Adds the `len` octets just written at the front of `kept_room` as the stream's next run.
    pub fn add_kept(pieces: *Pieces, len: usize) void {
        assert(pieces.has_room());
        assert(len > 0 and len <= pieces.kept.len - pieces.kept_len);
        pieces.runs[pieces.runs_len] = .{ .offset = pieces.end, .len = len, .caller = null, .kept_start = pieces.kept_len };
        pieces.runs_len += 1;
        pieces.kept_len += len;
        pieces.end += len;
    }

    /// Adds the caller's `octets` as the stream's next run. They stay the caller's, and are read
    /// in place until the peer acknowledges them.
    pub fn add_caller(pieces: *Pieces, octets: []const u8) void {
        assert(pieces.has_room());
        assert(octets.len > 0);
        pieces.runs[pieces.runs_len] = .{ .offset = pieces.end, .len = octets.len, .caller = octets.ptr, .kept_start = 0 };
        pieces.runs_len += 1;
        pieces.end += octets.len;
    }

    /// Drops every run below `acknowledged`, the offset under which the peer has acknowledged
    /// every octet, and moves the kept frames after them down to the front of `kept`. Returns the
    /// octets of the caller's runs dropped, which a coded response frees from its ring.
    pub fn release_below(pieces: *Pieces, acknowledged: u64) usize {
        assert(acknowledged <= pieces.end);
        var dropped: usize = 0;
        var kept_dropped: usize = 0;
        var caller_dropped: usize = 0;
        for (pieces.runs[0..pieces.runs_len]) |run| {
            if (run.end() > acknowledged) break;
            if (run.caller == null) kept_dropped += run.len else caller_dropped += run.len;
            dropped += 1;
        }
        if (dropped == 0) return 0;
        const rest = pieces.runs_len - dropped;
        std.mem.copyForwards(Piece, pieces.runs[0..rest], pieces.runs[dropped..pieces.runs_len]);
        pieces.runs_len = rest;
        std.mem.copyForwards(u8, pieces.kept[0 .. pieces.kept_len - kept_dropped], pieces.kept[kept_dropped..pieces.kept_len]);
        pieces.kept_len -= kept_dropped;
        for (pieces.runs[0..rest]) |*run| {
            if (run.caller == null) run.kept_start -= kept_dropped;
        }
        return caller_dropped;
    }

    /// The stream's octets from `offset`, as many as fit `output`. Every call at one offset answers
    /// the same octets, which RFC 9000 §2.2 asks of a retransmission.
    pub fn read(pieces: *const Pieces, offset: u64, output: []u8) usize {
        var written: usize = 0;
        for (pieces.runs[0..pieces.runs_len]) |run| {
            const at = offset + written;
            if (written == output.len) break;
            if (run.end() <= at) continue;
            // A run below the first held is acknowledged, and QUIC never reads it again.
            if (at < run.offset) break;
            const from: usize = @intCast(at - run.offset);
            const len = @min(output.len - written, run.len - from);
            @memcpy(output[written..][0..len], run_octets(pieces, run)[from..][0..len]);
            written += len;
        }
        return written;
    }

    fn run_octets(pieces: *const Pieces, run: Piece) []const u8 {
        if (run.caller) |octets| return octets[0..run.len];
        return pieces.kept[run.kept_start..][0..run.len];
    }
};

const testing = std.testing;

/// The pieces the tests fill. Test-only.
threadlocal var test_pieces: Pieces align(@alignOf(Pieces)) = undefined;

/// Adds `frame` as a kept run of `pieces`. Test-only.
fn test_keep(pieces: *Pieces, frame: []const u8) void {
    @memcpy(pieces.kept_room()[0..frame.len], frame);
    pieces.add_kept(frame.len);
}

test "decision 103: a stream reads as its kept frames and the caller's octets in order, from any offset" {
    const pieces = &test_pieces;
    pieces.init();
    test_keep(pieces, "HEAD");
    pieces.add_caller("hello");
    test_keep(pieces, "DH");
    pieces.add_caller("world");
    try testing.expectEqual(16, pieces.end);
    var output: [32]u8 = undefined;
    try testing.expectEqualStrings("HEADhelloDHworld", output[0..pieces.read(0, &output)]);
    // RFC 9000 §2.2: a resend at one offset reads the same octets, across runs.
    try testing.expectEqualStrings("lloDHw", output[0..pieces.read(6, output[0..6])]);
    try testing.expectEqual(0, pieces.read(16, &output));
}

test "decision 103: acknowledged runs leave, and the kept frames after them move down" {
    const pieces = &test_pieces;
    pieces.init();
    test_keep(pieces, "HEAD");
    pieces.add_caller("hello");
    test_keep(pieces, "DH");
    pieces.add_caller("world");
    // A run partly acknowledged stays whole.
    try testing.expectEqual(0, pieces.release_below(6));
    try testing.expectEqual(3, pieces.runs_len);
    try testing.expectEqual(2, pieces.kept_len);
    // A frame kept next lands where the dropped ones were, so a run read from its old place shows.
    test_keep(pieces, "TRAILERS");
    var output: [32]u8 = undefined;
    try testing.expectEqualStrings("helloDHworldTRAILERS", output[0..pieces.read(4, &output)]);
    // The octets below the first run held are acknowledged, and read as none.
    try testing.expectEqual(0, pieces.read(0, &output));
    // The caller's octets dropped are "hello" and "world"; the kept frames are not the caller's.
    try testing.expectEqual(10, pieces.release_below(pieces.end));
    try testing.expectEqual(0, pieces.runs_len);
    try testing.expectEqual(0, pieces.kept_len);
    test_keep(pieces, "END");
    try testing.expectEqualStrings("END", output[0..pieces.read(24, &output)]);
}
