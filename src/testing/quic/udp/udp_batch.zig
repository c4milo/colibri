//! The segmented sends of the UDP server's `h3` mode (UDP_SEGMENT, design §8 step 13f.6). Each
//! turn, the server takes every datagram the endpoint owes and adds it to a batch for its peer and
//! its codepoint. The endpoint takes its connections in turn, so two datagrams in a row seldom go
//! to one peer, and a batch for each peer collects them. Each open batch then goes to the kernel
//! as one send, which cuts it into datagrams of the batch's first length.
//!
//! The kernel requires each segment but the last to have one length, so a datagram longer than
//! the first one starts a new batch, and a shorter one closes its batch. On macOS, which has no
//! UDP_SEGMENT, each batch holds one datagram.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("../../constants.zig");

/// Whether the kernel cuts a send into segments: Linux alone.
pub const segmented = builtin.os.tag == .linux;

const Peer = @FieldType(server.Sent, "to");
const Ecn = @FieldType(server.Sent, "ecn");

pub const Batch = struct {
    bytes: [constants.udp_segmented_bytes_max]u8 = undefined,
    len: usize = 0,
    /// The length of the batch's first datagram, which each segment but the last has.
    segment_len: usize = 0,
    count: usize = 0,
    /// Whether the batch takes no more datagrams: its last one was shorter than the first.
    closed: bool = false,
    to: Peer = undefined,
    ecn: Ecn = undefined,
    state: State = .free,

    pub const State = enum { free, open, sending };

    /// The octets each segment holds, for the send's `segment_bytes`: 0 for a batch of one
    /// datagram, which the kernel sends as it is.
    pub fn segment_bytes(batch: *const Batch) u16 {
        return if (batch.count > 1) @intCast(batch.segment_len) else 0;
    }

    fn takes(batch: *const Batch, sent: server.Sent) bool {
        if (batch.state != .open or batch.closed) return false;
        if (batch.count == constants.udp_segments_max) return false;
        if (sent.bytes.len > batch.segment_len or batch.len + sent.bytes.len > batch.bytes.len) return false;
        return batch.ecn == sent.ecn and batch.to.eql(&sent.to);
    }

    fn append(batch: *Batch, sent: server.Sent) void {
        assert(batch.state == .open and sent.bytes.len > 0);
        @memcpy(batch.bytes[batch.len..][0..sent.bytes.len], sent.bytes);
        batch.len += sent.bytes.len;
        batch.count += 1;
        batch.closed = !segmented or sent.bytes.len < batch.segment_len;
    }
};

pub const Batches = struct {
    batches: [constants.udp_batches]Batch = @splat(.{}),

    /// Whether a batch is free, so that a datagram the endpoint gives now has a place.
    pub fn has_free(batches: *const Batches) bool {
        for (&batches.batches) |*batch| {
            if (batch.state == .free) return true;
        }
        return false;
    }

    /// Adds `sent` to the open batch for its peer and its codepoint, or to a free batch. A free
    /// batch must exist (`has_free`).
    pub fn add(batches: *Batches, sent: server.Sent) void {
        for (&batches.batches) |*batch| {
            if (batch.takes(sent)) return batch.append(sent);
        }
        for (&batches.batches) |*batch| {
            if (batch.state != .free) continue;
            batch.* = .{ .segment_len = sent.bytes.len, .to = sent.to, .ecn = sent.ecn, .state = .open };
            return batch.append(sent);
        }
        unreachable;
    }

    /// Gives a batch back once its send's event arrived.
    pub fn release(batches: *Batches, index: usize) void {
        assert(batches.batches[index].state == .sending);
        batches.batches[index].state = .free;
    }
};

/// The datagrams of one delivery: the delivery itself, or each segment of one the kernel coalesced
/// (UDP_GRO), each of `segment_bytes` but the last, which may be shorter.
pub const Segments = struct {
    bytes: []u8,
    segment_len: usize,
    offset: usize = 0,

    pub fn of(bytes: []u8, segment_bytes: u16) Segments {
        return .{ .bytes = bytes, .segment_len = if (segment_bytes == 0) bytes.len else segment_bytes };
    }

    pub fn next(segments: *Segments) ?[]u8 {
        if (segments.offset == segments.bytes.len) return null;
        const start = segments.offset;
        segments.offset = @min(start + segments.segment_len, segments.bytes.len);
        return segments.bytes[start..segments.offset];
    }
};

const testing = std.testing;

/// Two peers and the datagrams a test adds. Test-only.
const loopback_word: u32 = 0x7f00_0001;
const loopback: [@sizeOf(u32)]u8 = @bitCast(std.mem.nativeToBig(u32, loopback_word));
const port_a: u16 = 1;
const port_b: u16 = 2;
const peer_a = Peer.of(&loopback, port_a);
const peer_b = Peer.of(&loopback, port_b);
const full_len = 1200;
const short_len = 100;
const full: [full_len]u8 = @splat('f');
const short: [short_len]u8 = @splat('s');

fn sent_of(bytes: []const u8, to: Peer) server.Sent {
    return .{ .bytes = bytes, .ecn = .not_ect, .to = to };
}

fn open_count(batches: *const Batches) usize {
    var count: usize = 0;
    for (&batches.batches) |*batch| count += @intFromBool(batch.state == .open);
    return count;
}

test "design §8 step 13f.6: datagrams of one peer join one batch, and another peer's start another" {
    var batches: Batches = .{};
    batches.add(sent_of(&full, peer_a));
    batches.add(sent_of(&full, peer_b));
    batches.add(sent_of(&full, peer_a));
    batches.add(sent_of(&short, peer_a));
    if (!segmented) return testing.expectEqual(4, open_count(&batches));
    try testing.expectEqual(2, open_count(&batches));
    const first = &batches.batches[0];
    try testing.expectEqual(3, first.count);
    try testing.expectEqual(2 * full.len + short.len, first.len);
    try testing.expectEqual(full.len, first.segment_bytes());
    // The shorter datagram closed the batch, so the next one of peer A starts another.
    batches.add(sent_of(&full, peer_a));
    try testing.expectEqual(3, open_count(&batches));
    try testing.expectEqual(0, batches.batches[1].segment_bytes());
}

test "design §8 step 13f.6: a longer datagram starts a batch, and a full batch takes no more" {
    var batches: Batches = .{};
    batches.add(sent_of(&short, peer_a));
    batches.add(sent_of(&full, peer_a));
    try testing.expectEqual(2, open_count(&batches));
    if (!segmented) return;
    batches = .{};
    for (0..constants.udp_segments_max) |_| batches.add(sent_of(&short, peer_a));
    try testing.expectEqual(1, open_count(&batches));
    try testing.expectEqual(constants.udp_segments_max, batches.batches[0].count);
    batches.add(sent_of(&short, peer_a));
    try testing.expectEqual(2, open_count(&batches));
}

test "design §8 step 13f.6: a batch holds no more octets than one send carries" {
    if (!segmented) return;
    var batches: Batches = .{};
    const per_batch = constants.udp_segmented_bytes_max / full.len;
    for (0..per_batch + 1) |_| batches.add(sent_of(&full, peer_a));
    try testing.expectEqual(2, open_count(&batches));
    try testing.expectEqual(per_batch, batches.batches[0].count);
}

test "design §8 step 13f.6: a sending batch takes nothing, and is free once released" {
    var batches: Batches = .{};
    batches.add(sent_of(&full, peer_a));
    batches.batches[0].state = .sending;
    batches.add(sent_of(&full, peer_a));
    try testing.expectEqual(1, open_count(&batches));
    try testing.expectEqual(Batch.State.open, batches.batches[1].state);
    batches.release(0);
    try testing.expect(batches.has_free());
    try testing.expectEqual(Batch.State.free, batches.batches[0].state);
}

/// The segment length of the coalesced delivery the test splits. Test-only.
const test_segment_bytes: u16 = 4;

test "design §8 step 13f.6: a coalesced delivery splits into its segments, and a plain one stays whole" {
    var coalesced = "aaaabbbbcc".*;
    var segments = Segments.of(&coalesced, test_segment_bytes);
    try testing.expectEqualStrings("aaaa", segments.next().?);
    try testing.expectEqualStrings("bbbb", segments.next().?);
    try testing.expectEqualStrings("cc", segments.next().?);
    try testing.expectEqual(null, segments.next());
    var plain = Segments.of(&coalesced, 0);
    try testing.expectEqualStrings(&coalesced, plain.next().?);
    try testing.expectEqual(null, plain.next());
}

test "design §8 step 13f.6: datagrams of one peer with another codepoint start another batch" {
    var batches: Batches = .{};
    batches.add(sent_of(&full, peer_a));
    batches.add(.{ .bytes = &full, .ecn = .ect_0, .to = peer_a });
    try testing.expectEqual(2, open_count(&batches));
    try testing.expectEqual(Ecn.ect_0, batches.batches[1].ecn);
}
