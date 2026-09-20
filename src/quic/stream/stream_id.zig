//! Stream identifiers (RFC 9000 §2.1). A stream ID is a 62-bit integer whose two low bits say
//! who opened the stream and whether it carries data one way or both, and whose remaining bits
//! are that type's own counter.
//!
//! Reading the two bits in one place is the point. Everything else in `quic` asks which endpoint
//! initiated a stream and whether it is bidirectional, and none of it reads a bit out of a
//! number to find out.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// Which endpoint opened a stream (RFC 9000 §2.1).
pub const Initiator = enum(u1) {
    client = 0,
    server = 1,

    pub fn peer(initiator: Initiator) Initiator {
        return if (initiator == .client) .server else .client;
    }
};

/// Whether a stream carries data both ways or one (RFC 9000 §2.1).
pub const Directionality = enum(u1) {
    bidirectional = 0,
    unidirectional = 1,
};

/// One of the four types of Table 1 (RFC 9000 §2.1).
pub const StreamId = struct {
    value: u64,

    /// RFC 9000 §2.1: the least significant bit identifies the initiator, and the second
    /// least significant distinguishes bidirectional from unidirectional.
    pub fn initiator(id: StreamId) Initiator {
        return @enumFromInt(@as(u1, @truncate(id.value & constants.stream_id_initiator_bit)));
    }

    pub fn directionality(id: StreamId) Directionality {
        const bit = (id.value & constants.stream_id_directionality_bit) >> constants.stream_id_directionality_shift;
        return @enumFromInt(@as(u1, @truncate(bit)));
    }

    /// The stream's position among those of its own type, counting from 0. RFC 9000 §2.1: each
    /// type has its own space, beginning at its own low value and rising by four.
    pub fn index(id: StreamId) u64 {
        return id.value >> constants.stream_id_type_bits;
    }

    /// The `index`th stream of its type (RFC 9000 §2.1).
    pub fn of(initiator_of: Initiator, directionality_of: Directionality, index_of: u64) StreamId {
        assert(index_of <= constants.stream_index_max);
        const bits = @as(u64, @intFromEnum(initiator_of)) |
            (@as(u64, @intFromEnum(directionality_of)) << constants.stream_id_directionality_shift);
        return .{ .value = (index_of << constants.stream_id_type_bits) | bits };
    }

    /// Whether `role` opened this stream, which decides which half of it that endpoint sends on.
    pub fn is_initiated_by(id: StreamId, role: Initiator) bool {
        return id.initiator() == role;
    }

    /// Whether `role` may send on this stream at all. RFC 9000 §3.1: a unidirectional stream
    /// carries data from its initiator alone.
    pub fn is_sendable_by(id: StreamId, role: Initiator) bool {
        if (id.directionality() == .bidirectional) return true;
        return id.is_initiated_by(role);
    }

    /// Whether `role` may receive on this stream: exactly when the peer may send on it, which
    /// is what makes the two halves of RFC 9000 §3 mirror each other.
    pub fn is_receivable_by(id: StreamId, role: Initiator) bool {
        return id.is_sendable_by(role.peer());
    }
};

const testing = std.testing;

test "§2.1: the two low bits give the four types of Table 1" {
    const cases = [_]struct { value: u64, initiator: Initiator, directionality: Directionality }{
        .{ .value = 0x00, .initiator = .client, .directionality = .bidirectional },
        .{ .value = 0x01, .initiator = .server, .directionality = .bidirectional },
        .{ .value = 0x02, .initiator = .client, .directionality = .unidirectional },
        .{ .value = 0x03, .initiator = .server, .directionality = .unidirectional },
    };
    for (cases) |case| {
        const id: StreamId = .{ .value = case.value };
        try testing.expectEqual(case.initiator, id.initiator());
        try testing.expectEqual(case.directionality, id.directionality());
        try testing.expectEqual(0, id.index());
        // The same type built from its parts is the same identifier.
        try testing.expectEqual(case.value, StreamId.of(case.initiator, case.directionality, 0).value);
    }
}

test "§2.1: each type has its own space, rising by four" {
    for (0..4) |index| {
        const id = StreamId.of(.server, .unidirectional, index);
        try testing.expectEqual(0x03 + index * 4, id.value);
        try testing.expectEqual(index, id.index());
        try testing.expectEqual(Initiator.server, id.initiator());
        try testing.expectEqual(Directionality.unidirectional, id.directionality());
    }
    // The largest index a 62-bit identifier holds.
    const largest = StreamId.of(.server, .unidirectional, constants.stream_index_max);
    try testing.expectEqual(constants.stream_id_max, largest.value);
    try testing.expectEqual(constants.stream_index_max, largest.index());
}

test "§3.1: a unidirectional stream carries data from its initiator alone" {
    const client_uni = StreamId.of(.client, .unidirectional, 0);
    try testing.expect(client_uni.is_sendable_by(.client));
    try testing.expect(!client_uni.is_sendable_by(.server));
    try testing.expect(client_uni.is_receivable_by(.server));
    try testing.expect(!client_uni.is_receivable_by(.client));
    // A bidirectional stream is sendable and receivable by both, whoever opened it.
    const server_bidi = StreamId.of(.server, .bidirectional, 7);
    for ([_]Initiator{ .client, .server }) |role| {
        try testing.expect(server_bidi.is_sendable_by(role));
        try testing.expect(server_bidi.is_receivable_by(role));
    }
    try testing.expect(server_bidi.is_initiated_by(.server));
    try testing.expect(!server_bidi.is_initiated_by(.client));
    try testing.expectEqual(Initiator.client, Initiator.server.peer());
}
