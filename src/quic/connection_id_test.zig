//! The tests of `connection_id.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const constants = @import("constants.zig");
const connection_id = @import("connection_id.zig");

const Entry = connection_id.Entry;
const Remote = connection_id.Remote;
const Local = connection_id.Local;
const connection_error_code = connection_id.connection_error_code;
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
