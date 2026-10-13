//! The tests of `connection.zig`, split out because a hand-written source file stays at or under
//! 500 lines with its tests included (CLAUDE.md): what `init` writes, the preface each role
//! writes, the replies written after it, and `fail`.
const std = @import("std");
const constants = @import("../constants.zig");
const support = @import("connection_test_support.zig");

const Connection = @import("connection.zig").Connection;
const Role = @import("../role.zig").Role;

const testing = std.testing;
const test_connection = &support.test_connection;
const test_output = &support.test_output;

test "a server writes its SETTINGS and no preface, and a client writes the 24 octets first" {
    test_connection.init(.server);
    try testing.expect(test_connection.has_pending());
    const server_len = test_connection.write_pending(test_output, 0);
    // The server's SETTINGS omits ENABLE_PUSH, so it carries five of the six settings.
    try testing.expectEqual(constants.frame_header_len + 5 * constants.setting_len, server_len);
    try testing.expectEqual(constants.frame_type_settings, test_output[3]);
    try testing.expect(!test_connection.has_pending());
    try testing.expectEqual(1, test_connection.pending.len());
    test_connection.init(.client);
    const client_len = test_connection.write_pending(test_output, 0);
    try testing.expectEqualStrings(constants.client_preface, test_output[0..constants.client_preface_len]);
    try testing.expectEqual(constants.client_preface_len + constants.frame_header_len + 6 * constants.setting_len, client_len);
    try testing.expect(!test_connection.has_pending());
}

test "a buffer too short for the preface writes nothing and keeps it pending" {
    test_connection.init(.client);
    try testing.expectEqual(0, test_connection.write_pending(test_output[0 .. constants.client_preface_len - 1], 0));
    try testing.expect(test_connection.has_pending());
    try testing.expectEqual(0, test_connection.pending.len());
    // The 24 octets fit, the SETTINGS frame does not.
    try testing.expectEqual(constants.client_preface_len, test_connection.write_pending(test_output[0..constants.client_preface_len], 0));
    try testing.expect(test_connection.has_pending());
    const rest = test_connection.write_pending(test_output, 0);
    try testing.expectEqual(constants.frame_header_len + 6 * constants.setting_len, rest);
    try testing.expect(!test_connection.has_pending());
}

test "RFC 9113 §3.4: no reply goes out ahead of the preface" {
    test_connection.init(.server);
    // A connection error before the preface is out queues a GOAWAY (RFC 9113 §5.4.1).
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.error_protocol_error));
    try testing.expectEqual(0, test_connection.write_replies(test_output));
    const written = test_connection.write_pending(test_output, 0);
    // The server's SETTINGS carries five settings, and the GOAWAY follows it.
    const settings_len = constants.frame_header_len + 5 * constants.setting_len;
    try testing.expectEqual(constants.frame_type_settings, test_output[3]);
    try testing.expectEqual(constants.frame_type_goaway, test_output[settings_len + 3]);
    try testing.expect(written > settings_len);
}

test "fail queues one GOAWAY, records it against the streams and stands on the first code" {
    test_connection.init(.server);
    _ = test_connection.write_pending(test_output, 0);
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.error_protocol_error));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.error_internal_error));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
    const written = test_connection.write_pending(test_output, 0);
    const expected = "\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    try testing.expectEqualSlices(u8, expected, test_output[0..written]);
    try testing.expect(!test_connection.has_pending());
}

/// Requires a connection with nothing pending to write no reply, which is what lets a caller skip
/// `write_replies` when `has_pending` is false. Test-only.
fn expect_nothing_owed_when_none_pending() !void {
    if (test_connection.has_pending()) return;
    try testing.expectEqual(0, test_connection.write_replies(test_output));
}

test "a connection with nothing pending writes no reply, after each kind of reply goes out" {
    try support.start_server();
    try expect_nothing_owed_when_none_pending();
    // RFC 9113 §6.7: a PING owes its acknowledgment.
    const ping = try support.frame_bytes(&support.test_input, constants.frame_type_ping, 0, 0, "12345678");
    _ = try support.feed(ping);
    try testing.expect(test_connection.has_pending());
    _ = support.write_queued();
    try expect_nothing_owed_when_none_pending();
    // RFC 9113 §6.5.3: a SETTINGS frame owes its acknowledgment.
    _ = try support.feed(support.empty_settings);
    try testing.expect(test_connection.has_pending());
    _ = support.write_queued();
    try expect_nothing_owed_when_none_pending();
    // RFC 9113 §6.9: DATA owes WINDOW_UPDATEs once enough of it has been released.
    _ = try support.feed_request(1, "/", false);
    var payload: [constants.frame_size_max]u8 = @splat('d');
    for (0..constants.initial_window_size_initial / payload.len) |_| {
        _ = try support.feed(try support.frame_bytes(&support.test_input, constants.frame_type_data, 0, 1, &payload));
        if (test_connection.has_pending()) _ = support.write_queued();
        try expect_nothing_owed_when_none_pending();
    }
    // RFC 9113 §6.4: a stream colibri resets owes its RST_STREAM, alone.
    _ = try support.feed_request(3, "/", false);
    _ = support.write_queued();
    try test_connection.reset_stream(3, constants.error_cancel);
    try testing.expect(test_connection.has_pending());
    _ = support.write_queued();
    try expect_nothing_owed_when_none_pending();
    // RFC 9113 §5.4.1: a connection error owes its GOAWAY.
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.error_protocol_error));
    try testing.expect(test_connection.has_pending());
    _ = support.write_queued();
    try expect_nothing_owed_when_none_pending();
}

/// The parts of a connection `init` leaves as they were: storage written before it is read. The
/// HPACK tables hold an entry's octets once it is inserted, the stream pool an entry once it opens
/// (invariant 5), and the decoder's scratch, the field block and `send_block` what a call writes
/// before it reads. Test-only.
const storage_left_by_init = [_][]const u8{
    "decoder.table.octets", "decoder.table.entries", "decoder.name_scratch", "decoder.value_scratch",
    "encoder.table.octets", "encoder.table.entries", "streams.pool.entries", "block.buffer",
    "block.section.octets", "block.section.lines",   "send_block",
};

/// Two connections `init` starts over storage filled with zeros and with ones. Test-only.
var over_zeros: Connection align(@alignOf(Connection)) = undefined;
var over_ones: Connection align(@alignOf(Connection)) = undefined;

/// Fails, naming the field, when a field of `T` at any depth holds different octets in `a` and
/// `b`, other than the storage `init` leaves.
fn expect_written(comptime T: type, a: *const T, b: *const T, comptime path: []const u8) !void {
    inline for (storage_left_by_init) |left| {
        if (comptime std.mem.eql(u8, path, left)) return;
    }
    const info = @typeInfo(T);
    if (info == .@"struct" and info.@"struct".layout != .@"packed") {
        inline for (info.@"struct".fields) |field| {
            const inner = if (path.len == 0) field.name else path ++ "." ++ field.name;
            try expect_written(field.type, &@field(a.*, field.name), &@field(b.*, field.name), inner);
        }
        return;
    }
    if (std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b))) return;
    std.debug.print("first difference: init leaves {s} as the storage held it\n", .{path});
    return error.TestUnexpectedResult;
}

test "init writes every field but the storage it leaves, for each role" {
    for ([_]Role{ .server, .client }) |role| {
        @memset(std.mem.asBytes(&over_zeros), 0);
        @memset(std.mem.asBytes(&over_ones), std.math.maxInt(u8));
        over_zeros.init(role);
        over_ones.init(role);
        try expect_written(Connection, &over_zeros, &over_ones, "");
    }
}
