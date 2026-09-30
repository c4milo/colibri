//! The tests of `connection.zig`, split out because a hand-written source file stays at or under
//! 500 lines with its tests included (CLAUDE.md): the preface each role writes, and `fail`.
const std = @import("std");
const constants = @import("../constants.zig");
const support = @import("connection_test_support.zig");

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
