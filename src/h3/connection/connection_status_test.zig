//! The tests of a status code outside 100 to 599 over h3 (decision 158, ruling 17). RFC 9110 §15
//! tells a client to read such a code as a 5xx, so the client takes it as a final response. A
//! server never sends one. The harness is `connection_test.zig`'s.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const connection_module = @import("connection.zig");
const harness = @import("connection_test.zig");
const request_test = @import("connection_request_test.zig");

const Writer = core.Writer;
const Event = connection_module.Connection.Event;
const testing = std.testing;

const client = &harness.client;
const server = &harness.server;
const next = harness.next;
const Line = harness.Line;

/// Room for the HEADERS frame a test writes. Test-only.
const frames_len_max: usize = 64;

/// The codes the tests send, as text, which RFC 9110 §15 calls invalid.
const texts = [_][]const u8{ "099", "600", "800", "999" };

/// The code that `text` names. Test-only.
fn code_of(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, http.constants.protocol.status_digit_radix);
}

test "RFC 9110 §15: a client reads a :status outside 100 to 599 as a final 5xx" {
    for (texts) |text| {
        const code = try code_of(text);
        try harness.pair(.{ .role = .client }, .{ .role = .server });
        const id = try harness.request(&harness.get_lines, "");
        try harness.exchange();
        _ = (try next(server)).?.request;
        // The server's own write_response refuses the code, so the frame is written raw.
        var octets: [frames_len_max]u8 = undefined;
        var writer = Writer.init(&octets);
        try request_test.headers_frame(&writer, &[_]Line{.{ ":status", text }});
        try server.send_raw(id, writer.written(), true);
        try harness.exchange();
        const response = (try next(client)).?.response;
        try testing.expectEqual(code, @intFromEnum(response.response.status));
        try testing.expectEqual(http.Status.Class.server_error, response.response.status.class());
        try testing.expectEqual(Event{ .end = id }, (try next(client)).?);
    }
}

test "RFC 9110 §15: a server sends no :status outside 100 to 599" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = try harness.request(&harness.get_lines, "");
    try harness.exchange();
    _ = (try next(server)).?.request;
    for (texts) |text| {
        try testing.expectError(error.MessageInvalid, harness.respond(id, &[_]Line{.{ ":status", text }}, ""));
    }
    try harness.respond(id, &harness.ok_lines, "");
}
