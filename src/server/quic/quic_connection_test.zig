//! The tests of the server over QUIC (`quic_connection.zig`, `quic_connection_h3.zig`): requests
//! arrive from an h3 client over QUIC in the same process, and each response goes out from the
//! caller's memory until the request is `done` (decision 103).
const std = @import("std");
const h3 = @import("h3");
const quic = @import("quic");
const support = @import("quic_test_support.zig");
const constants = @import("../constants.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
const early_hints: u16 = 103;
const content_type = [_]support.Field{.{ .name = "content-type", .value = "text/plain" }};
const trailer_fields = [_]support.Field{.{ .name = "checksum", .value = "1" }};

/// A connected pair, and one GET from the client whose head and end the server read.
fn get(path: []const u8) !*support.Fetch {
    try support.start();
    try support.connect();
    const fetch = try support.request("GET", path, "");
    try support.pump(support.rounds_default);
    return fetch;
}

test "RFC 9114 §4.1: a GET's head arrives as a request event, and its end as a body event" {
    const fetch = try get("/index.html");
    try testing.expectEqual(event.Protocol.h3, connection.protocol().?);
    const head = support.nth(.request, 0).?;
    try testing.expectEqual(fetch.id, head.id);
    try testing.expectEqualStrings("/index.html", head.path_of());
    // RFC 9114 §4.1: the request's end comes apart from its head.
    const end = support.nth(.body, 0).?;
    try testing.expect(end.end and end.len == 0);
    try testing.expectEqualStrings("localhost", connection.server_name().?);
}

test "decision 103: a response goes out from the caller's memory, and is done once acknowledged" {
    const fetch = try get("/");
    const content = "hello over h3";
    try connection.respond(fetch.id, ok, &content_type, false);
    try testing.expectEqual(content.len, try connection.write_body(fetch.id, content, true));
    try testing.expectEqual(null, support.nth(.done, 0));
    try support.pump(support.rounds_default);
    try testing.expectEqual(ok, fetch.status);
    try testing.expectEqualStrings(content, support.content_of(fetch));
    try testing.expect(fetch.ended);
    // RFC 9000 §3.1: every octet was acknowledged, so the caller's octets are free.
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
}

/// Content in more DATA frames than a response holds runs for at once, so it goes out only as the
/// peer acknowledges the runs before it. Test-only.
const long_len: usize = 200_000;
const piece_len: usize = 4096;
var long: [long_len]u8 = undefined;
const write_rounds_max: usize = 1024;

test "decision 103: content in more runs than a response holds arrives whole as runs are acknowledged" {
    const fetch = try get("/long");
    for (&long, 0..) |*octet, index| octet.* = @truncate(index);
    try connection.respond(fetch.id, ok, &.{}, false);
    var taken: usize = 0;
    var blocked: usize = 0;
    // Bounded: each pass takes a piece, or pumps so the peer acknowledges some.
    for (0..write_rounds_max) |_| {
        if (taken == long.len) break;
        const next = long[taken..@min(taken + piece_len, long.len)];
        const written = connection.write_body(fetch.id, next, taken + next.len == long.len) catch |failure| {
            try testing.expectEqual(error.Blocked, failure);
            blocked += 1;
            try support.pump(1);
            continue;
        };
        taken += written;
    }
    try testing.expect(blocked > 0);
    try support.pump(support.rounds_default * 2);
    try testing.expectEqualSlices(u8, &long, support.content_of(fetch));
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
}

test "RFC 9114 §4.1: an interim head ends nothing, and nothing goes out of order around the final one" {
    const fetch = try get("/");
    // RFC 9114 §4.1: DATA and a trailer section follow the final response.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(fetch.id, "x", true));
    try testing.expectError(error.SectionOutOfOrder, connection.write_trailers(fetch.id, &trailer_fields));
    try connection.respond(fetch.id, early_hints, &.{}, true);
    try connection.respond(fetch.id, ok, &.{}, false);
    // RFC 9110 §15: one final response answers a request, even one with no end yet.
    try testing.expectError(error.SectionOutOfOrder, connection.respond(fetch.id, ok, &.{}, false));
    try testing.expectEqual(0, try connection.write_body(fetch.id, "", true));
    try testing.expectError(error.SectionOutOfOrder, connection.respond(fetch.id, ok, &.{}, true));
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(fetch.id, "x", false));
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, fetch.interims);
    try testing.expectEqual(ok, fetch.status);
    try testing.expect(fetch.ended);
}

test "RFC 9110 §15: a status is 100 to 599, and RFC 9114 §4.5: h3 has no 101" {
    const fetch = try get("/");
    for ([_]u16{ 99, 101, 600 }) |status| {
        try testing.expectError(error.StatusInvalid, connection.respond(fetch.id, status, &.{}, true));
    }
    try testing.expectError(error.RequestUnknown, connection.respond(fetch.id + 4, ok, &.{}, true));
    // RFC 9114 §4.2: a field name is lowercase.
    const upper = [_]support.Field{.{ .name = "Content-Type", .value = "text/plain" }};
    try testing.expectError(error.FieldLineInvalid, connection.respond(fetch.id, ok, &upper, true));
}

test "RFC 9114 §4.1: a trailer section ends the response, and the request is done" {
    const fetch = try get("/");
    try connection.respond(fetch.id, ok, &.{}, false);
    try testing.expectEqual(1, try connection.write_body(fetch.id, "x", false));
    try connection.write_trailers(fetch.id, &trailer_fields);
    try support.pump(support.rounds_default);
    try testing.expectEqualStrings("x", support.content_of(fetch));
    try testing.expect(fetch.ended);
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
}

test "RFC 9114 §4.1.1: cancel resets the response with H3_REQUEST_CANCELLED, and reports nothing" {
    const fetch = try get("/");
    try connection.respond(fetch.id, ok, &.{}, false);
    connection.cancel(fetch.id);
    try testing.expectError(error.RequestUnknown, connection.write_body(fetch.id, "x", true));
    try support.pump(support.rounds_default);
    try testing.expectEqual(h3.constants.error_request_cancelled, fetch.reset.?);
    try testing.expectEqual(null, support.nth(.done, 0));
    try testing.expectEqual(null, support.nth(.cancelled, 0));
}

test "RFC 9114 §4.1.1: a request the client cancels arrives cancelled, and its response is reset" {
    const fetch = try get("/");
    try connection.respond(fetch.id, ok, &.{}, false);
    support.cancel_fetch(fetch);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.cancelled, 0).?.id);
    // RFC 9114 §4.1.1: the server resets its response too, so nothing reads the caller's octets.
    try testing.expect(response_reset(fetch.id));
    try testing.expectError(error.RequestUnknown, connection.write_body(fetch.id, "x", true));
    try testing.expectEqual(null, support.nth(.done, 0));
}

/// Whether the server's side of stream `id` was reset, or the stream closed. Test-only.
fn response_reset(id: u64) bool {
    return switch (connection.transport.streams.lookup(.{ .value = id })) {
        .closed => true,
        .unopened => false,
        .live => |stream| stream.sending.state == .reset_sent or stream.sending.state == .reset_recvd,
    };
}

test "RFC 9114 §4.1.1: a request no record can hold is rejected, which the client may send again" {
    const first = try get("/");
    // Every other record holds the first request's open stream, so none is free.
    for (&connection.requests.records) |*record| {
        if (record.in_use) continue;
        record.* = .{ .in_use = true, .stream_id = first.id, .ended = true, .answered = false, .finished = false, .over = true, .response = undefined };
        record.response.init();
    }
    const second = try support.request("GET", "/second", "");
    try support.pump(support.rounds_default);
    try testing.expectEqual(h3.constants.error_request_rejected, second.reset.?);
    try testing.expectEqual(null, support.nth(.request, 1));
}

test "RFC 9000 §4.1: every window the server advertises fits its receive pool" {
    try support.start();
    try support.connect();
    const granted = connection.transport.local_parameters;
    try testing.expectEqual(quic.constants.receive_pool_len_default, granted.initial_max_data);
    try testing.expectEqual(constants.quic_stream_window, granted.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(constants.quic_stream_window, granted.initial_max_stream_data_uni);
    try testing.expectEqual(constants.quic_requests_max, granted.initial_max_streams_bidi);
}

test "RFC 9114 §5.2: a shutdown sends GOAWAY, and QUIC closes once the last request is done" {
    const fetch = try get("/");
    connection.shutdown(support.now_ns);
    try support.pump(support.rounds_default);
    try testing.expect(support.client.termination.state == .active);
    try connection.respond(fetch.id, ok, &.{}, true);
    try support.pump(support.rounds_default);
    try testing.expect(fetch.ended);
    // RFC 9000 §10.2: the client read the CONNECTION_CLOSE, and drains.
    try testing.expect(support.client.termination.state != .active);
    try testing.expect(!support.server_failed);
}

test "RFC 9000 §10.2.2: a client's close stops the connection, which is no failure" {
    const fetch = try get("/");
    // RFC 9114 §5.2: a client that is done closes with H3_NO_ERROR.
    quic.connection_close.owe(&support.client, .{
        .layer = .application,
        .error_code = support.client_h3.no_error_code(),
        .frame_type = null,
        .reason = "",
    });
    try support.pump(support.rounds_default);
    try testing.expect(connection.transport.termination.state == .draining);
    try testing.expectError(error.ConnectionClosed, connection.respond(fetch.id, ok, &.{}, true));
    // RFC 9000 §10.2: the draining state lasts three PTOs, which these rounds pass.
    try support.pump(support.rounds_default * 8);
    try testing.expect(connection.ended());
    try testing.expect(!support.server_failed);
}
