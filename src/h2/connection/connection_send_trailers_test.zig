//! The tests of the field sections the send path orders (`connection_send.zig`): the trailer
//! section that ends colibri's side of a stream, a response after the final one, DATA before it,
//! the field lines every section is held to (RFC 9113 §8.1, §8.2), and `Event.ended_stream`. Split
//! out of `connection_send.zig` for length.
const std = @import("std");
const hpack = @import("hpack");
const constants = @import("../constants.zig");
const stream = @import("../stream/stream.zig");
const connection = @import("connection.zig");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const test_connection = &support.test_connection;
const test_output = &support.test_output;
const Event = connection.Event;

/// The decoder a test reads colibri's trailer section back with. Test-only.
var trailer_decoder: hpack.Decoder align(@alignOf(hpack.Decoder)) = undefined;

/// A gRPC status trailer, the commonest trailer section. Test-only.
const trailers = [_]hpack.Field{.{ .name = "grpc-status", .value = "0" }};
const body = "hello";
/// RFC 9110 §15.2.4: 103 Early Hints, an interim response.
const early_hints: u16 = 103;
const ok: u16 = 200;
const no_content: u16 = 204;

/// A server with a request on stream 1 that carried END_STREAM, so the stream is half-closed
/// (remote) and colibri's side is open. Test-only.
fn server_with_request() !void {
    try support.start_server();
    _ = try support.feed_request(1, "/", true);
}

test "RFC 9113 §8.1: a server's trailer section ends the stream after its response and DATA" {
    try server_with_request();
    var written = try test_connection.write_response(test_output, 1, ok, &.{}, false);
    written += (try test_connection.write_data(test_output[written..], 1, body, false)).written;
    const trailer_len = try test_connection.write_trailers(test_output[written..], 1, &trailers);
    const frame_bytes = test_output[written..][0..trailer_len];
    try testing.expectEqual(constants.frame_type_headers, frame_bytes[3]);
    try testing.expectEqual(constants.flag_end_stream | constants.flag_end_headers, frame_bytes[4]);
    // The section holds the caller's field lines and no pseudo-header field.
    trailer_decoder.init(constants.header_table_size_initial);
    var block = trailer_decoder.block(frame_bytes[constants.frame_header_len..]);
    const line = (try block.next()).?;
    try testing.expectEqualStrings("grpc-status", line.name);
    try testing.expectEqualStrings("0", line.value);
    try testing.expectEqual(null, try block.next());
    try testing.expectEqual(stream.State.closed, test_connection.streams.lookup(1).live.state);
}

test "RFC 9113 §8.1: a trailer section before the final response, or a response after it, is refused" {
    try server_with_request();
    try testing.expectError(error.SectionOutOfOrder, test_connection.write_trailers(test_output, 1, &trailers));
    // An interim response is not the final one, so trailers still wait for it.
    _ = try test_connection.write_response(test_output, 1, early_hints, &.{}, false);
    try testing.expectError(error.SectionOutOfOrder, test_connection.write_trailers(test_output, 1, &trailers));
    _ = try test_connection.write_response(test_output, 1, ok, &.{}, false);
    try testing.expectError(error.SectionOutOfOrder, test_connection.write_response(test_output, 1, no_content, &.{}, false));
    _ = try test_connection.write_trailers(test_output, 1, &trailers);
    try testing.expectEqual(stream.State.closed, test_connection.streams.lookup(1).live.state);
}

test "RFC 9113 §8.1: an interim response never ends the stream, and the final one still may" {
    try server_with_request();
    try testing.expectError(error.InterimEndsStream, test_connection.write_response(test_output, 1, early_hints, &.{}, true));
    try testing.expectEqual(stream.State.half_closed_remote, test_connection.streams.lookup(1).live.state);
    _ = try test_connection.write_response(test_output, 1, early_hints, &.{}, false);
    _ = try test_connection.write_response(test_output, 1, ok, &.{}, true);
    try testing.expectEqual(stream.State.closed, test_connection.streams.lookup(1).live.state);
}

test "RFC 9113 §8.1: DATA before the final response, or after an interim one alone, is refused" {
    try server_with_request();
    try testing.expectError(error.SectionOutOfOrder, test_connection.write_data(test_output, 1, body, false));
    _ = try test_connection.write_response(test_output, 1, early_hints, &.{}, false);
    try testing.expectError(error.SectionOutOfOrder, test_connection.write_data(test_output, 1, body, true));
    _ = try test_connection.write_response(test_output, 1, ok, &.{}, false);
    const sent = try test_connection.write_data(test_output, 1, body, true);
    try testing.expectEqual(body.len, sent.consumed);
    try testing.expectEqual(stream.State.closed, test_connection.streams.lookup(1).live.state);
}

test "RFC 9113 §8.1, §8.2: a field line colibri would send malformed is refused, and nothing moves" {
    try server_with_request();
    // RFC 9113 §8.2: field names are lowercase in HTTP/2.
    const uppercase = [_]hpack.Field{.{ .name = "Content-Type", .value = "text/plain" }};
    try testing.expectError(error.FieldLineInvalid, test_connection.write_response(test_output, 1, ok, &uppercase, false));
    // RFC 9113 §8.2.2: no connection-specific field.
    const connection_specific = [_]hpack.Field{.{ .name = "connection", .value = "close" }};
    try testing.expectError(error.FieldLineInvalid, test_connection.write_response(test_output, 1, ok, &connection_specific, false));
    _ = try test_connection.write_response(test_output, 1, ok, &.{}, false);
    // RFC 9113 §8.1: "Trailers MUST NOT include pseudo-header fields".
    const pseudo = [_]hpack.Field{.{ .name = ":status", .value = "200" }};
    try testing.expectError(error.FieldLineInvalid, test_connection.write_trailers(test_output, 1, &pseudo));
    try testing.expectEqual(stream.State.half_closed_remote, test_connection.streams.lookup(1).live.state);
}

test "RFC 9113 §8.1: a client's trailer section follows its request and its DATA" {
    try support.start_client();
    const sent = try test_connection.write_request(test_output, .{ .method = "POST", .scheme = "https", .authority = "example.test", .path = "/" }, &.{}, &.{}, false);
    var written = sent.written;
    written += (try test_connection.write_data(test_output[written..], sent.stream_id, body, false)).written;
    const trailer_len = try test_connection.write_trailers(test_output[written..], sent.stream_id, &trailers);
    try testing.expectEqual(constants.flag_end_stream | constants.flag_end_headers, test_output[written..][0..trailer_len][4]);
    try testing.expectEqual(stream.State.half_closed_local, test_connection.streams.lookup(sent.stream_id).live.state);
}

test "RFC 9113 §8.1: ended_stream names the stream a request, response, DATA or trailers ended" {
    const request: Event = .{ .request = .{ .stream_id = 1, .request = undefined, .end_stream = true } };
    try testing.expectEqual(1, request.ended_stream().?);
    const open_request: Event = .{ .request = .{ .stream_id = 1, .request = undefined, .end_stream = false } };
    try testing.expectEqual(null, open_request.ended_stream());
    const response: Event = .{ .response = .{ .stream_id = 3, .response = undefined, .end_stream = true } };
    try testing.expectEqual(3, response.ended_stream().?);
    const open_response: Event = .{ .response = .{ .stream_id = 3, .response = undefined, .end_stream = false } };
    try testing.expectEqual(null, open_response.ended_stream());
    const data: Event = .{ .data = .{ .stream_id = 5, .payload = body, .end_stream = true } };
    try testing.expectEqual(5, data.ended_stream().?);
    const more_data: Event = .{ .data = .{ .stream_id = 5, .payload = body, .end_stream = false } };
    try testing.expectEqual(null, more_data.ended_stream());
    const trailer_event: Event = .{ .trailers = .{ .stream_id = 7 } };
    try testing.expectEqual(7, trailer_event.ended_stream().?);
    // A reset ends a stream too, but not by END_STREAM, and says so in its own event.
    const reset: Event = .{ .stream_reset = .{ .stream_id = 9, .error_code = constants.error_cancel } };
    try testing.expectEqual(null, reset.ended_stream());
}
