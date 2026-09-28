//! The ALTSVC frame of RFC 7838 §4 on a connection: a client reads the ones a server sends, and a
//! server writes one when its caller asks. RFC 9113 §5.1's stream states govern only the frames
//! RFC 9113 defines, so RFC 7838 §4 sets the rules here.
//!
//! A client reports an ALTSVC frame as an `alt_svc` event when it may use it: on stream 0 with an
//! Origin, or with no Origin on a stream the client opened, whose request names the origin. Every
//! other one is discarded, as RFC 7838 §4 and RFC 9113 §5.5 have a frame colibri cannot use be.
//! Whether the Origin is one the client considers authoritative is its caller's to judge.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const connection = @import("connection.zig");
const connection_send = @import("connection_send.zig");

const Connection = connection.Connection;
const Writer = core.Writer;

/// The event a frame of a type RFC 9113 §6 does not define is, or null for none: an ALTSVC frame
/// a client may use, and nothing for every other.
pub fn on_unknown(target: *const Connection, header: frame.Header, payload: []const u8) ?connection.Event {
    assert(payload.len == header.length);
    // RFC 9113 §4.1 and §5.5: a frame of an unknown type is discarded, whatever it carries.
    if (header.type != constants.frame_type_altsvc) return null;
    // RFC 7838 §4: "A device acting as a server MUST ignore it."
    if (target.role == .server) return null;
    const read = frame.parse_altsvc(header, payload) orelse return null;
    if (header.stream_id == constants.connection_stream_id) {
        // RFC 7838 §4: "An ALTSVC frame on stream 0 with empty (length 0) "Origin" information is
        // invalid and MUST be ignored."
        if (read.origin.len == 0) return null;
    } else {
        // RFC 7838 §4: on any other stream a non-empty Origin "is invalid and MUST be ignored".
        if (read.origin.len > 0) return null;
        // RFC 7838 §4: the alternative is "associated with the origin of that stream", and a
        // stream the client never opened carries no request to name one.
        if (!opened_by_client(target, header.stream_id)) return null;
    }
    return .{ .alt_svc = .{ .stream_id = header.stream_id, .origin = read.origin, .value = read.value } };
}

/// Whether the client opened stream `id`: it has the client's parity (RFC 9113 §5.1.1), and
/// `open_local` has passed it.
fn opened_by_client(target: *const Connection, id: u32) bool {
    assert(target.role == .client);
    const client_parity = id % constants.stream_id_step == constants.stream_id_client_first % constants.stream_id_step;
    return client_parity and id < target.streams.next_local_id;
}

/// Writes an ALTSVC frame on `stream_id` with no Origin, so the alternative the Alt-Svc field value
/// `value` names applies to the origin of the stream's request (RFC 7838 §4). A server's call, on
/// a stream it has not ended.
pub fn write_alt_svc(target: *Connection, output: []u8, stream_id: u32, value: []const u8) connection_send.Error!usize {
    assert(target.role == .server);
    assert(stream_id != constants.connection_stream_id);
    // RFC 9113 §4.2 and §6.5.2: no peer's SETTINGS_MAX_FRAME_SIZE is below `max_frame_size_min`.
    assert(constants.altsvc_origin_len_len + value.len <= constants.max_frame_size_min);
    const found = target.streams.lookup(stream_id);
    // RFC 7838 §4 ties the frame to the origin of the stream's request, so it goes on a stream the
    // table holds, before colibri's END_STREAM: open or half-closed (remote) (RFC 9113 §5.1).
    if (found != .live) return error.StreamNotSendable;
    const state = found.live.state;
    // RFC 9113 §5.1: colibri has not sent END_STREAM on a stream open or half-closed (remote).
    if (state != .open and state != .half_closed_remote) return error.StreamNotSendable;
    var writer = Writer.init(output);
    // RFC 9113 §4.1: a frame is its 9-octet header and its payload, written whole or not at all.
    frame.write_altsvc(&writer, stream_id, "", value) catch return error.OutputTooSmall;
    return writer.written().len;
}

const testing = std.testing;
const support = @import("connection_test_support.zig");
const test_connection = &support.test_connection;
const test_input = &support.test_input;
const test_output = &support.test_output;

/// The field value the tests advertise. Test-only.
const test_value = "h3=\":443\"; ma=60";

/// Feeds an ALTSVC frame on `stream_id` naming `origin`, and returns what the connection reported.
/// Test-only.
fn feed_altsvc(stream_id: u32, origin: []const u8) !?connection.Event {
    var writer = Writer.init(test_input);
    try frame.write_altsvc(&writer, stream_id, origin, test_value);
    return support.feed(writer.written());
}

/// A client that has read the server's preface and opened its first `opened` streams. Test-only.
fn start_client(opened: u32) !void {
    try support.start_client();
    test_connection.streams.next_local_id = constants.stream_id_client_first + opened * constants.stream_id_step;
}

test "RFC 7838 §4: a client reports an ALTSVC frame with no Origin on a stream it opened" {
    try start_client(1);
    const event = (try feed_altsvc(constants.stream_id_client_first, "")).?;
    try testing.expectEqual(constants.stream_id_client_first, event.alt_svc.stream_id);
    try testing.expectEqualStrings("", event.alt_svc.origin);
    try testing.expectEqualStrings(test_value, event.alt_svc.value);
}

test "RFC 7838 §4: a client reports one on stream 0 with an Origin, and ignores one without" {
    try start_client(0);
    const named = (try feed_altsvc(constants.connection_stream_id, "https://example.org")).?;
    try testing.expectEqualStrings("https://example.org", named.alt_svc.origin);
    try testing.expectEqual(null, try feed_altsvc(constants.connection_stream_id, ""));
}

test "RFC 7838 §4: an Origin on a request stream, or a stream the client never opened, is ignored" {
    try start_client(1);
    try testing.expectEqual(null, try feed_altsvc(constants.stream_id_client_first, "https://example.org"));
    try testing.expectEqual(null, try feed_altsvc(constants.stream_id_client_first + constants.stream_id_step, ""));
    // A server's parity: the client opened no such stream.
    try testing.expectEqual(null, try feed_altsvc(constants.stream_id_server_first, ""));
    try testing.expect(!test_connection.has_failed());
}

test "RFC 7838 §4: a server ignores an ALTSVC frame, and a client discards every other unknown type" {
    try support.start_server();
    try testing.expectEqual(null, try feed_altsvc(constants.connection_stream_id, "https://example.org"));
    try start_client(0);
    const other = try support.frame_bytes(test_input, constants.frame_type_altsvc + 1, 0, 0, "\x00\x01a");
    try testing.expectEqual(null, try support.feed(other));
    try testing.expect(!test_connection.has_failed());
}

test "RFC 7838 §4: a server writes ALTSVC with no Origin on a request's stream until it ends it" {
    try support.start_server();
    _ = try support.feed_request(constants.stream_id_client_first, "/", true);
    const written = try write_alt_svc(test_connection, test_output, constants.stream_id_client_first, test_value);
    var reader = core.Reader.init(test_output[0..written]);
    const header = try frame.read_header(&reader);
    try testing.expectEqual(constants.frame_type_altsvc, header.type);
    try testing.expectEqual(constants.stream_id_client_first, header.stream_id);
    const read = frame.parse_altsvc(header, reader.take_rest()).?;
    try testing.expectEqualStrings("", read.origin);
    try testing.expectEqualStrings(test_value, read.value);
    // A stream the client has not opened, and one whose response ended, carry none.
    const idle = constants.stream_id_client_first + constants.stream_id_step;
    try testing.expectError(error.StreamNotSendable, write_alt_svc(test_connection, test_output, idle, test_value));
    _ = try test_connection.write_response(test_output, constants.stream_id_client_first, 200, &.{}, true);
    try testing.expectError(error.StreamNotSendable, write_alt_svc(test_connection, test_output, constants.stream_id_client_first, test_value));
    // An output that cannot hold the frame is refused.
    _ = try support.feed_request(idle, "/", false);
    var small: [constants.frame_header_len]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, write_alt_svc(test_connection, &small, idle, test_value));
}
