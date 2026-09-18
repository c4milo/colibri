//! The frames that name a stream, and the one rule they share: what the stream table and the state
//! machine of RFC 9113 §5.1 say about the identifier the frame carries. DATA is in
//! `connection_data.zig` and HEADERS, CONTINUATION and PUSH_PROMISE in `connection_headers.zig`,
//! because each has work of its own; RST_STREAM (§6.4), PRIORITY (§6.3) and the WINDOW_UPDATE on a
//! stream (§6.9) are here, beside `find`, which every one of them starts with.
//!
//! `find` reads the table once and turns the four answers of `Lookup` into three (invariant 7):
//!   1. a record: the state machine decides the frame, and its verdict is returned with it;
//!   2. discard: RFC 9113 §5.1 says to drop the frame after the minimal processing the caller does,
//!      which is the frames that arrive after a RST_STREAM colibri sent and those the state machine
//!      ignores, PRIORITY among them;
//!   3. refused: the stream ends with the RST_STREAM the state machine's verdict names (§5.4.2).
//! A frame the state forbids outright ends the connection from inside `find` (§5.4.1).
//!
//! An identifier the table has forgotten is a connection error of PROTOCOL_ERROR: the peer never
//! opened it, which §5.1.1 closed implicitly, or its record is gone. §5.1 permits that choice once
//! a signal says the peer has seen the close, and a later identifier is such a signal (h2spec
//! http2/5.1.1/2). An identifier still in the table keeps the precise verdict of §5.1 instead
//! (h2spec http2/5.1/12).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const stream = @import("../stream/stream.zig");
const streams_table = @import("../stream/streams.zig");
const connection = @import("connection.zig");
const data_frames = @import("connection_data.zig");
const header_frames = @import("connection_headers.zig");

const Connection = connection.Connection;
const Event = connection.Event;
const Error = connection.Error;
const Stream = streams_table.Stream;

/// What the table and the state machine say about the stream a frame names.
pub const Found = union(enum) {
    /// The frame is permitted: act on this record, then apply `verdict` to it.
    act: Acting,
    /// RFC 9113 §5.1: drop the frame, after the minimal processing its handler does first.
    discard,
    /// The stream is idle and the frame opens it, which only a HEADERS frame does (§5.1): the
    /// verdict is the state the table's new record takes.
    open: stream.Verdict,
    /// The stream ends: the RST_STREAM is queued and this is the event the handler returns.
    refused: Event,
};

/// A record the state machine permits a frame on, with the verdict to apply once the frame's own
/// work is done: flow control and the field block happen before the stream moves.
pub const Acting = struct {
    record: *Stream,
    verdict: stream.Verdict,
};

/// Gives a frame that names a stream to the rules of its type.
pub fn on_stream_frame(
    target: *Connection,
    header: frame.Header,
    parsed: frame.Payload,
    now_ns: u64,
) Error!?Event {
    return switch (parsed) {
        .data => |payload| data_frames.on_data(target, header, payload, now_ns),
        .headers => |payload| header_frames.on_headers(target, header, payload, now_ns),
        .continuation => |payload| header_frames.on_continuation(target, header, payload, now_ns),
        .push_promise => |payload| header_frames.on_push_promise(target, header, payload, now_ns),
        .priority => on_priority(target, header),
        .rst_stream => |payload| on_rst_stream(target, header, payload, now_ns),
        .window_update => |payload| on_window_update(target, header, payload, now_ns),
        // The frames that name no stream never reach here: `connection_receive.zig` sends SETTINGS,
        // PING, GOAWAY, the WINDOW_UPDATE on stream 0 and an unknown type elsewhere.
        else => unreachable,
    };
}

/// Finds the stream `id` names for a frame of `kind`, and applies RFC 9113 §5.1 and §5.1.1 to it.
pub fn find(target: *Connection, id: u32, kind: stream.Kind, end_stream: bool, now_ns: u64) Error!Found {
    assert(id != constants.connection_stream_id);
    switch (target.streams.lookup(id)) {
        .live => |record| {
            const verdict = stream.on_receive(record.state, record.closed, kind, end_stream, target.role, record.peer_initiated);
            return verdict_of(target, id, record, verdict, now_ns);
        },
        .idle => |peer_initiated| {
            // An idle stream has no record, and §5.1 decides the frame from the state alone: a
            // HEADERS the peer sends opens it, PRIORITY is ignored, and the rest end the
            // connection. `connection_headers.zig` does the opening.
            const verdict = stream.on_receive(.idle, null, kind, end_stream, target.role, peer_initiated);
            return verdict_without_record(target, id, verdict, now_ns);
        },
        // RFC 9113 §5.1: after a RST_STREAM colibri sent, the frames still on their way are
        // discarded once the connection has done the minimal processing they ask for.
        .reset_and_dropped => return .discard,
        // The file header says why a forgotten identifier ends the connection.
        .forgotten => return target.fail(constants.error_protocol_error),
    }
}

/// Turns the state machine's verdict on a record into a `Found`.
fn verdict_of(target: *Connection, id: u32, record: *Stream, verdict: stream.Verdict, now_ns: u64) Error!Found {
    return switch (verdict) {
        .state => .{ .act = .{ .record = record, .verdict = verdict } },
        .ignore => .discard,
        .connection_error => |code| target.fail(code),
        .stream_error => |code| .{ .refused = try reset_stream(target, id, code, now_ns) },
        // RFC 9113 §5.1 gives `illegal` to frames colibri would send, never to one it receives.
        .illegal => unreachable,
    };
}

/// Turns a verdict on a stream with no record into a `Found`. A verdict of `.state` belongs to a
/// HEADERS frame that opens the stream, which `connection_headers.zig` does.
fn verdict_without_record(target: *Connection, id: u32, verdict: stream.Verdict, now_ns: u64) Error!Found {
    return switch (verdict) {
        .state => .{ .open = verdict },
        .ignore => .discard,
        .connection_error => |code| target.fail(code),
        .stream_error => |code| .{ .refused = try reset_stream(target, id, code, now_ns) },
        .illegal => unreachable,
    };
}

/// Ends the stream `id` with a RST_STREAM carrying `code`, and returns the event that says so
/// (RFC 9113 §5.4.2). The table keeps the record, so the frames still on their way are discarded.
pub fn reset_stream(target: *Connection, id: u32, code: u32, now_ns: u64) Error!Event {
    assert(id != constants.connection_stream_id);
    try count_reset(target, now_ns);
    if (target.streams.lookup(id) == .live) {
        const record = target.streams.lookup(id).live;
        const verdict = stream.on_send(record.state, record.closed, .rst_stream, false, target.role, record.peer_initiated);
        // A stream colibri has already closed takes no second close; §5.1 leaves it closed.
        if (verdict == .state) target.streams.transition(record, verdict, .send, .rst_stream, false);
    }
    target.replies.push_stream_reply(.{ .stream_id = id, .kind = .rst_stream, .value = code });
    return .{ .stream_refused = .{ .stream_id = id, .error_code = code } };
}

/// Ends a stream whose frame did not parse (RFC 9113 §5.4.2), for `connection_receive.zig`.
pub fn refuse_stream(target: *Connection, id: u32, code: u32, now_ns: u64) Error!?Event {
    return try reset_stream(target, id, code, now_ns);
}

/// Counts one RST_STREAM colibri sends in the period `now_ns` falls in, and ends the connection
/// past the limit. RFC 9113 §10.5 asks an endpoint to track the use of the features that cost it
/// work and to treat excess as ENHANCE_YOUR_CALM: a peer that opens and cancels streams makes
/// colibri do a request's work for nothing.
fn count_reset(target: *Connection, now_ns: u64) Error!void {
    if (now_ns - target.rst_stream_period_start_ns >= constants.rst_stream_rate_period_ns) {
        target.rst_stream_period_start_ns = now_ns;
        target.rst_stream_sent = 0;
    }
    if (target.rst_stream_sent == constants.rst_stream_rate_max) {
        return target.fail(constants.error_enhance_your_calm);
    }
    target.rst_stream_sent += 1;
}

/// Reads a PRIORITY frame, which colibri parses and never acts on (decision 18). RFC 9113 §5.1
/// lets PRIORITY arrive in any stream state, so it ends neither the stream nor the connection.
fn on_priority(target: *Connection, header: frame.Header) Error!?Event {
    // The frame is read for its side effect on the stream table: none. §6.3 deprecates the scheme
    // it belongs to, and colibri implements no scheduler.
    _ = target;
    _ = header;
    return null;
}

/// Reads a RST_STREAM the peer sent, which closes the stream at once (RFC 9113 §6.4).
fn on_rst_stream(target: *Connection, header: frame.Header, payload: frame.RstStream, now_ns: u64) Error!?Event {
    const found = try find(target, header.stream_id, .rst_stream, false, now_ns);
    switch (found) {
        .refused => |event| return event,
        .discard => return null,
        // Only a HEADERS frame opens a stream (RFC 9113 §5.1), so neither of these finds an idle
        // one: the state machine ends the connection on both before the table is asked to open.
        .open => unreachable,
        .act => |acting| {
            target.streams.transition(acting.record, acting.verdict, .receive, .rst_stream, false);
            return .{ .stream_reset = .{ .stream_id = header.stream_id, .error_code = payload.error_code } };
        },
    }
}

/// Adds the increment of a WINDOW_UPDATE on a stream to that stream's send window (RFC 9113 §6.9).
fn on_window_update(target: *Connection, header: frame.Header, payload: frame.WindowUpdate, now_ns: u64) Error!?Event {
    const found = try find(target, header.stream_id, .window_update, false, now_ns);
    switch (found) {
        .refused => |event| return event,
        .discard => return null,
        // Only a HEADERS frame opens a stream (RFC 9113 §5.1), so neither of these finds an idle
        // one: the state machine ends the connection on both before the table is asked to open.
        .open => unreachable,
        .act => |acting| {
            acting.record.send_window.add(payload.increment) catch {
                // RFC 9113 §6.9.1: an increment that takes a stream's window above 2^31 - 1 is a
                // stream error of FLOW_CONTROL_ERROR.
                return try reset_stream(target, header.stream_id, constants.error_flow_control_error, now_ns);
            };
            target.streams.transition(acting.record, acting.verdict, .receive, .window_update, false);
            return null;
        },
    }
}

const testing = std.testing;
const test_connection = &connection.test_connection;
const feed = connection.feed;
const feed_request = connection.feed_request;
const frame_bytes = connection.frame_bytes;
const start_server = connection.start_server;
const write_queued = connection.write_queued;
const test_input = &connection.test_input;

/// The octets of a RST_STREAM frame for `stream_id` carrying `code`. Test-only.
fn expect_rst_stream(written: []const u8, stream_id: u32, code: u32) !void {
    var expected: [constants.frame_header_len + constants.rst_stream_len]u8 = undefined;
    var writer = @import("core").Writer.init(&expected);
    try frame.write_rst_stream(&writer, stream_id, code);
    try testing.expectEqualSlices(u8, writer.written(), written);
}

test "http2/5.1/1, /2 and /3: DATA, RST_STREAM and WINDOW_UPDATE on an idle stream end the connection" {
    const cases = [_]struct { frame_type: u8, payload: []const u8 }{
        .{ .frame_type = constants.frame_type_data, .payload = "test" },
        .{ .frame_type = constants.frame_type_rst_stream, .payload = "\x00\x00\x00\x08" },
        .{ .frame_type = constants.frame_type_window_update, .payload = "\x00\x00\x00\x64" },
    };
    for (cases) |case| {
        try start_server();
        const bytes = try frame_bytes(test_input, case.frame_type, 0, 1, case.payload);
        try testing.expectEqual(error.ConnectionFailed, test_connection.receive(bytes, 0));
        try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
    }
}

test "http2/5.1.1/2: a HEADERS frame on an identifier below the watermark ends the connection" {
    try start_server();
    _ = try feed_request(5, "/", true);
    try testing.expectEqual(5, test_connection.streams.highest_peer_opened_id);
    var block: [constants.frame_size_max]u8 = undefined;
    const fragment = try connection.request_block(&block, "/");
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const bytes = try frame_bytes(test_input, constants.frame_type_headers, flags, 3, fragment);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(bytes, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "http2/5.1/5 and /6: DATA or a second HEADERS after END_STREAM is a stream error of STREAM_CLOSED" {
    try start_server();
    _ = try feed_request(1, "/", true);
    const data = try frame_bytes(test_input, constants.frame_type_data, 0, 1, "test");
    const event = (try feed(data)).?;
    try testing.expectEqual(1, event.stream_refused.stream_id);
    try testing.expectEqual(constants.error_stream_closed, event.stream_refused.error_code);
    try expect_rst_stream(write_queued(), 1, constants.error_stream_closed);
}

test "http2/6.4: a RST_STREAM the peer sends closes the stream and is reported" {
    try start_server();
    _ = try feed_request(1, "/", false);
    try testing.expectEqual(1, test_connection.streams.peer_active);
    const reset = try frame_bytes(test_input, constants.frame_type_rst_stream, 0, 1, "\x00\x00\x00\x08");
    const event = (try feed(reset)).?;
    try testing.expectEqual(1, event.stream_reset.stream_id);
    try testing.expectEqual(constants.error_cancel, event.stream_reset.error_code);
    try testing.expectEqual(0, test_connection.streams.peer_active);
    try testing.expect(!test_connection.has_pending());
}

test "http2/6.9/2: a WINDOW_UPDATE of 0 on a stream is a stream error, and http2/6.9.1/3 overflow is one too" {
    try start_server();
    _ = try feed_request(1, "/", false);
    const zero = try frame_bytes(test_input, constants.frame_type_window_update, 0, 1, "\x00\x00\x00\x00");
    const refused = (try feed(zero)).?;
    try testing.expectEqual(constants.error_protocol_error, refused.stream_refused.error_code);
    try expect_rst_stream(write_queued(), 1, constants.error_protocol_error);
    try start_server();
    _ = try feed_request(3, "/", false);
    // The stream window starts at the initial value, so one maximal increment already passes it.
    const large = try frame_bytes(test_input, constants.frame_type_window_update, 0, 3, "\x7f\xff\xff\xff");
    const overflow = (try feed(large)).?;
    try testing.expectEqual(constants.error_flow_control_error, overflow.stream_refused.error_code);
    try expect_rst_stream(write_queued(), 3, constants.error_flow_control_error);
}

test "generic/2/1: a PRIORITY frame on any stream is parsed and changes nothing (decision 18)" {
    try start_server();
    const idle = try frame_bytes(test_input, constants.frame_type_priority, 0, 1, "\x00\x00\x00\x00\xff");
    try testing.expectEqual(null, try feed(idle));
    try testing.expect(!test_connection.has_pending());
    try testing.expectEqual(0, test_connection.streams.len());
    _ = try feed_request(1, "/", false);
    const open = try frame_bytes(test_input, constants.frame_type_priority, 0, 1, "\x00\x00\x00\x00\x07");
    try testing.expectEqual(null, try feed(open));
    try testing.expectEqual(1, test_connection.streams.peer_active);
}

test "the frames that follow a RST_STREAM colibri sent are discarded (§5.1)" {
    try start_server();
    _ = try feed_request(1, "/", false);
    const zero = try frame_bytes(test_input, constants.frame_type_window_update, 0, 1, "\x00\x00\x00\x00");
    _ = try feed(zero);
    _ = write_queued();
    // The stream is closed by colibri's reset, and the peer is still sending on it.
    const data = try frame_bytes(test_input, constants.frame_type_data, 0, 1, "test");
    try testing.expectEqual(null, try feed(data));
    const reset = try frame_bytes(test_input, constants.frame_type_rst_stream, 0, 1, "\x00\x00\x00\x08");
    try testing.expectEqual(null, try feed(reset));
    try testing.expect(!test_connection.has_pending());
}

test "§10.5: more than rst_stream_rate_max resets in one period ends the connection" {
    try start_server();
    var id: u32 = 1;
    for (0..constants.rst_stream_rate_max) |_| {
        _ = try feed_request(id, "/", false);
        const zero = try frame_bytes(test_input, constants.frame_type_window_update, 0, id, "\x00\x00\x00\x00");
        _ = try feed(zero);
        _ = write_queued();
        id += constants.stream_id_step;
    }
    try testing.expectEqual(constants.rst_stream_rate_max, test_connection.rst_stream_sent);
    _ = try feed_request(id, "/", false);
    const zero = try frame_bytes(test_input, constants.frame_type_window_update, 0, id, "\x00\x00\x00\x00");
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(zero, 0));
    try testing.expectEqual(constants.error_enhance_your_calm, test_connection.failure.?);
}

test "the reset count starts again in the next period" {
    try start_server();
    _ = try feed_request(1, "/", false);
    const zero = try frame_bytes(test_input, constants.frame_type_window_update, 0, 1, "\x00\x00\x00\x00");
    _ = try test_connection.receive(zero, 0);
    try testing.expectEqual(1, test_connection.rst_stream_sent);
    _ = write_queued();
    _ = try feed_request(3, "/", false);
    const other = try frame_bytes(test_input, constants.frame_type_window_update, 0, 3, "\x00\x00\x00\x00");
    _ = try test_connection.receive(other, constants.rst_stream_rate_period_ns);
    try testing.expectEqual(1, test_connection.rst_stream_sent);
    try testing.expectEqual(constants.rst_stream_rate_period_ns, test_connection.rst_stream_period_start_ns);
}
