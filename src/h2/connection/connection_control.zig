//! The frames that concern the whole connection and name no stream: SETTINGS (RFC 9113 §6.5),
//! PING (§6.7), GOAWAY (§6.8) and the WINDOW_UPDATE on stream 0 (§6.9). Split off
//! `connection_receive.zig`, which decides which of these a frame is.
//!
//! The peer's settings are applied in the order the frame lists them (§6.5.3), and the frame is
//! acknowledged only once every value in it was accepted: a refusal ends the connection, so there
//! is nothing left to acknowledge. Two settings do more than change a number. A new
//! SETTINGS_INITIAL_WINDOW_SIZE moves the send window of every stream at once (§6.9.2), which is
//! the sweep `streams_window.zig` runs. A new SETTINGS_HEADER_TABLE_SIZE is given to colibri's
//! encoder as soon as it is read, rather than when the acknowledgment is written: §4.3.1 lets the
//! encoder use a table no larger than the limit the peer last sent, and reading it early only ever
//! makes colibri's table smaller than the peer allows.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const settings = @import("../settings.zig");
const window = @import("../window.zig");
const connection = @import("connection.zig");

const Connection = connection.Connection;
const Event = connection.Event;
const Error = connection.Error;

/// Applies one SETTINGS frame, or the peer's acknowledgment of one colibri sent (RFC 9113 §6.5.3).
pub fn on_settings(target: *Connection, values: frame.Settings) Error!?Event {
    if (values.ack) return acknowledge(target);
    var entries = values.iterator();
    while (entries.next()) |entry| try apply_one(target, entry.id, entry.value);
    // RFC 9113 §6.5.3: the receiver acknowledges the frame once it has applied every value in it.
    target.replies.push_settings_ack();
    return .settings_applied;
}

/// Reads the peer's acknowledgment of the oldest SETTINGS frame colibri sent, which puts those
/// values in force (RFC 9113 §6.5.3).
fn acknowledge(target: *Connection) ?Event {
    // RFC 9113 §6.5.3 gives no rule for an acknowledgment of a frame that was never sent, so
    // colibri discards it, as it discards a PING acknowledgment it did not ask for (§6.7).
    const acknowledged = target.pending.acknowledge() orelse return null;
    target.local = acknowledged;
    return .settings_acknowledged;
}

/// Applies one (identifier, value) pair to the peer's settings, and does what the two settings
/// that change more than a number ask for.
fn apply_one(target: *Connection, id: u16, value: u32) Error!void {
    const change = settings.apply(&target.peer, id, value, target.role) catch |failure| {
        return target.fail(apply_error_code(failure));
    };
    switch (change orelse return) {
        .initial_window_size => |sizes| try adjust_windows(target, sizes),
        // RFC 9113 §4.3.1: the peer's SETTINGS_HEADER_TABLE_SIZE is the largest dynamic table
        // colibri's encoder may use. The file header says why it is read now and not at the
        // acknowledgment.
        .header_table_size => |size| target.encoder.set_capacity_limit(size),
        .other => {},
    }
}

/// The connection error code RFC 9113 §6.5.2 gives each refused value.
fn apply_error_code(failure: settings.ApplyError) u32 {
    return switch (failure) {
        // RFC 9113 §6.5.2: a SETTINGS_INITIAL_WINDOW_SIZE above 2^31 - 1 is a connection error of
        // FLOW_CONTROL_ERROR.
        error.InitialWindowSizeTooLarge => constants.error_flow_control_error,
        // RFC 9113 §6.5.2: an ENABLE_PUSH other than 0 or 1, an ENABLE_PUSH of 1 from a server and
        // a SETTINGS_MAX_FRAME_SIZE outside its range are connection errors of PROTOCOL_ERROR.
        error.EnablePushInvalid, error.EnablePushByServer, error.MaxFrameSizeOutOfRange => constants.error_protocol_error,
    };
}

/// Moves every stream's send window by the change in SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113
/// §6.9.2). The connection's own window is not one of them: §6.9.2 changes stream windows alone.
fn adjust_windows(target: *Connection, sizes: settings.WindowChange) Error!void {
    const delta = window.initial_window_delta(sizes.old, sizes.new);
    target.streams.adjust_send_windows(delta) catch {
        // RFC 9113 §6.9.2: a change that makes a flow-control window exceed the maximum is a
        // connection error of FLOW_CONTROL_ERROR.
        return target.fail(constants.error_flow_control_error);
    };
}

/// Answers a PING the peer sent, or reads its answer to one colibri sent (RFC 9113 §6.7).
pub fn on_ping(target: *Connection, ping: frame.Ping) ?Event {
    // RFC 9113 §6.7: an endpoint answers a PING without the ACK flag with one that carries the
    // same Opaque Data and the flag set, and answers nothing else.
    if (!ping.ack) {
        target.replies.push_ping_ack(ping.opaque_data);
        return null;
    }
    return .{ .ping_acknowledged = ping.opaque_data };
}

/// Reads the GOAWAY the peer sent (RFC 9113 §6.8).
pub fn on_goaway(target: *Connection, goaway: frame.Goaway) Error!?Event {
    target.streams.record_goaway_received(goaway.last_stream_id) catch {
        // RFC 9113 §6.8: an endpoint MUST treat a GOAWAY whose last stream identifier is higher
        // than a previous one as a connection error of PROTOCOL_ERROR (invariant 16).
        return target.fail(constants.error_protocol_error);
    };
    return .{ .goaway = .{ .last_stream_id = goaway.last_stream_id, .error_code = goaway.error_code } };
}

/// Adds the increment of a WINDOW_UPDATE on stream 0 to the connection's send window (RFC 9113
/// §6.9). The parser refused an increment of 0 before this.
pub fn on_window_update(target: *Connection, update: frame.WindowUpdate) Error!?Event {
    target.send_window.add(update.increment) catch {
        // RFC 9113 §6.9.1: an increment that takes the window above 2^31 - 1 is a connection error
        // of FLOW_CONTROL_ERROR on the connection's window.
        return target.fail(constants.error_flow_control_error);
    };
    return null;
}

const testing = std.testing;
const Writer = @import("core").Writer;
const test_connection = &connection.test_connection;
const feed = connection.feed;
const frame_bytes = connection.frame_bytes;
const start_server = connection.start_server;
const write_queued = connection.write_queued;
const test_input = &connection.test_input;

/// Writes a SETTINGS frame carrying one setting. Test-only.
fn settings_frame(id: u16, value: u32) ![]const u8 {
    var payload: [constants.setting_len]u8 = undefined;
    var writer = Writer.init(&payload);
    try writer.write_int(u16, id);
    try writer.write_int(u32, value);
    return frame_bytes(test_input, constants.frame_type_settings, 0, 0, writer.written());
}

test "http2/6.5.3/2: a SETTINGS frame is applied and acknowledged, and the peer's values are kept" {
    try start_server();
    const event = try feed(try settings_frame(constants.setting_max_concurrent_streams, 100));
    try testing.expectEqual(connection.Event.settings_applied, event.?);
    try testing.expectEqual(100, test_connection.peer.max_concurrent_streams.?);
    try testing.expectEqualStrings("\x00\x00\x00\x04\x01\x00\x00\x00\x00", write_queued());
}

test "http2/6.5.3/1: the settings of one frame are applied in the order they appear" {
    try start_server();
    var payload: [2 * constants.setting_len]u8 = undefined;
    var writer = Writer.init(&payload);
    try writer.write_int(u16, constants.setting_initial_window_size);
    try writer.write_int(u32, 100);
    try writer.write_int(u16, constants.setting_initial_window_size);
    try writer.write_int(u32, 1);
    const bytes = try frame_bytes(test_input, constants.frame_type_settings, 0, 0, writer.written());
    _ = try feed(bytes);
    try testing.expectEqual(1, test_connection.peer.initial_window_size);
}

test "http2/6.5.2: every value RFC 9113 §6.5.2 refuses ends the connection with the code it names" {
    const cases = [_]struct { id: u16, value: u32, code: u32 }{
        .{ .id = constants.setting_enable_push, .value = 2, .code = constants.error_protocol_error },
        .{ .id = constants.setting_initial_window_size, .value = 1 << 31, .code = constants.error_flow_control_error },
        .{ .id = constants.setting_max_frame_size, .value = 16383, .code = constants.error_protocol_error },
        .{ .id = constants.setting_max_frame_size, .value = 1 << 24, .code = constants.error_protocol_error },
    };
    for (cases) |case| {
        try start_server();
        const bytes = try settings_frame(case.id, case.value);
        try testing.expectEqual(error.ConnectionFailed, test_connection.receive(bytes, 0));
        try testing.expectEqual(case.code, test_connection.failure.?);
        // RFC 9113 §6.5.3: the acknowledgment says the values were applied, so a frame that was
        // refused is never acknowledged: the GOAWAY is the only frame left to write.
        const queued = write_queued();
        try testing.expectEqual(constants.frame_header_len + constants.goaway_len_min, queued.len);
        try testing.expectEqual(constants.frame_type_goaway, queued[3]);
    }
}

test "http2/6.5.2/5: a setting colibri does not know is ignored, and the frame is still acknowledged" {
    try start_server();
    const event = try feed(try settings_frame(0xff, 1));
    try testing.expectEqual(connection.Event.settings_applied, event.?);
    try testing.expectEqualStrings("\x00\x00\x00\x04\x01\x00\x00\x00\x00", write_queued());
}

test "the peer's acknowledgment puts colibri's own settings in force, and one it never asked for is ignored" {
    try start_server();
    try testing.expectEqual(1, test_connection.pending.len());
    const ack = try frame_bytes(test_input, constants.frame_type_settings, constants.flag_ack, 0, "");
    try testing.expectEqual(connection.Event.settings_acknowledged, (try feed(ack)).?);
    try testing.expectEqual(0, test_connection.pending.len());
    try testing.expectEqual(constants.concurrent_streams_max, test_connection.local.max_concurrent_streams.?);
    // RFC 9113 §6.5.3 gives no rule for a second acknowledgment, so colibri discards it.
    try testing.expectEqual(null, try feed(ack));
    try testing.expect(!test_connection.has_pending());
}

test "a new SETTINGS_INITIAL_WINDOW_SIZE moves every stream's send window, and an overflow is FLOW_CONTROL_ERROR" {
    try start_server();
    _ = try connection.feed_request(1, "/", false);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(constants.initial_window_size_initial, record.send_window.available);
    _ = try feed(try settings_frame(constants.setting_initial_window_size, 100));
    try testing.expectEqual(100, record.send_window.available);
    // RFC 9113 §6.9.2: a change that takes a window past the maximum ends the connection.
    try record.send_window.add(constants.window_max - 100);
    const bytes = try settings_frame(constants.setting_initial_window_size, 101);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(bytes, 0));
    try testing.expectEqual(constants.error_flow_control_error, test_connection.failure.?);
}

test "the peer's SETTINGS_HEADER_TABLE_SIZE becomes the limit on colibri's encoder (§4.3.1)" {
    try start_server();
    _ = try feed(try settings_frame(constants.setting_header_table_size, 256));
    try testing.expectEqual(256, test_connection.encoder.capacity_limit);
}

test "http2/6.7/1 and http2/6.7/2: a PING is answered with its own data, and an acknowledgment is not" {
    try start_server();
    const ping = try frame_bytes(test_input, constants.frame_type_ping, 0, 0, "h2spec\x00\x00");
    try testing.expectEqual(null, try feed(ping));
    try testing.expectEqualStrings("\x00\x00\x08\x06\x01\x00\x00\x00\x00h2spec\x00\x00", write_queued());
    const answer = try frame_bytes(test_input, constants.frame_type_ping, constants.flag_ack, 0, "invalid!");
    const event = try feed(answer);
    try testing.expectEqualStrings("invalid!", &event.?.ping_acknowledged);
    try testing.expect(!test_connection.has_pending());
}

test "http2/6.8: the peer's GOAWAY is reported, and a higher last stream identifier ends the connection" {
    try start_server();
    const first = try frame_bytes(test_input, constants.frame_type_goaway, 0, 0, "\x00\x00\x00\x05\x00\x00\x00\x00bye");
    const event = try feed(first);
    try testing.expectEqual(5, event.?.goaway.last_stream_id);
    try testing.expectEqual(constants.error_no_error, event.?.goaway.error_code);
    const lower = try frame_bytes(test_input, constants.frame_type_goaway, 0, 0, "\x00\x00\x00\x03\x00\x00\x00\x00");
    _ = try feed(lower);
    // RFC 9113 §6.8 and invariant 16: a later GOAWAY may not name a higher stream.
    const higher = try frame_bytes(test_input, constants.frame_type_goaway, 0, 0, "\x00\x00\x00\x07\x00\x00\x00\x00");
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(higher, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "http2/6.9.1/2: WINDOW_UPDATE on stream 0 adds to the connection window and overflow is FLOW_CONTROL_ERROR" {
    try start_server();
    const one = try frame_bytes(test_input, constants.frame_type_window_update, 0, 0, "\x00\x00\x00\x01");
    try testing.expectEqual(null, try feed(one));
    try testing.expectEqual(constants.initial_window_size_initial + 1, test_connection.send_window.available);
    // RFC 9113 §6.9.1: an increment that takes the window past 2^31 - 1 ends the connection.
    const large = try frame_bytes(test_input, constants.frame_type_window_update, 0, 0, "\x7f\xff\xff\xff");
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(large, 0));
    try testing.expectEqual(constants.error_flow_control_error, test_connection.failure.?);
}
