//! The tests of decision 110's send deadlines in a server connection over TCP
//! (`connection_sends.zig`): a peer that takes too little of what the connection holds for it, or
//! in h2 opens a stream's window too slowly, is cut at its window's end, and a connection that has
//! ended closes once its last octets are out or its linger passes.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");
const deadline_support = @import("connection_deadline_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const server_constants = support.server_constants;
const receive_at = deadline_support.receive_at;
const send_at = deadline_support.send_at;
const early_ns = deadline_support.early_ns;
const Deadline = @import("../deadline.zig").Deadline;

const grace_ns = server_constants.rate_grace_ns;
const window_ns = server_constants.rate_window_ns;
const linger_ns = server_constants.close_linger_ns;
const first_end_ns = early_ns + grace_ns + window_ns;
/// The octets each window owes at the default send rate.
const quota: usize = server_constants.send_rate_min * (window_ns / server_constants.nanoseconds_per_second);

const whole_request = "GET / HTTP/1.1\r\nHost: h\r\n\r\n";
const head_begun = "GET / HT";
/// An answer longer than the octets the tests' peer takes at once, and the status it carries: 200
/// (OK), RFC 9110 §15.3.1.
const content: [answer_len]u8 = @splat('a');
const answer_len: usize = answer_windows * quota;
/// The windows of quota an answer holds: past the two a test's peer takes in full.
const answer_windows: usize = 3;
const ok_status: u16 = 200;
/// The octets a test's peer takes in one `send`.
const taken_len: usize = 64;

/// Answers the h11 request `receive_at` read with `content`, and has the peer take `taken_len`
/// octets of it at `early_ns`, so the rest waits in the output.
fn answer_slowly() !void {
    const id = (try receive_at(whole_request, early_ns)).event.?.request.id;
    try connection.respond(id, .{ .status = ok_status, .end = false });
    _ = try connection.write_body(id, .{ .octets = &content, .end = true });
    try testing.expectEqual(taken_len, connection.send(support.output[0..taken_len], early_ns));
}

/// The peer takes `len` octets at `now_ns`.
fn take(len: usize, now_ns: u64) usize {
    return connection.send(support.output[0..len], now_ns);
}

test "decision 110: a peer that takes too little of what the connection holds is cut when its window ends" {
    try support.start_cleartext(.h11);
    try answer_slowly();
    try testing.expectEqual(first_end_ns, connection.deadline_ns().?);
    try testing.expectEqual(quota - 1, take(quota - 1, early_ns + 1));
    connection.on_instant(first_end_ns - 1);
    try testing.expectEqual(null, connection.close_reason());
    connection.on_instant(first_end_ns);
    try testing.expectEqual(.send_rate, connection.close_reason().?.deadline);
    // RFC 9112 §9.6: nothing more goes out, and the connection closes when its linger passes.
    try testing.expect(!connection.should_close());
    try testing.expectEqual(first_end_ns + linger_ns, connection.deadline_ns().?);
    connection.on_instant(first_end_ns + linger_ns - 1);
    try testing.expect(!connection.should_close());
    connection.on_instant(first_end_ns + linger_ns);
    try testing.expect(connection.should_close());
}

test "decision 110: a peer that takes the quota each window is not cut, and an empty output stops the meter" {
    try support.start_cleartext(.h11);
    try answer_slowly();
    try testing.expectEqual(quota, take(quota, early_ns + 1));
    try testing.expectEqual(first_end_ns + window_ns, connection.deadline_ns().?);
    try testing.expectEqual(quota, take(quota, first_end_ns));
    connection.on_instant(first_end_ns + window_ns);
    try testing.expectEqual(null, connection.close_reason());
    _ = send_at(first_end_ns + window_ns);
    // The response is out, and only the idle deadline runs.
    try testing.expectEqual(first_end_ns + window_ns + server_constants.idle_timeout_ns, connection.deadline_ns().?);
}

test "decision 110: a connection a deadline ended closes at its linger when the peer takes nothing, and at once when it takes all" {
    try support.start_cleartext(.h11);
    _ = try receive_at(head_begun, early_ns);
    const ended_ns = server_constants.first_request_timeout_ns;
    connection.on_instant(ended_ns);
    // The 408 waits: the peer's socket takes nothing.
    try testing.expectEqual(0, take(0, ended_ns));
    try testing.expect(!connection.should_close());
    connection.on_instant(ended_ns + linger_ns);
    try testing.expect(connection.should_close());
    try support.start_cleartext(.h11);
    _ = try receive_at(head_begun, early_ns);
    connection.on_instant(ended_ns);
    _ = send_at(ended_ns);
    try testing.expect(connection.should_close());
}

test "decision 110: with no send rate and no linger, a connection waits on its peer" {
    try support.start_cleartext(.h11);
    try connection.set_deadlines(.{ .send_rate_min = null, .linger_ns = null });
    try answer_slowly();
    try testing.expectEqual(null, connection.deadline_ns());
    connection.on_instant(first_end_ns + window_ns);
    try testing.expectEqual(null, connection.close_reason());
}

/// An h2 connection whose client asked for streams with a window of `stream_window` octets, and
/// a request on stream 1 whose answer began and whose content, once the window is spent, waits on
/// it.
fn answer_blocked(stream_window: u32) !void {
    try h2_support.start();
    var frame: [h2.constants.frame_header_len + h2.constants.setting_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_settings(&writer, &.{.{ .id = h2.constants.setting_initial_window_size, .value = stream_window }});
    _ = try receive_at(writer.written(), early_ns);
    _ = try receive_at(try h2_support.request_frame(1, "/", true), early_ns);
    try connection.respond(1, .{ .status = ok_status, .end = false });
    const written = connection.write_body(1, .{ .octets = &content, .end = true }) catch 0;
    try testing.expectError(error.Blocked, connection.write_body(1, .{ .octets = content[written..], .end = true }));
}

test "RFC 9113 §10.5: a stream whose window stays under the floor is reset with CANCEL when its window ends" {
    // The client's windows start at the floor, so the floor holds the frames it opens less for.
    try answer_blocked(floor_len);
    _ = send_at(early_ns);
    try testing.expectEqual(first_end_ns, connection.deadline_ns().?);
    // The client opens the window by less than the floor, so no frame goes out.
    var frame: [h2.constants.frame_header_len + h2.constants.window_update_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_window_update(&writer, 1, server_constants.data_frame_len_min - 1);
    _ = try receive_at(writer.written(), early_ns + 1);
    try testing.expectError(error.Blocked, connection.write_body(1, .{ .octets = &content, .end = true }));
    connection.on_instant(first_end_ns);
    // The stream ends, and the connection goes on.
    try testing.expectEqual(null, connection.close_reason());
    try testing.expectEqual(h2.constants.error_cancel, try deadline_support.reset_code(send_at(first_end_ns), 1));
    const cancelled = (try connection.receive(&.{}, first_end_ns)).event.?.cancelled;
    try testing.expectEqual(1, cancelled.id);
    try testing.expectEqual(Deadline.send_rate, cancelled.reason.deadline);
}

test "decision 110: a stream's window meter waits while the connection holds other octets" {
    try answer_blocked(0);
    // The HEADERS frame stays in the output: the peer takes nothing.
    try testing.expectEqual(0, take(0, early_ns));
    connection.on_instant(first_end_ns);
    // The connection's meter judges it, not the stream's.
    try testing.expectEqual(.send_rate, connection.close_reason().?.deadline);
}

test "decision 110: a stream the connection's window holds ends the connection with ENHANCE_YOUR_CALM" {
    try h2_support.start();
    _ = try receive_at(try h2_support.request_frame(1, "/", true), early_ns);
    try connection.respond(1, .{ .status = ok_status, .end = false });
    connection.session.h2.send_window = h2.window.Window.init(server_constants.data_frame_len_min - 1);
    try testing.expectError(error.Blocked, connection.write_body(1, .{ .octets = &content, .end = true }));
    _ = send_at(early_ns);
    connection.on_instant(first_end_ns);
    try testing.expectEqual(.send_rate, connection.close_reason().?.deadline);
    try testing.expectEqual(h2.constants.error_enhance_your_calm, try deadline_support.goaway_code(send_at(first_end_ns)));
}

/// Whether `receive` owes nothing more at `now_ns`.
fn nothing_owed(now_ns: u64) !bool {
    return (try connection.receive(&.{}, now_ns)).event == null;
}

test "decision 110: a stream held by its window that ends, or is cancelled, runs no send deadline" {
    // The caller ends the response with trailers before its content is out.
    try answer_blocked(0);
    try connection.write_trailers(1, &.{.{ .name = "checksum", .value = "1" }});
    _ = send_at(early_ns);
    try testing.expectEqual(1, (try connection.receive(&.{}, early_ns)).event.?.done.id);
    connection.on_instant(first_end_ns);
    try testing.expect(try nothing_owed(first_end_ns));
    // The peer resets the stream.
    try answer_blocked(0);
    _ = send_at(early_ns);
    var frame: [h2.constants.frame_header_len + h2.constants.rst_stream_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_rst_stream(&writer, 1, h2.constants.error_cancel);
    try testing.expect((try receive_at(writer.written(), early_ns + 1)).event.?.cancelled.reason == .peer_reset);
    connection.on_instant(first_end_ns);
    try testing.expect(try nothing_owed(first_end_ns));
    // The caller cancels the request.
    try answer_blocked(0);
    _ = send_at(early_ns);
    connection.cancel(1);
    connection.on_instant(first_end_ns);
    try testing.expect(try nothing_owed(first_end_ns));
}

/// An h2 connection with streams of window 0, and an upload on stream 1 whose answer began and
/// whose content waits on the window.
fn upload_blocked() !void {
    try h2_support.start();
    var frame: [h2.constants.frame_header_len + h2.constants.setting_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_settings(&writer, &.{.{ .id = h2.constants.setting_initial_window_size, .value = 0 }});
    _ = try receive_at(writer.written(), early_ns);
    _ = try receive_at(try h2_support.request_frame_with(1, "POST", "/u", &.{}, false), early_ns);
    try connection.respond(1, .{ .status = ok_status, .end = false });
    try testing.expectError(error.Blocked, connection.write_body(1, .{ .octets = &content, .end = true }));
    _ = send_at(early_ns);
}

test "decision 110: a stream a body deadline ends owes one cancelled, not a second for its send" {
    try upload_blocked();
    connection.on_instant(first_end_ns);
    try testing.expectEqual(Deadline.body_rate, (try connection.receive(&.{}, first_end_ns)).event.?.cancelled.reason.deadline);
    try testing.expect(try nothing_owed(first_end_ns));
}

test "decision 110: a stream a send deadline ends owes one cancelled, not a second for its body" {
    try upload_blocked();
    // The body keeps its rate for a window, so the send deadline passes first.
    _ = try receive_at(try deadline_support.data_frame(1, content[0..quota], false, 0), early_ns + 1);
    connection.on_instant(first_end_ns);
    try testing.expectEqual(Deadline.send_rate, (try connection.receive(&.{}, first_end_ns)).event.?.cancelled.reason.deadline);
    connection.on_instant(first_end_ns + window_ns);
    try testing.expect(try nothing_owed(first_end_ns + window_ns));
}

/// A WINDOW_UPDATE frame for `stream_id` adding `increment` octets.
fn window_update(stream_id: u32, increment: u32) ![h2.constants.frame_header_len + h2.constants.window_update_len]u8 {
    var frame: [h2.constants.frame_header_len + h2.constants.window_update_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_window_update(&writer, stream_id, increment);
    return frame;
}

const second_ns: u64 = server_constants.nanoseconds_per_second;
const floor_len: u32 = server_constants.data_frame_len_min;

test "decision 110: a stream whose window opens a floor at a time, at the rate, is not cut" {
    try answer_blocked(0);
    _ = send_at(early_ns);
    var written: usize = 0;
    // A floor a second: the quota each window, the first window's octets counted in it, and the
    // octets at its end in the next.
    const windows_len = (grace_ns + 2 * window_ns) / second_ns;
    for (1..windows_len) |k| {
        const now_ns = early_ns + k * second_ns;
        _ = try receive_at(&(try window_update(1, floor_len)), now_ns);
        written += try connection.write_body(1, .{ .octets = content[written..], .end = true });
        _ = send_at(now_ns);
    }
    connection.on_instant(first_end_ns + window_ns);
    try testing.expectEqual(null, connection.close_reason());
    try testing.expect(try nothing_owed(first_end_ns + window_ns));
}

test "decision 110: a stream whose window lets a write through is held no more" {
    try answer_blocked(0);
    _ = send_at(early_ns);
    _ = try receive_at(&(try window_update(1, answer_len)), early_ns + 1);
    // One frame goes out, and the caller writes no more for a while.
    try testing.expect(try connection.write_body(1, .{ .octets = &content, .end = true }) > 0);
    _ = send_at(early_ns + 1);
    connection.on_instant(first_end_ns + window_ns);
    try testing.expect(try nothing_owed(first_end_ns + window_ns));
}

test "decision 110: a stream's window meter does not run while another stream's octets fill the output" {
    try answer_blocked(0);
    // Stream 3's answer fills the output, and its window lets it all through.
    _ = try receive_at(try h2_support.request_frame(3, "/", true), early_ns);
    _ = try receive_at(&(try window_update(3, answer_len)), early_ns);
    try connection.respond(3, .{ .status = ok_status, .end = false });
    var written: usize = 0;
    for (0..answer_windows + 1) |_| {
        written += connection.write_body(3, .{ .octets = content[written..], .end = true }) catch break;
    }
    // The peer takes a quota each window, so the connection's meter holds.
    try testing.expectEqual(quota, take(quota, early_ns + 1));
    try testing.expectEqual(quota, take(quota, first_end_ns));
    connection.on_instant(first_end_ns);
    try testing.expectEqual(null, connection.close_reason());
    // Stream 3's answer is done, and stream 1 is not cut.
    try testing.expectEqual(3, (try connection.receive(&.{}, first_end_ns)).event.?.done.id);
    try testing.expect(try nothing_owed(first_end_ns));
}
