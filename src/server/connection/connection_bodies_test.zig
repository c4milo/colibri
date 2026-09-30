//! The tests of decision 110's body deadlines in a server connection over TCP
//! (`connection_bodies.zig`): a body under the minimum rate or past its cap ends at its instant,
//! in h11 with the connection and in h2 with its stream, and h2's bodies together keep the rate.
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
const idle_ns = server_constants.idle_timeout_ns;
/// The octets each window owes at the default rate.
const quota: usize = server_constants.body_rate_min * (window_ns / server_constants.nanoseconds_per_second);
const first_end_ns = early_ns + grace_ns + window_ns;

/// A request whose Content-Length is more than any test sends, one with a body of five octets,
/// the same owed a 100 (Continue), and the octets of the bodies the tests send.
const upload_head = "POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 1000000\r\n\r\n";
const short_head = "POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\n";
const continue_head = "POST /u HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n";
const short_body_len: usize = 5;
const filler: [support.input_len]u8 = @splat('b');

/// The statuses the tests answer with and look for: 200 (OK) and 408 (Request Timeout), RFC 9110
/// §15.3.1 and §15.5.9.
const ok_status: u16 = 200;
const timeout_status: u16 = 408;

/// Reads all of `octets` at `now_ns`, a call at a time.
fn feed(octets: []const u8, now_ns: u64) !void {
    var taken: usize = 0;
    // Bounded: each pass takes an octet at least.
    for (0..octets.len) |_| {
        if (taken == octets.len) return;
        const received = try receive_at(octets[taken..], now_ns);
        if (received.consumed == 0) return error.TestUnexpectedResult;
        taken += received.consumed;
    }
}

/// Opens an h2 stream whose body follows, at `now_ns`.
fn open_upload(stream_id: u32, now_ns: u64) !void {
    const received = try receive_at(try h2_support.request_frame_with(stream_id, "POST", "/u", &.{}, false), now_ns);
    try testing.expect(!received.event.?.request.end);
}

test "decision 110: an h11 body under the minimum rate gets a 408 when its first window ends" {
    try support.start_cleartext(.h11);
    try testing.expect(!(try receive_at(upload_head, early_ns)).event.?.request.end);
    try testing.expectEqual(first_end_ns, connection.deadline_ns().?);
    try feed(filler[0 .. quota - 1], early_ns + 1);
    connection.on_instant(first_end_ns - 1);
    try testing.expectEqual(null, connection.close_reason());
    connection.on_instant(first_end_ns);
    try testing.expectEqual(.body_rate, connection.close_reason().?.deadline);
    try testing.expect(std.mem.startsWith(u8, send_at(first_end_ns), "HTTP/1.1 408 Request Timeout\r\n"));
    try testing.expect(connection.should_close());
}

test "decision 110: each window owes the quota, and octets at a window's end count in the next" {
    try support.start_cleartext(.h11);
    _ = try receive_at(upload_head, early_ns);
    try feed(filler[0..quota], early_ns + 1);
    // A window that holds its quota is looked at next when the window after it ends.
    try testing.expectEqual(first_end_ns + window_ns, connection.deadline_ns().?);
    try feed(filler[0 .. quota - 1], first_end_ns);
    connection.on_instant(first_end_ns + window_ns - 1);
    try testing.expectEqual(null, connection.close_reason());
    connection.on_instant(first_end_ns + window_ns);
    try testing.expectEqual(.body_rate, connection.close_reason().?.deadline);
}

test "decision 110: a body that keeps the rate still ends at its cap" {
    try support.start_cleartext(.h11);
    const cap_ns = grace_ns + window_ns + window_ns / 2;
    try connection.set_deadlines(.{ .body_ns = cap_ns });
    _ = try receive_at(upload_head, early_ns);
    try feed(filler[0..quota], early_ns + 1);
    try testing.expectEqual(early_ns + cap_ns, connection.deadline_ns().?);
    connection.on_instant(early_ns + cap_ns - 1);
    try testing.expectEqual(null, connection.close_reason());
    connection.on_instant(early_ns + cap_ns);
    try testing.expectEqual(.body, connection.close_reason().?.deadline);
    try testing.expect(std.mem.startsWith(u8, send_at(early_ns + cap_ns), "HTTP/1.1 408 "));
}

test "decision 110: a body that ends, or has no limits, runs no deadline" {
    try support.start_cleartext(.h11);
    _ = try receive_at(short_head, early_ns);
    try feed(filler[0..short_body_len], early_ns + 1);
    // h11 reports the body's end on the call after its last octet.
    try testing.expect((try connection.receive(&.{}, early_ns + 1)).event.?.body.end);
    try testing.expectEqual(null, connection.deadline_ns());
    try support.start_cleartext(.h11);
    try connection.set_deadlines(.{ .body_rate_min = null, .body_ns = null });
    _ = try receive_at(upload_head, early_ns);
    try testing.expectEqual(null, connection.deadline_ns());
}

test "decision 110: an h11 body that falls short after its response began closes without a 408" {
    try support.start_cleartext(.h11);
    const request = try receive_at(upload_head, early_ns);
    try connection.respond(request.event.?.request.id, .{ .status = ok_status, .end = false });
    _ = send_at(early_ns);
    connection.on_instant(first_end_ns);
    try testing.expectEqual(.body_rate, connection.close_reason().?.deadline);
    try testing.expectEqual(0, send_at(first_end_ns).len);
    try testing.expect(connection.should_close());
}

test "RFC 9112 §9.3: no deadline runs once h11 closes after a response to a request it did not read whole" {
    try support.start_cleartext(.h11);
    const request = try receive_at(upload_head, early_ns);
    try connection.respond(request.event.?.request.id, .{ .status = deadline_support.no_content, .end = true });
    _ = send_at(early_ns);
    try testing.expectEqual(null, connection.deadline_ns());
    connection.on_instant(first_end_ns);
    try testing.expectEqual(null, connection.close_reason());
}

test "RFC 9110 §10.1.1: a body owed a 100 (Continue) starts its wait when the 100 is written" {
    try support.start_cleartext(.h11);
    _ = try receive_at(continue_head, early_ns);
    try testing.expectEqual(null, connection.deadline_ns());
    try testing.expect(std.mem.startsWith(u8, send_at(early_ns + 1), "HTTP/1.1 100 Continue\r\n"));
    try testing.expectEqual(first_end_ns + 1, connection.deadline_ns().?);
}

test "RFC 9113 §8.1: an h2 body under the rate gets a 408 and RST_STREAM with NO_ERROR, and the caller reads cancelled" {
    try h2_support.start();
    try open_upload(1, early_ns);
    try testing.expectEqual(first_end_ns, connection.deadline_ns().?);
    connection.on_instant(first_end_ns);
    // The stream ends, and the connection goes on.
    try testing.expectEqual(null, connection.close_reason());
    const sent = send_at(first_end_ns);
    try testing.expectEqual(timeout_status, try deadline_support.response_status(sent, 1));
    try testing.expectEqual(h2.constants.error_no_error, try deadline_support.reset_code(sent, 1));
    const cancelled = (try connection.receive(&.{}, first_end_ns)).event.?.cancelled;
    try testing.expectEqual(1, cancelled.id);
    try testing.expectEqual(Deadline.body_rate, cancelled.reason.deadline);
    // With no stream open, the idle deadline runs.
    try testing.expectEqual(first_end_ns + idle_ns, connection.deadline_ns().?);
}

test "RFC 9113 §6.4: an h2 body that falls short after its response began is reset with CANCEL" {
    try h2_support.start();
    try open_upload(1, early_ns);
    try connection.respond(1, .{ .status = ok_status, .end = false });
    _ = send_at(early_ns);
    connection.on_instant(first_end_ns);
    const sent = send_at(first_end_ns);
    try testing.expectEqual(null, deadline_support.find_frame(sent, h2.constants.frame_type_headers, 1));
    try testing.expectEqual(h2.constants.error_cancel, try deadline_support.reset_code(sent, 1));
    try testing.expectEqual(Deadline.body_rate, (try connection.receive(&.{}, first_end_ns)).event.?.cancelled.reason.deadline);
}

test "decision 110: an h2 body past its cap is cancelled for the cap" {
    try h2_support.start();
    const cap_ns = grace_ns + window_ns / 2;
    try connection.set_deadlines(.{ .body_ns = cap_ns });
    try open_upload(1, early_ns);
    connection.on_instant(early_ns + cap_ns);
    try testing.expectEqual(timeout_status, try deadline_support.response_status(send_at(early_ns + cap_ns), 1));
    try testing.expectEqual(Deadline.body, (try connection.receive(&.{}, early_ns + cap_ns)).event.?.cancelled.reason.deadline);
}

test "decision 110: h2 bodies that together fall under the rate end the connection with ENHANCE_YOUR_CALM" {
    try h2_support.start();
    // Stream 1 brings the first window's quota and ends; stream 3, begun later, brings nothing.
    try open_upload(1, early_ns);
    _ = try receive_at(try deadline_support.data_frame(1, filler[0..quota], false, 0), early_ns + 1);
    try open_upload(3, early_ns + grace_ns + window_ns / 2);
    _ = try receive_at(try deadline_support.data_frame(1, &.{}, true, 0), early_ns + grace_ns + window_ns / 2 + 1);
    // The connection's second window ends before stream 3's first one.
    const together_end_ns = first_end_ns + window_ns;
    try testing.expectEqual(together_end_ns, connection.deadline_ns().?);
    connection.on_instant(together_end_ns);
    try testing.expectEqual(.body_rate, connection.close_reason().?.deadline);
    try testing.expectEqual(h2.constants.error_enhance_your_calm, try deadline_support.goaway_code(send_at(together_end_ns)));
}

test "decision 110: only a body's own octets count, not an h2 DATA frame's padding or a PING" {
    try h2_support.start();
    try open_upload(1, early_ns);
    const padding_len: u8 = 255;
    _ = try receive_at(try deadline_support.data_frame(1, filler[0 .. quota - 1], false, padding_len), early_ns + 1);
    _ = try receive_at(&(try deadline_support.ping_frame()), early_ns + 2);
    connection.on_instant(first_end_ns);
    try testing.expectEqual(Deadline.body_rate, (try connection.receive(&.{}, first_end_ns)).event.?.cancelled.reason.deadline);
}

test "RFC 9113 §8.2.1: a request colibri refuses as malformed is cancelled as refused" {
    try h2_support.start();
    const upper = [_]support.Field{.{ .name = "X-Upper", .value = "1" }};
    const cancelled = (try receive_at(try h2_support.request_frame_with(1, "GET", "/", &upper, true), early_ns)).event.?.cancelled;
    try testing.expectEqual(1, cancelled.id);
    try testing.expect(cancelled.reason == .refused);
}

test "decision 110: a body ended by trailers, or a request the peer resets or the caller cancels, runs no body deadline" {
    try h2_support.start();
    try open_upload(1, early_ns);
    const trailer = [_]support.Field{.{ .name = "checksum", .value = "1" }};
    try testing.expectEqual(1, (try receive_at(try trailers_frame(1, &trailer), early_ns + 1)).event.?.trailers.id);
    try open_upload(3, early_ns + 2);
    var writer = h2.core.Writer.init(&deadline_support.data_frames);
    try h2.frame.write_rst_stream(&writer, 3, h2.constants.error_cancel);
    try testing.expect((try receive_at(writer.written(), early_ns + 3)).event.?.cancelled.reason == .peer_reset);
    try open_upload(5, early_ns + 4);
    connection.cancel(5);
    // Stream 1 waits on the application, and no body deadline runs.
    try testing.expectEqual(null, connection.deadline_ns());
    connection.on_instant(first_end_ns + window_ns);
    try testing.expectEqual(null, connection.close_reason());
    try testing.expectEqual(null, (try connection.receive(&.{}, first_end_ns + window_ns)).event);
}

/// A HEADERS frame carrying `fields` as a trailer section on `stream_id`, ending the stream.
fn trailers_frame(stream_id: u32, fields: []const support.Field) ![]const u8 {
    var block: [h2.constants.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2.constants.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    for (fields) |field| try encoder.write_field(&block_writer, field.name, field.value, .without_indexing);
    encoder.commit_block();
    var writer = h2.core.Writer.init(&deadline_support.data_frames);
    try h2.frame.write_headers(&writer, stream_id, block_writer.written(), true, true, 0, null);
    return writer.written();
}
