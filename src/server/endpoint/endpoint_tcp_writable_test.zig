//! The tests of `writable` over h11 and h2 (`endpoint_held_tcp.zig`, decision 119): content a
//! response's connection had no room for is writable once a `send_stream` empties its output, or
//! once the peer's WINDOW_UPDATE opens its stream's window.
const std = @import("std");
const h2 = @import("h2");
const support = @import("endpoint_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const server_constants = @import("../constants.zig");

const event = @import("../event.zig");

const testing = std.testing;
const endpoint = &support.endpoint;

const ok: u16 = 200;
const word: usize = 0x3a7e;
/// More content than a connection's output holds.
const long_content: [server_constants.output_len + 1]u8 = @splat('c');

test "decision 119: h11 content past the output is writable once send_stream empties it" {
    try support.start(null, .{});
    support.flushing = false;
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const id = support.id_of(handle, support.nth(.request, 0).?.number);
    try endpoint.set_user_data(id, word);
    try endpoint.respond(id, .{ .status = ok, .end = false });
    const taken = try endpoint.write_body(id, .{ .octets = &long_content, .end = true });
    try testing.expect(taken < long_content.len);
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
    support.flush(handle);
    support.collect();
    const writable = support.nth(.writable, 0).?;
    try testing.expectEqual(word, writable.user_data);
    try testing.expect(try endpoint.write_body(id, .{ .octets = long_content[taken..], .end = true }) > 0);
}

/// The client preface with a SETTINGS frame whose SETTINGS_INITIAL_WINDOW_SIZE (0x4) is
/// `small_window` (RFC 9113 §6.5.2), then the acknowledgment of the server's SETTINGS.
const small_window: u32 = 100;
const preface_small_window = h2.constants.client_preface ++ "\x00\x00\x06\x04\x00\x00\x00\x00\x00" ++
    "\x00\x04\x00\x00\x00\x64" ++ h2_support.settings_ack;

test "RFC 9113 §6.9.1: h2 content a stream's window holds is writable once a WINDOW_UPDATE opens it" {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, preface_small_window);
    _ = support.give(handle, try h2_support.request_frame(1, "/", true));
    const id = support.id_of(handle, 1);
    try endpoint.set_user_data(id, word);
    try endpoint.respond(id, .{ .status = ok, .end = false });
    const content = long_content[0 .. small_window * 4];
    const taken = try endpoint.write_body(id, .{ .octets = content, .end = true });
    try testing.expectEqual(small_window, taken);
    support.collect();
    try testing.expectEqual(null, support.nth(.writable, 0));
    // A PING is a read that opens no window: the stream still takes nothing (RFC 9113 §6.7).
    _ = support.give(handle, "\x00\x00\x08\x06\x00\x00\x00\x00\x00" ++ "\x00" ** h2.constants.ping_len);
    try testing.expectEqual(null, support.nth(.writable, 0));
    var update: [h2.constants.frame_header_len + h2.constants.window_update_len]u8 = undefined;
    var writer = h2.core.Writer.init(&update);
    try h2.frame.write_window_update(&writer, 1, small_window * 4);
    _ = support.give(handle, &update);
    support.collect();
    try testing.expectEqual(word, support.nth(.writable, 0).?.user_data);
    try testing.expectEqual(content.len - taken, try endpoint.write_body(id, .{ .octets = content[taken..], .end = true }));
}

/// The client preface with a SETTINGS_INITIAL_WINDOW_SIZE of 0, so a stream's window opens only by
/// WINDOW_UPDATE (RFC 9113 §6.9.2), then the acknowledgment of the server's SETTINGS.
const preface_no_window = h2.constants.client_preface ++ "\x00\x00\x06\x04\x00\x00\x00\x00\x00" ++
    "\x00\x04\x00\x00\x00\x00" ++ h2_support.settings_ack;

/// The seconds the peer below opens its window for at most: past decision 110's default grace
/// period and window, 10 s each.
const seconds_max: u64 = 40;

/// A program writes each octet a peer's window opens, an octet a second, and the stream is cut at
/// the send rate (decision 110 as amended). The endpoint asks for each octet's `send` before it
/// reads the connection again, so the stream's send meter never waits on the output: whether the
/// program writes before it passes the peer's WINDOW_UPDATE, or after.
fn expect_cut_at_send_rate(writes_first: bool) !void {
    try support.start(null, .{});
    const handle = endpoint.accept(.cleartext, support.now_ns).?;
    _ = support.give(handle, preface_no_window);
    _ = support.give(handle, try h2_support.request_frame(1, "/", true));
    const id = support.id_of(handle, 1);
    try endpoint.respond(id, .{ .status = ok, .end = false });
    var update: [h2.constants.frame_header_len + h2.constants.window_update_len]u8 = undefined;
    var writer = h2.core.Writer.init(&update);
    try h2.frame.write_window_update(&writer, 1, 1);
    var taken: usize = 0;
    for (1..seconds_max) |second| {
        support.instant_ns = support.now_ns + second * server_constants.nanoseconds_per_second;
        endpoint.on_instant(support.instant_ns);
        support.collect();
        if (support.nth(.cancelled, 0) != null) break;
        if (writes_first) taken += endpoint.write_body(id, .{ .octets = long_content[taken..], .end = true }) catch 0;
        _ = support.give(handle, &update);
        if (!writes_first) taken += endpoint.write_body(id, .{ .octets = long_content[taken..], .end = true }) catch 0;
        support.collect();
    }
    const cancelled = support.nth(.cancelled, 0).?;
    try testing.expectEqual(event.CancelReason{ .deadline = .send_rate }, cancelled.reason.?);
    try testing.expect(taken > 0);
}

test "decision 110 as amended: a stream whose window opens an octet a second is cut at the send rate" {
    try expect_cut_at_send_rate(false);
    try expect_cut_at_send_rate(true);
}
