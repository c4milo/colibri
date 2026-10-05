//! The tests of the server's send deadlines over QUIC (`quic_sends.zig`, decision 110 as amended):
//! a response its stream's credit holds, a peer that acknowledges too little, and a connection
//! whose own credit holds its responses.
const std = @import("std");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
const constants = @import("../constants.zig");
const quic_deadline = @import("quic_deadline.zig");
const internal = @import("quic_connection_internal.zig");
const Deadline = @import("../deadline.zig").Deadline;

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
/// Rounds that carry a request to the server, and its answer back.
const rounds_few: usize = 2;
/// What a window owes at the default rate, and a response's content for four windows.
const quota: usize = 10_240;
const windows: usize = 4;
const content: [windows * quota]u8 = @splat('r');
/// A client window of one quota, and one of a tenth of it.
const window_quota: u64 = quota;
const window_small: u64 = 1_024;

/// A server and a client connected, the client's streams starting with `stream_window` octets of
/// credit and its connection with `connection_window`.
fn connected(stream_window: u64, connection_window: u64) !void {
    support.client_stream_window = stream_window;
    support.client_connection_window = connection_window;
    defer support.client_stream_window = support.window_default;
    defer support.client_connection_window = support.window_default;
    try support.start();
    try support.connect();
}

/// A GET the server answers with all of `content`, of which nothing has left yet.
fn answered_get() !*support.Fetch {
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try testing.expectEqual(content.len, try connection.write_body(fetch.id, .{ .octets = &content, .end = true }));
    return fetch;
}

/// Where the response to `fetch` stood when the server last looked.
fn entry_of(fetch: *const support.Fetch) @TypeOf(&connection.sends.entries[0]) {
    return &connection.sends.entries[connection.requests.index_of(connection.requests.of(fetch.id).?)];
}

/// Has the server see `now_ns`, and the test's clock with it, and keeps what it reports.
fn server_at(now_ns: u64) void {
    internal.on_instant(connection, now_ns);
    support.now_ns = now_ns;
    support.collect();
}

/// The deadline the `n`th `cancelled` event names, or null when there is no such event.
fn cancelled_for(n: usize) ?Deadline {
    const entry = support.nth(.cancelled, n) orelse return null;
    return entry.reason.?.deadline;
}

fn closing_for_load() bool {
    const close = connection.transport.pending_close orelse return false;
    return close.layer == .application and close.error_code == h3.constants.error_excessive_load;
}

test "RFC 9114 §4.1.1: a response its stream's credit holds under the rate is reset, and the connection goes on" {
    try connected(window_small, support.window_default);
    support.client_reads = false;
    const fetch = try answered_get();
    try support.pump(support.rounds_default);
    // The client acknowledged what its credit covered, and gives no more.
    const entry = entry_of(fetch);
    try testing.expect(entry.bound and !entry.busy);
    try testing.expect(!connection.sends.meter.running());
    const end_ns = entry.meter.window_end_ns.?;
    try testing.expectEqual(end_ns, quic_deadline.soonest(connection).?);
    server_at(end_ns - 1);
    try testing.expectEqual(null, cancelled_for(0));
    server_at(end_ns);
    try testing.expectEqual(Deadline.send_rate, cancelled_for(0).?);
    try testing.expectEqual(fetch.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(connection.clock.timed_out == null and !support.server_failed);
    support.client_reads = true;
    try support.pump(support.rounds_default);
    try testing.expectEqual(h3.constants.error_request_cancelled, fetch.reset.?);
    try testing.expect(!connection.sends.metered);
    try testing.expectEqual(null, support.nth(.done, 0));
}

test "decision 110: a stream whose credit grows by the quota each window is not reset, and one that stops growing is" {
    try connected(window_quota, support.window_default);
    support.client_reads = false;
    const fetch = try answered_get();
    try support.pump(support.rounds_default);
    const first_end_ns = entry_of(fetch).meter.window_end_ns.?;
    // The first window counted the octets the first credit covered.
    server_at(first_end_ns);
    try testing.expectEqual(null, cancelled_for(0));
    // The client reads once, so its credit grows by one window's octets.
    try support.client_read();
    try support.pump(support.rounds_default);
    const second_end_ns = first_end_ns + constants.rate_window_ns;
    server_at(second_end_ns);
    try testing.expectEqual(null, cancelled_for(0));
    server_at(second_end_ns + constants.rate_window_ns - 1);
    try testing.expectEqual(null, cancelled_for(0));
    server_at(second_end_ns + constants.rate_window_ns);
    try testing.expectEqual(Deadline.send_rate, cancelled_for(0).?);
}

test "decision 110: credit that grows under the rate does not start a stream's window again" {
    try connected(window_small, support.window_default);
    support.client_reads = false;
    const fetch = try answered_get();
    try support.pump(support.rounds_default);
    const end_ns = entry_of(fetch).meter.window_end_ns.?;
    // Part of the way, the client reads once: its credit grows by a tenth of the quota.
    server_at(end_ns - constants.rate_window_ns);
    try support.client_read();
    try support.pump(support.rounds_default);
    try testing.expect(entry_of(fetch).acknowledged_len > window_small);
    try testing.expectEqual(end_ns, entry_of(fetch).meter.window_end_ns.?);
    server_at(end_ns);
    try testing.expectEqual(Deadline.send_rate, cancelled_for(0).?);
}

test "RFC 9114 §10.5: a peer that acknowledges nothing of a response closes the connection with H3_EXCESSIVE_LOAD" {
    try connected(support.window_default, support.window_default);
    _ = try answered_get();
    support.client_mute = true;
    try support.pump(rounds_few);
    try testing.expectEqual(1, connection.sends.busy);
    const end_ns = connection.sends.meter.window_end_ns.?;
    try testing.expectEqual(end_ns, quic_deadline.soonest(connection).?);
    server_at(end_ns - 1);
    try testing.expect(connection.clock.timed_out == null and !support.server_failed);
    server_at(end_ns);
    try testing.expectEqual(Deadline.send_rate, connection.clock.timed_out.?);
    try testing.expect(closing_for_load() and support.server_failed);
}

test "decision 110: a peer that acknowledges the quota each window is not closed, and one that stops is" {
    try connected(support.window_default, 2 * window_quota);
    support.client_reads = false;
    _ = try answered_get();
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, connection.sends.busy);
    const first_end_ns = connection.sends.meter.window_end_ns.?;
    server_at(first_end_ns);
    // The client reads once, so its connection's credit grows by two quotas.
    try support.client_read();
    try support.pump(support.rounds_default);
    const third_end_ns = first_end_ns + 2 * constants.rate_window_ns;
    server_at(first_end_ns + constants.rate_window_ns);
    try testing.expectEqual(1, connection.sends.busy);
    server_at(third_end_ns - 1);
    try testing.expect(connection.clock.timed_out == null and !support.server_failed);
    server_at(third_end_ns);
    try testing.expectEqual(Deadline.send_rate, connection.clock.timed_out.?);
}

test "decision 110: a response its connection's credit holds waits on its peer before its end is written" {
    try connected(support.window_default, window_small);
    support.client_reads = false;
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try testing.expectEqual(content.len, try connection.write_body(fetch.id, .{ .octets = &content, .end = false }));
    try support.pump(support.rounds_default);
    // The client acknowledged every octet its connection's credit let through. The rest is
    // within the stream's credit and waits on the connection's, which is the peer's to give.
    const outgoing = &connection.transport.streams.lookup(.{ .value = fetch.id }).live.outgoing;
    try testing.expectEqual(outgoing.framed_end, outgoing.acknowledged_len);
    try testing.expect(outgoing.framed_end < content.len and !outgoing.finished);
    try testing.expect(entry_of(fetch).busy and !entry_of(fetch).bound);
    server_at(connection.sends.meter.window_end_ns.?);
    try testing.expectEqual(Deadline.send_rate, connection.clock.timed_out.?);
    try testing.expect(closing_for_load());
}

test "RFC 9000 §3.1: a response whose end alone is not acknowledged still waits on its peer" {
    try connected(support.window_default, support.window_default);
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    _ = try connection.write_body(fetch.id, .{ .octets = content[0..quota], .end = false });
    try support.pump(support.rounds_default);
    try testing.expectEqual(0, connection.sends.busy);
    support.client_mute = true;
    try testing.expectEqual(0, try connection.write_body(fetch.id, .{ .octets = "", .end = true }));
    try support.pump(rounds_few);
    try testing.expect(entry_of(fetch).busy);
    server_at(connection.sends.meter.window_end_ns.?);
    try testing.expectEqual(Deadline.send_rate, connection.clock.timed_out.?);
}

test "decision 110: a stream a send deadline ends waits for its request's body no more" {
    support.client_stream_window = window_small;
    defer support.client_stream_window = support.window_default;
    try support.start();
    support.config.deadlines.body_rate_min = null;
    support.config.deadlines.body_ns = null;
    try support.connect();
    support.client_reads = false;
    const fetch = try support.request_open("POST", "/", "x");
    try support.pump(rounds_few);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    _ = try connection.write_body(fetch.id, .{ .octets = &content, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, connection.bodies.waiting);
    server_at(entry_of(fetch).meter.window_end_ns.?);
    try testing.expectEqual(Deadline.send_rate, cancelled_for(0).?);
    try testing.expectEqual(0, connection.bodies.waiting);
    support.client_reads = true;
    try support.pump(support.rounds_default);
    try testing.expect(connection.requests.idle());
}

test "RFC 9114 §10.5: a connection whose own credit holds its responses closes with H3_EXCESSIVE_LOAD" {
    try connected(support.window_default, window_small);
    support.client_reads = false;
    const fetch = try answered_get();
    try support.pump(support.rounds_default);
    // The stream's credit covers the response, and the connection's does not.
    const entry = entry_of(fetch);
    try testing.expect(entry.busy and !entry.bound);
    const end_ns = connection.sends.meter.window_end_ns.?;
    server_at(end_ns - 1);
    try testing.expect(connection.clock.timed_out == null);
    server_at(end_ns);
    try testing.expectEqual(Deadline.send_rate, connection.clock.timed_out.?);
    try testing.expect(closing_for_load());
}

test "decision 110: a peer that keeps up runs no send deadline, and a record starts each response from nothing" {
    try connected(support.window_default, support.window_default);
    for (0..2) |_| {
        const fetch = try answered_get();
        try support.pump(support.rounds_default);
        try testing.expect(fetch.ended);
        try testing.expectEqual(content.len, fetch.received_len);
        try testing.expect(!connection.sends.metered and connection.sends.busy == 0);
        try testing.expect(connection.requests.idle());
    }
}

test "decision 110: a stream's own meter waits while another response holds octets the peer may take" {
    try connected(window_small, support.window_default);
    support.client_reads = false;
    const held = try answered_get();
    try support.pump(support.rounds_default);
    const end_ns = entry_of(held).meter.window_end_ns.?;
    // A second response, which the peer may take and does not acknowledge.
    const second = try support.request("GET", "/second", "");
    try support.pump(rounds_few);
    support.client_mute = true;
    try connection.respond(second.id, .{ .status = ok, .end = true });
    try support.pump(rounds_few);
    try testing.expect(entry_of(second).busy);
    try testing.expect(!entry_of(held).meter.running());
    const closes_ns = connection.sends.meter.window_end_ns.?;
    try testing.expect(closes_ns > end_ns);
    server_at(end_ns);
    try testing.expectEqual(null, cancelled_for(0));
    server_at(closes_ns);
    try testing.expectEqual(Deadline.send_rate, connection.clock.timed_out.?);
}

test "decision 110: a response the caller cancels runs no send deadline, before its stream closes" {
    try connected(window_small, support.window_default);
    support.client_reads = false;
    const fetch = try answered_get();
    try support.pump(support.rounds_default);
    try testing.expect(connection.sends.metered);
    // The client's acknowledgment of the reset never arrives, so the stream stays open.
    support.client_mute = true;
    connection.cancel(fetch.id);
    try support.pump(rounds_few);
    try testing.expect(connection.requests.of(fetch.id) != null);
    try testing.expect(!connection.sends.metered);
    try testing.expectEqual(0, connection.sends.bound);
}

test "decision 110: octets acknowledged after a window's end do not count in it" {
    try connected(support.window_default, support.window_default);
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    _ = try connection.write_body(fetch.id, .{ .octets = content[0..quota], .end = true });
    support.client_mute = true;
    try support.pump(rounds_few);
    const end_ns = connection.sends.meter.window_end_ns.?;
    // The client's acknowledgment of the whole response arrives one round after the window ended,
    // in the first datagram the server takes after it.
    support.now_ns = end_ns;
    support.client_mute = false;
    try support.pump(1);
    try testing.expectEqual(Deadline.send_rate, connection.clock.timed_out.?);
}
