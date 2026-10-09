//! The tests of the 100 (Continue) a server connection over QUIC owes (`quic_continue.zig`, RFC
//! 9110 §10.1.1). The connection writes the 100 at the caller's first call after the `receive`
//! that reports a request, so each test reads the server's events itself, one `receive` at a time.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
const internal = @import("quic_connection_internal.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const connection = &support.connection;
const Field = support.Field;

const hundred: u16 = 100;
const early_hints: u16 = 103;
const ok: u16 = 200;
const content_too_large: u16 = 413;
const expect_continue = [_]Field{.{ .name = "expect", .value = "100-continue" }};

/// Moves datagrams both ways while the server reports nothing. `pump` reads every event the
/// server has, and a stopped connection takes its datagrams and reads no request, so the test
/// makes each `receive` after this itself. Test-only.
fn deliver() !void {
    connection.stopped = true;
    defer connection.stopped = false;
    try support.pump(support.rounds_default);
}

/// A connected pair, and a PUT with `fields` whose head the server reported, and nothing after
/// it. With `open` the client leaves its stream open, as one that waits for the 100 (Continue)
/// does; without, the stream ended with the head. Test-only.
fn put(fields: []const Field, open: bool) !*support.Fetch {
    try support.start();
    try support.connect();
    const fetch = if (open)
        try support.request_open_with_fields("PUT", "/f", fields)
    else
        try support.request_with_fields("PUT", "/f", fields);
    try deliver();
    const head = (try connection.receive(support.now_ns)).event.?.request;
    try testing.expectEqual(fetch.id, head.id.number);
    // RFC 9114 §4.1: h3 reports the request's end apart from its head.
    try testing.expect(!head.end);
    return fetch;
}

/// The status of the last response head the client read. Test-only.
fn last_status() []const u8 {
    return support.client_h3.field_section().get(0).value;
}

/// The client sends `content` on the stream `fetch` left open, and ends the stream, as it does
/// once the 100 (Continue) arrived. Test-only.
fn send_content(fetch: *support.Fetch, content: []const u8) !void {
    var writer = quic.core.Writer.init(fetch.prefix[fetch.prefix_len..]);
    try support.client_h3.write_data_header(fetch.id, content.len, &writer, support.now_ns);
    fetch.prefix_len += writer.written().len;
    fetch.content = content;
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, fetch.prefix_len + content.len, true);
}

test "RFC 9110 §10.1.1: an h3 request expecting 100-continue gets the 100 at the next receive, once" {
    const fetch = try put(&expect_continue, true);
    const record = connection.requests.of(fetch.id).?;
    try testing.expect(record.continue_owed and connection.continue_owed);
    // The caller reads on, so the 100 goes out.
    try testing.expectEqual(null, (try connection.receive(support.now_ns)).event);
    try testing.expect(!record.continue_owed and !connection.continue_owed);
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, fetch.interims);
    try testing.expectEqualStrings("100", last_status());
    try testing.expectEqual(0, fetch.status);
    // The client sends its content, and the final response follows the one 100.
    try send_content(fetch, "hello");
    try support.pump(support.rounds_default);
    try testing.expectEqual(5, support.nth(.body, 0).?.len);
    try testing.expect(support.nth(.body, 1).?.end);
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, fetch.interims);
    try testing.expectEqual(ok, fetch.status);
}

/// Rounds enough for QUIC to send a lost datagram's frames again (RFC 9002 §6.2): it takes 4.
/// Test-only.
const rounds_past_probe: usize = 32;
/// How long after the request's head the test's `send` runs. Test-only.
const send_delay_ns: u64 = 1_000;

test "RFC 9110 §10.1.1: the 100 goes out before the next datagram, with no receive between" {
    const fetch = try put(&expect_continue, true);
    const record = connection.requests.of(fetch.id).?;
    var datagram: [quic.constants.datagram_len_max]u8 = undefined;
    support.now_ns += send_delay_ns;
    try testing.expect(internal.send(connection, &datagram, support.now_ns) != null);
    try testing.expect(!record.continue_owed and !connection.continue_owed);
    try testing.expectEqual(1, record.response.runs_len);
    // Decision 102: the write carries the instant of the call that made it.
    try testing.expectEqual(support.now_ns, connection.last_ns);
    // The test kept the datagram, so the client gets the 100 once QUIC sends it again.
    try support.pump(rounds_past_probe);
    try testing.expectEqual(1, fetch.interims);
    try testing.expectEqualStrings("100", last_status());
}

test "RFC 9110 §10.1.1: a final response before the next call takes the place of the 100 owed" {
    const fetch = try put(&expect_continue, true);
    try connection.respond(fetch.id, .{ .status = content_too_large, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(0, fetch.interims);
    try testing.expectEqual(content_too_large, fetch.status);
    try testing.expect(!connection.requests.of(fetch.id).?.continue_owed and !connection.continue_owed);
}

test "RFC 9110 §10.1.1: the caller's own 100 takes the place of the 100 owed" {
    const fetch = try put(&expect_continue, true);
    try connection.respond(fetch.id, .{ .status = hundred, .end = false });
    try testing.expect(!connection.requests.of(fetch.id).?.continue_owed);
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, fetch.interims);
    try testing.expectEqualStrings("100", last_status());
}

test "RFC 9110 §10.1.1: an interim response other than 100 leaves the 100 owed" {
    const fetch = try put(&expect_continue, true);
    try connection.respond(fetch.id, .{ .status = early_hints, .end = false });
    try testing.expect(connection.requests.of(fetch.id).?.continue_owed);
    try support.pump(support.rounds_default);
    try testing.expectEqual(2, fetch.interims);
    // RFC 9114 §4.1: the stream carries the heads in the order they were written.
    try testing.expectEqualStrings("100", last_status());
}

test "RFC 9110 §10.1.1: an h3 request cancelled before its 100 gets none" {
    const fetch = try put(&expect_continue, true);
    connection.cancel(fetch.id);
    try support.pump(support.rounds_default);
    try testing.expectEqual(0, fetch.interims);
    try testing.expectEqual(h3.constants.error_request_cancelled, fetch.reset.?);
    try testing.expect(!connection.continue_owed);
}

test "RFC 9110 §10.1.1: an h3 request that expects no 100 gets none, and a send settles nothing" {
    const fetch = try put(&.{}, true);
    try testing.expect(!connection.requests.of(fetch.id).?.continue_owed and !connection.continue_owed);
    // With no 100 owed, `send` walks no request, so it leaves the instant of the last call.
    const read_at_ns = connection.last_ns;
    var datagram: [quic.constants.datagram_len_max]u8 = undefined;
    support.now_ns += send_delay_ns;
    _ = internal.send(connection, &datagram, support.now_ns);
    try testing.expectEqual(read_at_ns, connection.last_ns);
    try support.pump(support.rounds_default);
    try testing.expectEqual(0, fetch.interims);
}

test "decision 116: an h3 request whose stream ended with its head gets no 100" {
    const fetch = try put(&expect_continue, false);
    const record = connection.requests.of(fetch.id).?;
    // RFC 9114 §4.1: the head does not say that the request ended, so it owes the 100.
    try testing.expect(record.continue_owed);
    const end = (try connection.receive(support.now_ns)).event.?.body;
    try testing.expect(end.end and end.octets.len == 0);
    // RFC 9000 §4.5: h3 had taken every octet below the stream's final size, so no content
    // follows.
    try testing.expect(!record.continue_owed and !connection.continue_owed);
    try support.pump(support.rounds_default);
    try testing.expectEqual(0, fetch.interims);
}

test "decision 116: an h3 request that ends with no content before its 100 is written gets none" {
    const fetch = try put(&expect_continue, true);
    // The client ends its stream with no content. The FIN arrives before the caller's next call,
    // and h3 has not read it when the 100 is due.
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, fetch.prefix_len, true);
    try deliver();
    const end = (try connection.receive(support.now_ns)).event.?.body;
    try testing.expect(end.end and end.octets.len == 0);
    try testing.expect(!connection.requests.of(fetch.id).?.continue_owed);
    try support.pump(support.rounds_default);
    try testing.expectEqual(0, fetch.interims);
}

test "decision 116: content that arrived whole with the head leaves the 100 owed, as over h2" {
    try support.start();
    try support.connect();
    const fetch = try support.request_open_with_fields("PUT", "/f", &expect_continue);
    try send_content(fetch, "hello");
    try deliver();
    try testing.expectEqual(fetch.id, (try connection.receive(support.now_ns)).event.?.request.id.number);
    // RFC 9000 §4.5: the stream's final size is known, and its content is still to read.
    const content = (try connection.receive(support.now_ns)).event.?.body;
    try testing.expectEqual(5, content.octets.len);
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, fetch.interims);
    try testing.expectEqualStrings("100", last_status());
}

test "RFC 9000 §3.1: the 100 waits for a run of the response, and goes out once the peer acknowledges one" {
    const fetch = try put(&expect_continue, true);
    const record = connection.requests.of(fetch.id).?;
    // RFC 9110 §15.2: interim responses, each a HEADERS frame in a run of its own, fill every
    // run the response holds.
    for (0..constants.quic_response_pieces_max) |_| {
        try connection.respond(fetch.id, .{ .status = early_hints, .end = false });
    }
    try testing.expectEqual(null, (try connection.receive(support.now_ns)).event);
    try testing.expect(record.continue_owed and connection.continue_owed);
    try support.pump(support.rounds_default);
    try testing.expect(!record.continue_owed and !connection.continue_owed);
    try testing.expectEqual(constants.quic_response_pieces_max + 1, fetch.interims);
    try testing.expectEqualStrings("100", last_status());
}

/// The connection ID and the receive pool the test below starts a connection from. Test-only.
const start_id: [constants.quic_id_len]u8 = @splat(start_id_octet);
const start_id_octet: u8 = 0x0d;
const start_pool_len: usize = 32_768;
const StartPool = quic.stream.stream_incoming.Pool(start_pool_len);
threadlocal var start_pool: StartPool align(@alignOf(StartPool)) = undefined;

test "RFC 9110 §10.1.1: a connection starts with no 100 owed" {
    try support.start();
    connection.continue_owed = true;
    try internal.start(connection, &support.config, start_pool.storage(), .{
        .local_id = start_id,
        .original_destination = &start_id,
        .peer_source = &start_id,
        .grease = 0,
        .peer = support.client_address(),
    }, tcp_support.stream.random(), 0, support.now_ns);
    try testing.expect(!connection.continue_owed);
}
