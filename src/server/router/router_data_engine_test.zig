//! The tests of a stream route's `on_data` over h11, h2 and h3 (decision 163 ruling 6, design §8
//! step 50f): the router runs on the engines of the TCP and QUIC tests, which report each event
//! to it. `on_data` reads each piece of a body of two events, and a message that the two cut.
//! Over h2 the end of the body comes with the last DATA frame, so `ended` is true at the last
//! piece. Over h11 and h3 the end comes in a later event with no octets.
const std = @import("std");
const h2 = @import("h2");
const quic = @import("quic");
const event = @import("../event.zig");
const tcp_support = @import("../engine/engine_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");
const data = @import("router_data_test_support.zig");

const testing = std.testing;

/// The router and the program's context, which the program hooks reach. Test-only.
var engine_router: data.Pool align(@alignOf(data.Pool)) = .{};
var engine_app: data.App align(@alignOf(data.App)) = .{};

const tcp_engine = &tcp_support.engine;
const quic_engine = &quic_support.engine_support.engine;

/// The body of each test, in two pieces, and a message of three octets that the two pieces cut.
const first_piece = "ab";
const second_piece = "cd";
const first_part = "\x03ab";
const second_part = "c";
/// The h2 stream of each test's request (RFC 9113 §5.1.1), the rounds an h3 test pumps for a
/// piece, and the rounds it pumps at most for the whole response.
const stream_id: u32 = 1;
const rounds_piece = 4;
const rounds_max = 64;
const ok_code: u16 = 200;

/// Passes each event the TCP engine reports to the router, as a program's loop does.
fn take_tcp(reported: event.Event) void {
    _ = engine_router.handle(&engine_app, tcp_engine, reported);
}

/// Passes each event the QUIC engine reports to the router.
fn take_quic(reported: event.Event) void {
    _ = engine_router.handle(&engine_app, quic_engine, reported);
}

/// Starts the TCP engine with the router as its program, and accepts one cleartext connection.
fn start_tcp() !event.ConnectionHandle {
    try tcp_support.start(null, .{});
    tcp_support.program = take_tcp;
    engine_router = .{};
    engine_app = .{};
    return tcp_engine.accept(.{ .tls = false }, tcp_support.now_ns).?;
}

/// Requires the route to have read the two pieces, with `ended` false after the first.
fn expect_collected() !void {
    try testing.expectEqualStrings(first_piece ++ second_piece, engine_app.collected.get());
    try testing.expect(!engine_app.ended_at[0]);
    try testing.expect(engine_app.ended_at[engine_app.last_call()]);
}

/// The calls of `on_data` that the two pieces of a body of two events make.
const piece_calls = 2;

/// Requires the end of the body to have come in a call of `on_data` after the one that got the
/// last piece, with no piece of its own.
fn expect_end_later() !void {
    const last = engine_app.last_call();
    try testing.expect(last >= piece_calls);
    try testing.expectEqual(0, engine_app.pieces[last]);
    try testing.expectEqualStrings(second_piece, engine_app.firsts[last - 1].get());
    try testing.expect(!engine_app.ended_at[last - 1]);
}

const h11_head = "POST /collect HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n";
const h11_framed_head = "POST /framed HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n";

test "decision 163 ruling 6: on_data reads a body of two events, and ended comes in a later event, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_head);
    _ = tcp_support.give(handle, first_piece);
    _ = tcp_support.give(handle, second_piece);
    try expect_collected();
    try expect_end_later();
    try testing.expect(std.mem.indexOf(u8, tcp_support.sent_of(handle.slot), "HTTP/1.1 200") != null);
}

test "decision 163 ruling 6: a message that two events cut is read whole, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_framed_head);
    _ = tcp_support.give(handle, first_part);
    try testing.expectEqual(0, engine_app.message_count);
    _ = tcp_support.give(handle, second_part);
    try testing.expectEqualStrings("abc", engine_app.messages.get());
    try testing.expectEqual(1, engine_app.message_calls[0]);
}

/// Passes one DATA frame of `bytes`, which ends the stream when `end` is set (RFC 9113 §6.1).
fn give_data(handle: event.ConnectionHandle, bytes: []const u8, end: bool) !void {
    var frame: [h2.constants.protocol.frame_header_len + data.body_bytes]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_data(&writer, stream_id, bytes, end, 0);
    _ = tcp_support.give(handle, writer.written());
}

/// Starts an h2 connection on the TCP engine, with a POST of `path` whose body stays open.
fn start_h2(path: []const u8) !event.ConnectionHandle {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h2_support.client_preface);
    _ = tcp_support.give(handle, try h2_support.request_frame_with(stream_id, "POST", path, &.{}, false));
    return handle;
}

test "decision 163 ruling 6: ended is true at the last piece, on a DATA frame with END_STREAM, over h2" {
    const handle = try start_h2("/collect");
    try give_data(handle, first_piece, false);
    try give_data(handle, second_piece, true);
    try expect_collected();
    // RFC 9113 §6.1: END_STREAM on the last DATA frame ends the body with its last piece.
    try testing.expectEqual(1, engine_app.last_call());
    try testing.expectEqualStrings(second_piece, engine_app.firsts[1].get());
    try testing.expect(engine_app.ended_at[1]);
}

test "decision 163 ruling 6: a message that two events cut is read whole, over h2" {
    const handle = try start_h2("/framed");
    try give_data(handle, first_part, false);
    try testing.expectEqual(0, engine_app.message_count);
    try give_data(handle, second_part, true);
    try testing.expectEqualStrings("abc", engine_app.messages.get());
    try testing.expectEqual(1, engine_app.message_calls[0]);
}

/// Starts the QUIC engine with the router as its program, connects its client, and stages a POST
/// of `path` with `content`, which the client supplies in parts.
fn start_quic(path: []const u8, content: []const u8) !*quic_support.Fetch {
    try quic_support.start_engine(null);
    try quic_support.connect();
    engine_router = .{};
    engine_app = .{};
    quic_support.seen_support.program = take_quic;
    return quic_support.stage_request("POST", path, &.{}, content, &.{});
}

/// Supplies the content of `fetch` up to `len` octets, with a FIN when `fin` is set, and moves
/// datagrams both ways.
fn supply(fetch: *const quic_support.Fetch, len: usize, fin: bool) !void {
    try quic.Connection.supply(&quic_support.client, .{ .value = fetch.id }, fetch.prefix_len + len, fin);
    try quic_support.pump(rounds_piece);
}

/// Moves datagrams both ways until the client has the whole response of `fetch`.
fn pump_until_ended(fetch: *const quic_support.Fetch) !void {
    // Bounded: each round moves time on and moves datagrams both ways.
    for (0..rounds_max) |_| {
        if (fetch.ended) return;
        try quic_support.pump(1);
    }
    return error.TestExpectedEnded;
}

test "decision 163 ruling 6: on_data reads a body of two pieces, and ended comes in a later event, over h3" {
    const fetch = try start_quic("/collect", first_piece ++ second_piece);
    defer quic_support.seen_support.program = null;
    try supply(fetch, first_piece.len, false);
    try testing.expectEqual(1, engine_app.calls);
    try supply(fetch, first_piece.len + second_piece.len, true);
    try pump_until_ended(fetch);
    try testing.expectEqual(ok_code, fetch.status);
    try expect_collected();
    try expect_end_later();
}

test "decision 163 ruling 6: a message that two pieces cut is read whole, over h3" {
    const fetch = try start_quic("/framed", first_part ++ second_part);
    defer quic_support.seen_support.program = null;
    try supply(fetch, first_part.len, false);
    try testing.expectEqual(0, engine_app.message_count);
    try supply(fetch, first_part.len + second_part.len, true);
    try pump_until_ended(fetch);
    try testing.expectEqualStrings("abc", engine_app.messages.get());
    try testing.expectEqual(1, engine_app.message_calls[0]);
}
