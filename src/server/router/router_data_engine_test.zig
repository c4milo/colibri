//! The tests of a stream route's `on_data` over h11, h2 and h3 (decision 163 ruling 6, design §8
//! step 50f): the router runs on the engines of the TCP and QUIC tests, which report each event
//! to it. `on_data` reads each piece of a body of two events, and a message that the two cut.
//! Over h2 the end of the body comes with the last DATA frame, so `ended` is true at the last
//! piece. Over h11 and h3 the end comes in a later event with no octets. At the end, a route that
//! kept the whole body reads it as the last piece (decision 163 ruling 6 as amended). Through a
//! wrapper, the router copies kept octets into the entry's `body_bytes`, and no other piece.
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
/// A body with no length that the route keeps whole, and one octet past `body_bytes` in two parts.
const whole_body = first_piece ++ second_piece;
const long_first = "01234567";
const long_second = "89abcdef!";
/// Messages through a wrapper: one whose window leaves less room than a long message takes, and
/// one that copies the kept octets alone.
const windowed_first = "\x01a\x07bcd";
const windowed_second = "efgh";
const windowed_messages = "abcdefgh";
const wrapped_first = "\x03a";
const wrapped_second = "bc\x01z";
/// The h2 stream of each test's request (RFC 9113 §5.1.1), the rounds an h3 test pumps for a
/// piece, and the rounds it pumps at most for the whole response.
const stream_id: u32 = 1;
const rounds_piece = 4;
const rounds_max = 64;
const ok_code: u16 = 200;
const too_large_code: u16 = 413;
/// Octets of the payload of a DATA frame a test sends at most, and of a trailer section's block.
const data_len_max = (long_first ++ long_second).len;
const trailer_block_len = 16;
/// The pieces and the copies of the two calls of `on_data` over the wrapped messages. The first
/// call gets "\x03", then "\x03a" joined after a keep. The second gets "\x03ab" and "\x03abc"
/// joined, "\x01" after a keep(0) with no copy, and "\x01z" joined.
const wrapped_pieces_first = 2;
const wrapped_copies_first = 1;
const wrapped_pieces_second = 4;
const wrapped_copies_second = 3;

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

/// The status of the response that the router wrote for the test's request. A check reads the
/// entry's field, which a program does not.
fn written_status() u16 {
    return @intFromEnum(engine_router.entries[0].response.status);
}

/// Lets the app count the pieces that lie in the entry's body memory.
fn watch_storage() void {
    engine_app.storage = &engine_router.entries[0].body.held;
}

/// Requires `Whole` to have read the body whole as its last piece: the last call's pieces were
/// `pieces`, the last of them the whole body, and its `keep` kept nothing, so `ended` turned true.
fn expect_whole(pieces: usize) !void {
    try testing.expectEqualStrings(whole_body, engine_app.whole.get());
    const last = engine_app.last_call();
    try testing.expectEqual(pieces, engine_app.pieces[last]);
    try testing.expect(engine_app.ended_at[last]);
}

/// Requires the route to have read the two messages through a wrapper, the second one cut. Each
/// piece that follows a `keep` lies in the entry's body memory, and no other piece does.
fn expect_copied_after_keep() !void {
    try testing.expectEqualStrings("abcz", engine_app.messages.get());
    try testing.expectEqual(wrapped_pieces_first, engine_app.pieces[0]);
    try testing.expectEqual(wrapped_copies_first, engine_app.copies[0]);
    try testing.expectEqual(wrapped_pieces_second, engine_app.pieces[1]);
    try testing.expectEqual(wrapped_copies_second, engine_app.copies[1]);
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

/// The head of an h11 POST of `path` with a body of `length` octets.
fn h11_post(comptime path: []const u8, comptime length: []const u8) []const u8 {
    return "POST " ++ path ++ " HTTP/1.1\r\nHost: example.com\r\nContent-Length: " ++ length ++ "\r\n\r\n";
}

/// Whether the TCP engine sent a response head of `status` on `handle`'s connection.
fn h11_sent(handle: event.ConnectionHandle, comptime status: []const u8) bool {
    return std.mem.indexOf(u8, tcp_support.sent_of(handle.slot), "HTTP/1.1 " ++ status) != null;
}

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

test "decision 163 ruling 6 as amended: a body kept whole is read as the last piece, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_post("/whole", "4"));
    _ = tcp_support.give(handle, first_piece);
    _ = tcp_support.give(handle, second_piece);
    try expect_whole(1);
    try testing.expect(h11_sent(handle, "200"));
}

test "decision 163 ruling 6 as amended: a body kept whole is read as the last piece after trailers, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, "POST /whole HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n");
    _ = tcp_support.give(handle, "2\r\nab\r\n");
    _ = tcp_support.give(handle, "2\r\ncd\r\n");
    // RFC 9112 §7.1.2: the last chunk, then a trailer section.
    _ = tcp_support.give(handle, "0\r\nx-sum: 1\r\n\r\n");
    try expect_whole(1);
    try testing.expect(h11_sent(handle, "200"));
}

test "RFC 9110 §15.5.14: a body kept past body_bytes gets 413, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_post("/whole", "17"));
    _ = tcp_support.give(handle, long_first);
    try testing.expect(!h11_sent(handle, "413"));
    _ = tcp_support.give(handle, long_second);
    try testing.expect(h11_sent(handle, "413"));
}

test "decision 163 ruling 6 as amended: a long keep through a wrapper that keeps a window is read whole, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_post("/framed-windowed", "10"));
    _ = tcp_support.give(handle, windowed_first);
    _ = tcp_support.give(handle, windowed_second);
    try testing.expectEqualStrings(windowed_messages, engine_app.messages.get());
    try testing.expect(h11_sent(handle, "200"));
}

test "decision 163 ruling 6 as amended: through a wrapper, a piece is copied only after a keep, over h11" {
    const handle = try start_tcp();
    watch_storage();
    _ = tcp_support.give(handle, h11_post("/framed-wrapped", "6"));
    _ = tcp_support.give(handle, wrapped_first);
    _ = tcp_support.give(handle, wrapped_second);
    try expect_copied_after_keep();
}

/// Passes one DATA frame of `bytes`, which ends the stream when `end` is set (RFC 9113 §6.1).
fn give_data(handle: event.ConnectionHandle, bytes: []const u8, end: bool) !void {
    var frame: [h2.constants.protocol.frame_header_len + data_len_max]u8 = undefined;
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

/// Passes a HEADERS frame that carries a trailer section and ends the stream (RFC 9113 §8.1).
fn give_trailers(handle: event.ConnectionHandle) !void {
    var block: [trailer_block_len]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2.constants.protocol.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    try encoder.write_field(&block_writer, "x-sum", "1", .without_indexing);
    encoder.commit_block();
    var frame: [h2.constants.protocol.frame_header_len + trailer_block_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    const flags = h2.constants.protocol.flag_end_headers | h2.constants.protocol.flag_end_stream;
    try h2.frame.write_header(&writer, .{ .length = @intCast(block_writer.written().len), .type = .headers, .flags = flags, .stream_id = stream_id });
    try writer.write_bytes(block_writer.written());
    _ = tcp_support.give(handle, writer.written());
}

test "decision 163 ruling 6 as amended: a body kept whole is read as the last piece, over h2" {
    const handle = try start_h2("/whole");
    try give_data(handle, first_piece, false);
    try give_data(handle, second_piece, true);
    // RFC 9113 §6.1: END_STREAM comes with the last octets, so the last call joins them, and then
    // gives them again as the last piece.
    try expect_whole(2);
    try testing.expectEqual(ok_code, written_status());
}

test "decision 163 ruling 6 as amended: a body kept whole is read as the last piece after trailers, over h2" {
    const handle = try start_h2("/whole");
    try give_data(handle, first_piece, false);
    try give_data(handle, second_piece, false);
    try give_trailers(handle);
    try expect_whole(1);
    try testing.expectEqual(ok_code, written_status());
}

test "RFC 9110 §15.5.14: a last piece kept past body_bytes gets 413, over h2" {
    const handle = try start_h2("/whole");
    // The end comes with the octets, so the router holds none of them.
    try give_data(handle, long_first ++ long_second, true);
    try testing.expectEqual(1, engine_app.pieces[0]);
    try testing.expectEqual(too_large_code, written_status());
}

test "decision 163 ruling 6 as amended: a long keep through a wrapper that keeps a window is read whole, over h2" {
    const handle = try start_h2("/framed-windowed");
    try give_data(handle, windowed_first, false);
    try give_data(handle, windowed_second, true);
    try testing.expectEqualStrings(windowed_messages, engine_app.messages.get());
    try testing.expectEqual(ok_code, written_status());
}

test "decision 163 ruling 6 as amended: through a wrapper, a piece is copied only after a keep, over h2" {
    const handle = try start_h2("/framed-wrapped");
    watch_storage();
    try give_data(handle, wrapped_first, false);
    try give_data(handle, wrapped_second, true);
    try expect_copied_after_keep();
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

test "decision 163 ruling 6 as amended: a body kept whole is read as the last piece, over h3" {
    const fetch = try start_quic("/whole", whole_body);
    defer quic_support.seen_support.program = null;
    try supply(fetch, first_piece.len, false);
    try supply(fetch, whole_body.len, true);
    try pump_until_ended(fetch);
    try testing.expectEqual(ok_code, fetch.status);
    try expect_whole(1);
}

test "RFC 9110 §15.5.14: a body kept past body_bytes gets 413, over h3" {
    const fetch = try start_quic("/whole", long_first ++ long_second);
    defer quic_support.seen_support.program = null;
    try supply(fetch, long_first.len, false);
    try supply(fetch, long_first.len + long_second.len, true);
    try pump_until_ended(fetch);
    try testing.expectEqual(too_large_code, fetch.status);
}

test "decision 163 ruling 6 as amended: a long keep through a wrapper that keeps a window is read whole, over h3" {
    const fetch = try start_quic("/framed-windowed", windowed_first ++ windowed_second);
    defer quic_support.seen_support.program = null;
    try supply(fetch, windowed_first.len, false);
    try supply(fetch, windowed_first.len + windowed_second.len, true);
    try pump_until_ended(fetch);
    try testing.expectEqualStrings(windowed_messages, engine_app.messages.get());
    try testing.expectEqual(ok_code, fetch.status);
}

test "decision 163 ruling 6 as amended: through a wrapper, a piece is copied only after a keep, over h3" {
    const fetch = try start_quic("/framed-wrapped", wrapped_first ++ wrapped_second);
    defer quic_support.seen_support.program = null;
    watch_storage();
    try supply(fetch, wrapped_first.len, false);
    try supply(fetch, wrapped_first.len + wrapped_second.len, true);
    try pump_until_ended(fetch);
    try expect_copied_after_keep();
}
