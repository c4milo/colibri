//! The tests of a function route that gets the whole request in one call (decision 163 rulings 4
//! and 5, design §8 step 50e). A request with a body gets its call at the body's end, from the
//! router's copy of its header. A request with no body gets its call at the head, with the
//! engine's request, and the entry copies nothing. The engine's event, a middleware's
//! `on_request` and a struct route's `on_request` come before the body, so a read of
//! `request.body` there fails. The tests run against an engine that records each call, then over
//! h11, h2 and h3. `router_whole_head_test.zig` holds the tests of a router whose `header_bytes`
//! is 0.
const std = @import("std");
const http = @import("http");
const h2 = @import("h2");
const quic = @import("quic");
const event = @import("../event.zig");
const Router = @import("router.zig").Router;
const support = @import("router_handle_test_support.zig");
const whole = @import("router_whole_test_support.zig");
const tcp_support = @import("../engine/engine_tcp_test_support.zig");
const h2_support = @import("../connection/connection_h2_test_support.zig");
const connection_support = @import("../connection/connection_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");

const testing = std.testing;
const Recorder = support.Recorder;
const App = whole.App;

/// A router whose copy of a header holds exactly the header of `named_request("/echo",
/// first_name, false)`. Test-only.
const ExactPool = Router(App, whole.routes, whole.options_with(whole.exact_header_bytes));

fn Fixture(comptime Pool: type) type {
    return struct {
        app: App = .{},
        recorder: Recorder = .{},
        pool: Pool = .{},

        const Self = @This();

        fn handle(fixture: *Self, received: event.Event) void {
            const handled = fixture.pool.handle(&fixture.app, &fixture.recorder, received);
            std.debug.assert(handled == .taken);
        }

        fn head(fixture: *Self, request: event.Request) void {
            fixture.handle(.{ .request = request });
        }

        fn body(fixture: *Self, bytes: []const u8, end: bool) void {
            fixture.handle(.{ .body = .{ .id = whole.first_id, .user_data = fixture.recorder.user_data, .bytes = bytes, .end = end } });
        }
    };
}

test "RFC 6585 §5: a header one octet past header_bytes gets 431, and the route no call" {
    var fixture: Fixture(ExactPool) = .{};
    fixture.head(try whole.named_request("/echo", whole.first_name ++ "!", false));
    try testing.expectEqual(431, @intFromEnum(fixture.recorder.heads[0].status));
    fixture.body("x", true);
    try testing.expectEqual(0, fixture.app.calls);
}

test "decision 163 ruling 5: a header of exactly header_bytes is copied, and the route called" {
    var fixture: Fixture(ExactPool) = .{};
    const request = try whole.named_request("/echo", whole.first_name, false);
    try testing.expectEqual(whole.exact_header_bytes, whole.copy_len(&request));
    fixture.head(request);
    try testing.expectEqual(0, fixture.recorder.head_count);
    fixture.body("x", true);
    try testing.expectEqual(1, fixture.app.calls);
    try testing.expectEqualStrings("x", fixture.recorder.body_bytes());
}

test "RFC 9110 §15.5.14: a body one octet past body_bytes gets 413, and the route no call" {
    var fixture: Fixture(ExactPool) = .{};
    fixture.head(try whole.named_request("/echo", whole.first_name, false));
    fixture.body(whole.full_body[0 .. whole.body_bytes - 1], false);
    fixture.body("!!", true);
    try testing.expectEqual(413, @intFromEnum(fixture.recorder.heads[0].status));
    try testing.expectEqual(0, fixture.app.calls);
}

test "decision 163 ruling 4: a body of exactly body_bytes reaches the route whole" {
    var fixture: Fixture(ExactPool) = .{};
    fixture.head(try whole.named_request("/echo", whole.first_name, false));
    fixture.body(whole.full_body[0 .. whole.body_bytes - 1], false);
    fixture.body("!", true);
    try testing.expectEqual(1, fixture.app.calls);
    try testing.expectEqualStrings(whole.full_body[0 .. whole.body_bytes - 1] ++ "!", fixture.recorder.body_bytes());
}

test "decision 163 ruling 5: a request with no body gets the engine's request, and no copy" {
    var fixture: Fixture(ExactPool) = .{};
    fixture.head(support.request_of(1, "GET", "/empty", true));
    // The call came at the head, with the engine's body, which ends at once.
    try testing.expectEqual(1, fixture.app.calls);
    try testing.expectEqual(error.EndOfStream, fixture.app.empty_read.?);
    try testing.expect(fixture.app.empty_body.? == &support.body_readers.empty);
    // The route got the request that the middleware got: the engine's, with no copy.
    try testing.expect(fixture.app.empty_request.? == fixture.app.middleware_request.?);
    try testing.expect(fixture.recorder.ended);
    try testing.expectEqual(0, fixture.pool.entries[0].header.lines.len());
}

test "decision 163 ruling 4: the error function of a late call reads the copy of the header" {
    var fixture: Fixture(EnginePool) = .{};
    fixture.head(try whole.named_request("/broken", whole.first_name, false));
    // The engine writes its section again, as the next HEADERS frame of an h2 connection does.
    _ = try whole.named_request("/broken", whole.second_name, false);
    fixture.body("x", true);
    try testing.expectEqual(whole.unprocessable, fixture.recorder.heads[0].status);
    try testing.expectEqualStrings(whole.first_name, fixture.app.error_name.get());
    try testing.expectEqualStrings("/broken", fixture.app.error_path.get());
}

/// The router and the program's context of the tests over an engine, which the program hooks
/// reach. Test-only.
const EnginePool = Router(App, whole.routes, whole.options_with(whole.engine_header_bytes));
var engine_router: EnginePool align(@alignOf(EnginePool)) = .{};
var engine_app: App align(@alignOf(App)) = .{};
/// The body events the router took.
var body_events: usize = 0;

const tcp_engine = &tcp_support.engine;
const quic_engine = &quic_support.engine_support.engine;

/// Passes each event the TCP engine reports to the router, as a program's loop does.
fn take_tcp(reported: event.Event) void {
    if (reported == .body) body_events += 1;
    _ = engine_router.handle(&engine_app, tcp_engine, reported);
}

/// Passes each event the QUIC engine reports to the router.
fn take_quic(reported: event.Event) void {
    if (reported == .body) body_events += 1;
    _ = engine_router.handle(&engine_app, quic_engine, reported);
}

/// Starts the TCP engine with the router as its program, and accepts one cleartext connection.
fn start_tcp() !event.ConnectionHandle {
    try tcp_support.start(null, .{});
    tcp_support.program = take_tcp;
    engine_router = .{};
    engine_app = .{};
    body_events = 0;
    return tcp_engine.accept(.{ .tls = false }, tcp_support.now_ns).?;
}

/// Requires the TCP connection to have sent `content`.
fn expect_sent(handle: event.ConnectionHandle, content: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, tcp_support.sent_of(handle.slot), content) != null);
}

/// Requires each read of `request.body` before the body to have failed, in the middleware and in
/// the struct route.
fn expect_reads_failed() !void {
    try testing.expectEqual(error.ReadFailed, engine_app.middleware_read.?);
    try testing.expectEqual(error.ReadFailed, engine_app.struct_read.?);
}

/// Requires `empty` to have had its call at the head, and to have read a body that ended. That
/// body is the engine's, and not the router's reader of a held body.
fn expect_empty_body() !void {
    try testing.expectEqual(1, engine_app.calls);
    try testing.expectEqual(error.EndOfStream, engine_app.empty_read.?);
    try testing.expect(engine_app.empty_body.? != &engine_router.entries[0].body.cursor.reader);
}

const h11_echo_head = "POST /echo HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\n";
const h11_stream_head = "POST /stream HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\n\r\n";
const h11_empty_head = "GET /empty HTTP/1.1\r\nHost: example.com\r\n\r\n";

test "decision 163 ruling 4: a function route reads a body of two events whole, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_echo_head);
    _ = tcp_support.give(handle, whole.echo_body[0..3]);
    try testing.expectEqual(0, engine_app.calls);
    _ = tcp_support.give(handle, whole.echo_body[3..]);
    try testing.expectEqual(1, engine_app.calls);
    try testing.expect(body_events >= 2);
    try expect_sent(handle, whole.echo_body);
}

test "decision 163 ruling 4: a read of the body before it fails, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_stream_head ++ "x");
    try expect_reads_failed();
    try expect_sent(handle, "streamed");
}

test "decision 163 ruling 4: a GET's function route reads an empty body, over h11" {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h11_empty_head);
    try expect_empty_body();
}

/// Starts the TCP engine with a TLS identity and the router as its program. Accepts one
/// connection, whose client offers h11 alone and completes the handshake.
fn start_tls() !event.ConnectionHandle {
    try tcp_support.start(tcp_support.identity(), .{});
    tcp_support.program = take_tcp;
    engine_router = .{};
    engine_app = .{};
    body_events = 0;
    const handle = tcp_engine.accept(.{}, tcp_support.now_ns).?;
    try tcp_support.start_client(&connection_support.protocols_h11);
    try testing.expect(try tcp_support.handshake(handle));
    return handle;
}

/// How a test's octets go to the connection: as they are, or as the TLS client's records.
const Carried = enum { cleartext, sealed };

/// Passes `octets` to the connection, and requires the engine to consume each one.
fn give_h11(handle: event.ConnectionHandle, carried: Carried, octets: []const u8) !void {
    const left = if (carried == .sealed) try tcp_support.give_sealed(handle, octets) else tcp_support.give(handle, octets);
    try testing.expectEqual(0, left);
}

/// The rest of an h11 POST's head after its target, with a body as long as `full_body`.
const h11_parts_rest = std.fmt.comptimePrint(" HTTP/1.1\r\nHost: example.com\r\nContent-Length: {d}\r\n\r\n", .{whole.full_body.len});

/// Passes `head`, and then the body in a later call, and requires the late call to answer with
/// `parts`. The later call writes the body over the head's first octets. In cleartext the
/// fixture's buffer holds them, as a program's read buffer does. Over TLS the connection's
/// `plain_in` holds them.
fn expect_h11_parts(handle: event.ConnectionHandle, carried: Carried, head: []const u8, parts: []const u8) !void {
    try give_h11(handle, carried, head);
    try testing.expectEqual(0, engine_app.calls);
    try testing.expectEqualStrings("POST", engine_app.head_method);
    try give_h11(handle, carried, whole.full_body);
    try testing.expectEqual(1, engine_app.calls);
    // The engine's octets of the method hold the body's first octets now.
    try testing.expectEqualStrings(whole.full_body[0.."POST".len], engine_app.head_method);
    const sent = if (carried == .sealed) try tcp_support.open_sent(handle.slot) else tcp_support.sent_of(handle.slot);
    try testing.expect(std.mem.indexOf(u8, sent, parts) != null);
}

test "decision 163 ruling 5: a late call reads the method, the target, the path and the query, over h11" {
    const handle = try start_tcp();
    // RFC 9112 §3.2.1: the origin-form. Its method and target lie in the octets h11 read.
    const head = "POST /parts?mark=a" ++ h11_parts_rest;
    try expect_h11_parts(handle, .cleartext, head, "POST /parts?mark=a /parts mark=a http example.com");
}

test "decision 163 ruling 5: a late call reads the scheme and the authority of an absolute-form target, over h11" {
    const handle = try start_tcp();
    // RFC 9112 §3.2.2: the absolute-form, whose scheme and authority lie in the target.
    const head = "POST http://h.test/parts?mark=a" ++ h11_parts_rest;
    try expect_h11_parts(handle, .cleartext, head, "POST http://h.test/parts?mark=a /parts mark=a http h.test");
}

test "decision 163 ruling 5: a late call reads the method and the target after a later record, over h11 and TLS" {
    const handle = try start_tls();
    const head = "POST /parts?mark=a" ++ h11_parts_rest;
    try expect_h11_parts(handle, .sealed, head, "POST /parts?mark=a /parts mark=a https example.com");
}

/// Passes one DATA frame of `bytes` on `stream_id`, which ends the stream when `end` is set (RFC
/// 9113 §6.1).
fn give_data(handle: event.ConnectionHandle, stream_id: u32, bytes: []const u8, end: bool) !void {
    var frame: [h2.constants.protocol.frame_header_len + whole.body_bytes]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_data(&writer, stream_id, bytes, end, 0);
    _ = tcp_support.give(handle, writer.written());
}

/// Passes a POST's HEADERS frame of `path` on `stream_id`, with `x-name: name` and the body open.
fn give_post(handle: event.ConnectionHandle, stream_id: u32, path: []const u8, name: []const u8) !void {
    const lines = [_]http.Field{.{ .name = whole.name_field, .value = name }};
    _ = tcp_support.give(handle, try h2_support.request_frame_with(stream_id, "POST", path, &lines, false));
}

/// Starts an h2 connection on the TCP engine.
fn start_h2() !event.ConnectionHandle {
    const handle = try start_tcp();
    _ = tcp_support.give(handle, h2_support.client_preface);
    return handle;
}

test "decision 163 ruling 4: a function route reads a body of two events whole, over h2" {
    const handle = try start_h2();
    try give_post(handle, whole.first_stream, "/echo", whole.first_name);
    try give_data(handle, whole.first_stream, whole.echo_body[0..3], false);
    try testing.expectEqual(0, engine_app.calls);
    try give_data(handle, whole.first_stream, whole.echo_body[3..], true);
    try testing.expectEqual(1, engine_app.calls);
    try testing.expect(body_events >= 2);
    try expect_sent(handle, whole.echo_body);
}

/// The targets of the two requests of `/item/:id`, each with its own mark.
const first_item = "/item/" ++ whole.first_id_text ++ "?mark=" ++ whole.first_mark;
const second_item = "/item/" ++ whole.second_id_text ++ "?mark=" ++ whole.second_mark;

test "decision 163 ruling 5: each late call reads its own request's header, path and query, over h2" {
    const handle = try start_h2();
    // The second request's HEADERS frame writes the connection's field section again, and its
    // match writes the router's path parameters, before the first request's body ends.
    try give_post(handle, whole.first_stream, first_item, whole.first_name);
    try give_post(handle, whole.second_stream, second_item, whole.second_name);
    try give_data(handle, whole.first_stream, "1", true);
    try expect_sent(handle, whole.first_name ++ " " ++ whole.first_id_text ++ " " ++ whole.first_mark ++ " 1");
    try give_data(handle, whole.second_stream, "2", true);
    try expect_sent(handle, whole.second_name ++ " " ++ whole.second_id_text ++ " " ++ whole.second_mark ++ " 2");
    try testing.expectEqual(2, engine_app.calls);
}

test "decision 163 ruling 4: a read of the body before it fails, over h2" {
    const handle = try start_h2();
    try give_post(handle, whole.first_stream, "/stream", whole.first_name);
    try give_data(handle, whole.first_stream, "x", true);
    try expect_reads_failed();
    try expect_sent(handle, "streamed");
}

test "decision 163 ruling 4: a GET's function route reads an empty body, over h2" {
    const handle = try start_h2();
    _ = tcp_support.give(handle, try h2_support.request_frame_with(whole.first_stream, "GET", "/empty", &.{}, true));
    try expect_empty_body();
}

test "decision 163 ruling 5: a GET that ends in an empty DATA frame takes a copy, over h2" {
    const handle = try start_h2();
    _ = tcp_support.give(handle, try h2_support.request_frame_with(whole.first_stream, "GET", "/empty", &.{}, false));
    try testing.expectEqual(0, engine_app.calls);
    // RFC 9113 §8.1: a DATA frame with END_STREAM and no octets ends the request.
    try give_data(handle, whole.first_stream, "", true);
    try testing.expectEqual(1, engine_app.calls);
    // The router read the body it held, which holds no octet.
    try testing.expectEqual(error.EndOfStream, engine_app.empty_read.?);
    try testing.expect(engine_app.empty_body.? == &engine_router.entries[0].body.cursor.reader);
}

/// Starts the QUIC engine with the router as its program, and connects its client.
fn start_quic() !void {
    try quic_support.start_engine(null);
    try quic_support.connect();
    engine_router = .{};
    engine_app = .{};
    body_events = 0;
    quic_support.seen_support.program = take_quic;
}

/// Moves datagrams both ways until the client has the whole response of `fetch`.
fn pump_until_ended(fetch: *const quic_support.Fetch) !void {
    // Bounded: each round moves time on and moves datagrams both ways.
    for (0..whole.rounds_max) |_| {
        if (fetch.ended) return;
        try quic_support.pump(1);
    }
    return error.TestExpectedEnded;
}

test "decision 163 ruling 4: a function route reads a body of two pieces whole, over h3" {
    try start_quic();
    defer quic_support.seen_support.program = null;
    const fetch = try quic_support.stage_request("POST", "/echo", &.{}, whole.echo_body, &.{});
    const half = fetch.prefix_len + whole.echo_body.len / 2;
    try quic.Connection.supply(&quic_support.client, .{ .value = fetch.id }, half, false);
    try quic_support.pump(whole.rounds_piece);
    try testing.expect(body_events > 0);
    try testing.expectEqual(0, engine_app.calls);
    try quic.Connection.supply(&quic_support.client, .{ .value = fetch.id }, fetch.prefix_len + whole.echo_body.len, true);
    try pump_until_ended(fetch);
    try testing.expectEqual(1, engine_app.calls);
    try testing.expectEqualStrings(whole.echo_body, quic_support.content_of(fetch));
}

test "decision 163 ruling 4: a read of the body before it fails, over h3" {
    try start_quic();
    defer quic_support.seen_support.program = null;
    const fetch = try quic_support.request("POST", "/stream", "x");
    try pump_until_ended(fetch);
    try expect_reads_failed();
    try testing.expectEqualStrings("streamed", quic_support.content_of(fetch));
}

test "decision 163 ruling 4: a GET's function route reads an empty body, over h3" {
    try start_quic();
    defer quic_support.seen_support.program = null;
    const fetch = try quic_support.request("GET", "/empty", "");
    try pump_until_ended(fetch);
    try expect_empty_body();
}
