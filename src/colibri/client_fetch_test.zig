//! The tests of `fetch` and `cancel` of a `.private` `colibri.Client` (design §8 step 44h),
//! against the `colibri.Server` of `client_test_support.zig` on 127.0.0.1. Decision 150 ruling 7
//! lets these tests bind loopback. The tests of `.hosted` are in `fake_host_test.zig` and
//! `fake_host_pair_test.zig`.
const std = @import("std");
const client = @import("client");
const testdata = @import("testdata");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

const testing = std.testing;
const test_client = &fixture.test_client;

/// RFC 9110 §15.3.1: 200 (OK).
const ok: client.Status = .ok;
/// The body that a POST sends, which the server's `/echo` route answers with.
const note = "a note for the server";
/// The room of a response's body, a room shorter than the greeting, and the room of a header
/// section.
const body_len = 64;
const short_body_len = 4;
const headers_len = 256;

/// Starts the server over TLS, with a UDP socket when `udp` is set, and the client of `protocols`
/// with `handler`.
fn start(protocols: client.Protocols, udp: bool, counter: *support.Counter, handler: anytype) !void {
    try fixture.start_server(true, udp);
    errdefer fixture.stop_server();
    try test_client.init(&.{
        .destination = fixture.loopback(fixture.port()),
        .pool = fixture.pool_config(protocols, true),
        .random = counter.random(),
        .unix_seconds = testdata.now_seconds,
    }, handler);
}

/// Fetches a GET and then a POST over a client of `protocols`, and checks that `expected` carried
/// them on one connection, that each response arrived whole, and that the handler got neither
/// `finished`.
fn get_and_post(protocols: client.Protocols, udp: bool, expected: client.Protocol) !void {
    var counter: support.Counter = .{};
    var handler: fixture.Handler = .{};
    try start(protocols, udp, &counter, &handler);
    defer fixture.stop_server();
    var watchdog: fixture.Watchdog = .{};
    try watchdog.start();
    defer watchdog.stop();
    // `deinit` stops the loop that the first fetch made: each connection closes.
    defer test_client.deinit();
    var body: [body_len]u8 = undefined;
    var headers: [headers_len]u8 = undefined;
    const got = try test_client.fetch(&.{ .path = "/greeting", .response_body = &body, .response_headers = &headers });
    try testing.expectEqual(client.Result.response, got.result);
    try testing.expectEqual(ok, got.status);
    try testing.expectEqualStrings(fixture.greeting, body[0..got.body_len]);
    try testing.expectEqualStrings("text/plain", got.headers.get("content-type") orelse return error.HeaderMissing);
    // A request body makes the method POST (RFC 9110 §9.3.3).
    const posted = try test_client.fetch(&.{ .path = "/echo", .request_body = note, .response_body = &body });
    try testing.expectEqual(client.Result.response, posted.result);
    try testing.expectEqualStrings(note, body[0..posted.body_len]);
    // The loop stayed made between the fetches, so one connection carried both.
    try testing.expectEqual(@as(?client.Protocol, expected), handler.connected);
    try testing.expectEqual(1, handler.connections);
    try testing.expectEqual(0, handler.finished);
}

test "decision 156 ruling 12: fetch runs a GET and a POST over h11" {
    try get_and_post(.{ .h2 = false, .h3 = false }, false, .h11);
}

test "decision 156 ruling 12: fetch runs a GET and a POST over h2" {
    try get_and_post(.{ .h3 = false }, false, .h2);
}

test "decision 156 ruling 12: fetch runs a GET and a POST over h3" {
    try get_and_post(.{ .prefer = .quic }, true, .h3);
}

test "decision 156 ruling 12: a body longer than response_body ends too_large" {
    var counter: support.Counter = .{};
    var handler: fixture.Handler = .{};
    try start(.{ .h3 = false }, false, &counter, &handler);
    defer fixture.stop_server();
    var watchdog: fixture.Watchdog = .{};
    try watchdog.start();
    defer watchdog.stop();
    defer test_client.deinit();
    var body: [short_body_len]u8 = undefined;
    const got = try test_client.fetch(&.{ .path = "/greeting", .response_body = &body });
    // The status arrived with the head, before the body that did not fit.
    try testing.expectEqual(client.Result.too_large, got.result);
    try testing.expectEqual(ok, got.status);
}

/// A handler that keeps the id of each exchange that ended.
const Ended = struct {
    id: ?client.RequestId = null,
    count: u32 = 0,

    pub fn on_finished(handler: *Ended, _: *fixture.TestClient, finished: client.Finished) void {
        handler.id = finished.id;
        handler.count += 1;
    }
};

test "decision 156 ruling 12: a fetch beside an exchange of request leaves that one to the handler" {
    var counter: support.Counter = .{};
    var handler: Ended = .{};
    try start(.{ .h3 = false }, false, &counter, &handler);
    defer fixture.stop_server();
    var watchdog: fixture.Watchdog = .{};
    try watchdog.start();
    defer watchdog.stop();
    var exchange: fixture.Exchange = .{};
    exchange.response = .{ .body = &exchange.body };
    const id = try test_client.request(&exchange.request, &exchange.response);
    var body: [body_len]u8 = undefined;
    const got = test_client.fetch(&.{ .path = "/greeting", .response_body = &body }) catch |failure| {
        test_client.deinit();
        return failure;
    };
    // `deinit` runs the loop until the exchange of `request` has ended too, on the one h2
    // connection, and until that connection has closed (decision 156 ruling 10).
    test_client.deinit();
    try testing.expect(test_client.stopped());
    try testing.expectEqualStrings(fixture.greeting, body[0..got.body_len]);
    // The handler got the exchange of `request`, by its id, and not the exchange of the fetch.
    try testing.expectEqual(1, handler.count);
    try testing.expectEqual(@as(?client.RequestId, id), handler.id);
    try testing.expectEqualStrings(fixture.greeting, exchange.response.body_received());
}

test "decision 156 ruling 12: a fetch after shutdown returns ShutDown, and makes no loop" {
    var counter: support.Counter = .{};
    // No server runs: the fetch ends before the client connects.
    try test_client.init(&.{
        .destination = fixture.loopback(fixture.https_port),
        .pool = fixture.pool_config(.{ .h3 = false }, false),
        .random = counter.random(),
        .unix_seconds = testdata.now_seconds,
    }, null);
    defer test_client.deinit();
    test_client.shutdown();
    try testing.expectError(error.ShutDown, test_client.fetch(&.{ .path = "/greeting" }));
    try testing.expect(!test_client.begun and test_client.fetching == null);
}

test "decision 156 ruling 12: a cancelled exchange gives the handler no finished" {
    var counter: support.Counter = .{};
    var handler: fixture.Handler = .{};
    try start(.{ .h2 = false, .h3 = false }, false, &counter, &handler);
    defer fixture.stop_server();
    defer test_client.deinit();
    try handler.request(1);
    const second = &handler.exchanges[1];
    second.response = .{ .body = &second.body };
    const id = try test_client.request(&second.request, &second.response);
    test_client.cancel(id);
    test_client.shutdown();
    try fixture.run();
    try testing.expectEqual(1, handler.finished);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Result.pending, second.response.result);
}
