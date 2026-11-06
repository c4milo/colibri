//! The tests of a `colibri.Client` over TCP (design §8 step 42): a `colibri.Server` runs on a
//! thread of its own on 127.0.0.1, and the client runs on the test's thread, over h11 and h2, in
//! cleartext and over TLS. Decision 150 ruling 7 lets these tests bind loopback.
const std = @import("std");
const rotor = @import("rotor");
const client = @import("client");
const testdata = @import("testdata");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

const testing = std.testing;
const test_client = &fixture.test_client;

/// Starts the client on the server's port with `protocols`, over TLS when `secure` is set.
fn start_client(protocols: client.Protocols, secure: bool, counter: *support.Counter) !void {
    var pool = fixture.pool_config(protocols, secure);
    pool.protocols.h3 = false;
    try test_client.init(.{
        .host = "127.0.0.1",
        .port = fixture.port(),
        .pool = pool,
        .random = counter.random(),
        .unix_seconds = testdata.now_seconds,
    });
}

/// Fetches `count` greetings over a client of `protocols`, with `shutdown` before `run`, and
/// returns the handler that recorded them.
fn fetch(protocols: client.Protocols, secure: bool, count: u32, handler: *fixture.Handler) !void {
    var counter: support.Counter = .{};
    try fixture.start_server(secure, false);
    defer fixture.stop_server();
    try start_client(protocols, secure, &counter);
    defer test_client.deinit();
    try handler.request(count);
    test_client.shutdown();
    try fixture.run(handler);
}

test "design §8 step 42: a client fetches over h11 in cleartext" {
    var handler: fixture.Handler = .{};
    try fetch(.{ .h2 = false }, false, 1, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h11, handler.connected.?);
}

test "design §8 step 42: a client fetches over h2 in cleartext by prior knowledge" {
    var handler: fixture.Handler = .{};
    // RFC 9113 §3.3: a client that knows the server speaks h2 sends the preface at once.
    try fetch(.{ .h11 = false }, false, 1, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h2, handler.connected.?);
}

test "design §8 step 42: over TLS, ALPN selects h2 when the client offers both" {
    var handler: fixture.Handler = .{};
    // RFC 7301 §3.2: the server selects h2, the first of the client's list it speaks.
    try fetch(.{}, true, 2, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h2, handler.connected.?);
}

test "design §8 step 42: over TLS with h11 alone, the client offers http/1.1" {
    var handler: fixture.Handler = .{};
    try fetch(.{ .h2 = false }, true, 1, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h11, handler.connected.?);
}

test "design §8 step 42: more requests than connections go one after another over h11" {
    var handler: fixture.Handler = .{};
    try fetch(.{ .h2 = false }, false, fixture.requests_max, &handler);
    try testing.expect(handler.greeted());
}

test "design §8 step 42: a handler makes a request from on_finished, and shuts the client down" {
    var counter: support.Counter = .{};
    try fixture.start_server(false, false);
    defer fixture.stop_server();
    try start_client(.{ .h11 = false }, false, &counter);
    defer test_client.deinit();
    var handler: fixture.Handler = .{ .more = 2, .stop_after = 3 };
    try handler.request(1);
    try fixture.run(&handler);
    try testing.expectEqual(3, handler.requested);
    try testing.expect(handler.greeted());
}

test "design §8 step 42: a slot's next connection opens once its last socket has closed" {
    var counter: support.Counter = .{};
    try fixture.start_server(false, false);
    defer fixture.stop_server();
    try start_client(.{ .h2 = false }, false, &counter);
    defer test_client.deinit();
    // RFC 9112 §9.6: the server closes each connection after its response, so each request of the
    // one TCP slot opens a connection of its own.
    // The handler makes each request once the one before has ended, so none is written on a
    // connection the server closes, and shuts the client down after the third.
    var handler: fixture.Handler = .{ .path = "/goodbye", .more = 2, .stop_after = 3 };
    try handler.request(1);
    try fixture.run(&handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(3, handler.connections);
}

fn shutdown_later(started: *std.atomic.Value(bool)) void {
    // Bounded: the test's run starts within the watchdog's time.
    for (0..std.math.maxInt(u32)) |_| {
        if (started.load(.acquire)) break;
        std.Thread.yield() catch {};
    }
    test_client.shutdown();
}

test "design §8 step 42: shutdown from another thread ends a run that has nothing to do" {
    var counter: support.Counter = .{};
    try fixture.start_server(false, false);
    defer fixture.stop_server();
    try start_client(.{}, false, &counter);
    defer test_client.deinit();
    var handler: fixture.Handler = .{};
    var started: std.atomic.Value(bool) = .init(false);
    const thread = try std.Thread.spawn(.{}, shutdown_later, .{&started});
    started.store(true, .release);
    try fixture.run(&handler);
    thread.join();
    try testing.expectEqual(0, handler.finished);
}

test "design §8 step 42: a refused connect ends the exchange refused" {
    // A port the system gave a listener that is closed again, so no socket listens on it.
    const address = rotor.Address.ipv4(.{ 127, 0, 0, 1 }, 0);
    const listener = try rotor.sync.listen(&address, .{ .backlog = 1, .reuse_port = false });
    const closed_port = (try rotor.sync.local_address(listener)).port;
    rotor.sync.close_now(listener);
    var counter: support.Counter = .{};
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    try test_client.init(.{ .host = "127.0.0.1", .port = closed_port, .pool = pool, .random = counter.random() });
    defer test_client.deinit();
    var handler: fixture.Handler = .{};
    try handler.request(1);
    test_client.shutdown();
    try fixture.run(&handler);
    try testing.expectEqual(1, handler.finished);
    // The connection ended before the request was written, so the server processed none of it.
    try testing.expectEqual(client.Result.refused, handler.exchanges[0].response.result);
    try testing.expectEqual(null, handler.connected);
}

test "design §8 step 42: a chain judged after its notAfter ends the exchange refused" {
    var counter: support.Counter = .{};
    try fixture.start_server(true, false);
    defer fixture.stop_server();
    var pool = fixture.pool_config(.{}, true);
    pool.protocols.h3 = false;
    // RFC 5280 §4.1.2.5: a certificate is valid from notBefore through notAfter, and not after.
    try test_client.init(.{
        .host = "127.0.0.1",
        .port = fixture.port(),
        .pool = pool,
        .random = counter.random(),
        .unix_seconds = testdata.not_after_seconds + 1,
    });
    defer test_client.deinit();
    var handler: fixture.Handler = .{};
    try handler.request(1);
    test_client.shutdown();
    try fixture.run(&handler);
    // RFC 9846 §6.2: the handshake fails, so the request was never written.
    try testing.expectEqual(client.Result.refused, handler.exchanges[0].response.result);
    try testing.expectEqual(null, handler.connected);
}

/// Fetches one greeting over TLS with the chain judged at `unix_seconds`, and returns the result.
fn fetch_at(unix_seconds: u64) !client.Result {
    var counter: support.Counter = .{};
    try fixture.start_server(true, false);
    defer fixture.stop_server();
    var pool = fixture.pool_config(.{}, true);
    pool.protocols.h3 = false;
    try test_client.init(.{ .host = "127.0.0.1", .port = fixture.port(), .pool = pool, .random = counter.random(), .unix_seconds = unix_seconds });
    defer test_client.deinit();
    var handler: fixture.Handler = .{};
    try handler.request(1);
    test_client.shutdown();
    try fixture.run(&handler);
    return handler.exchanges[0].response.result;
}

test "design §8 step 42: a chain is judged at the program's instant, from its notBefore to its notAfter" {
    // RFC 5280 §4.1.2.5: a certificate is valid from notBefore through notAfter, both included.
    // The run adds the loop's time since it started, which is under a second here.
    try testing.expectEqual(client.Result.response, try fetch_at(testdata.not_before_seconds));
    try testing.expectEqual(client.Result.response, try fetch_at(testdata.not_after_seconds - 1));
    try testing.expectEqual(client.Result.refused, try fetch_at(testdata.not_before_seconds - 1));
}

/// The octets a raw peer reads at once, and the response it answers with (RFC 9112 §6.3).
const raw_read_len = 1024;
const raw_response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";

/// What a raw peer does with the one connection it accepts.
const PeerAction = enum { close_unanswered, answer_and_wait };

/// Accepts one connection and reads the request. Then it closes the connection with no answer, or
/// answers and reads until the client closes the connection.
fn raw_peer(listener: *std.Io.net.Server, action: PeerAction) void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const stream = listener.accept(io) catch return;
    defer stream.close(io);
    var read_buffer: [raw_read_len]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    _ = reader.interface.peekGreedy(1) catch return;
    if (action == .close_unanswered) return;
    var write_buffer: [raw_read_len]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    writer.interface.writeAll(raw_response) catch return;
    writer.interface.flush() catch return;
    _ = reader.interface.discardRemaining() catch {};
}

/// Sends one request of `method` over h11 to a raw peer that does `action`, with `shutdown` before
/// `run`.
fn fetch_raw(action: PeerAction, method: []const u8, handler: *fixture.Handler) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{});
    defer listener.deinit(io);
    const thread = try std.Thread.spawn(.{}, raw_peer, .{ &listener, action });
    defer thread.join();
    var counter: support.Counter = .{};
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    try test_client.init(.{ .host = "127.0.0.1", .port = listener.socket.address.getPort(), .pool = pool, .random = counter.random() });
    defer test_client.deinit();
    handler.method = method;
    try handler.request(1);
    test_client.shutdown();
    try fixture.run(handler);
}

test "design §8 step 42: a peer that closes with no answer ends the exchange closed" {
    var handler: fixture.Handler = .{};
    // RFC 9112 §9.3.1: the request was written, so the server may have processed it, and a POST is
    // not sent again (RFC 9110 §9.2.2).
    try fetch_raw(.close_unanswered, "POST", &handler);
    try testing.expectEqual(1, handler.finished);
    try testing.expectEqual(client.Result.closed, handler.exchanges[0].response.result);
}

test "design §8 step 42: the client closes its socket once the pool closes the connection" {
    var handler: fixture.Handler = .{};
    // The peer keeps the connection (RFC 9112 §9.3) and reads until the client closes it, so the
    // run returns only when the client's socket closes.
    try fetch_raw(.answer_and_wait, "GET", &handler);
    try testing.expectEqual(client.Result.response, handler.exchanges[0].response.result);
    try testing.expectEqualStrings("hi", handler.exchanges[0].response.body_received());
}
