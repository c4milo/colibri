//! One connection of the test-only client, on the `client` module (design §8 step 21c): the
//! plan's exchanges handed to a `client.Channel` with TCP alone, which speaks h2 or h11 and runs TLS
//! itself. `client_loop.zig` is the socket around it, and these tests run it against §9's server in
//! one process.
//!
//! Every exchange of the plan is requested at once, so h2 multiplexes them and h11 pipelines them
//! as decision 88 allows, and the channel is shut down at once: its connection ends after its last
//! exchange, h2 with its GOAWAY (RFC 9113 §6.8), and the channel reports `closed` once no
//! connection is left. The channel asks for each socket with an `open` event and is done with it
//! at a `close` event. An exchange a connection refused unprocessed moves to the next connection,
//! on a socket of its own (decision 100).
//!
//! Time is a value, never a clock: each step reports an instant `tick_ns` after the last (design
//! §4.2, invariant 6).
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const tls = @import("tls");
const constants = @import("../constants.zig");
const client_exchange = @import("client_exchange.zig");

const Exchange = client_exchange.Exchange;
const Plan = client_exchange.Plan;

/// What one step did, and what the channel asked of the socket during it.
pub const Step = struct {
    /// Octets of the caller's input the channel consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// The channel is done with the socket: the caller sends what it holds, then closes it.
    close: bool,
    /// Where the next socket the channel asked for goes, or null. The caller closes the last socket
    /// before it opens this one.
    open: ?client.Address,
    /// The channel reported `closed`: every exchange ended, and no connection is left.
    done: bool,
};

/// The response content of each exchange of one connection, which `client` fills.
pub const Bodies = [constants.exchanges_max][constants.response_content_len_max]u8;

/// One connection's client state, in storage the caller places. The channel stays in place after
/// `init`: the TLS configuration it built points into it.
pub const Session = struct {
    channel: client.Channel,
    /// The server's one address, which the channel reads for each socket it asks for.
    addresses: [1]client.Address,
    exchanges: [constants.exchanges_max]Exchange,
    exchanges_count: u32,
    /// What each connection's start takes: the source its TLS session draws from, and the instant
    /// chapulin judges the server's chain at, in seconds since 1970-01-01T00:00:00Z.
    random: tls.Random,
    now_seconds: u64,
    /// The instant the next step passes (design §4.2).
    now_ns: u64,
    /// Whether the channel's `closed` event arrived.
    closed: bool,
    /// The protocol of the connection that last reported `connected`.
    protocol: ?client.Protocol,
    /// What the channel asked of the socket since the step began.
    close_asked: bool,
    open_asked: ?client.Address,

    /// Makes a channel that has opened nothing, with every exchange of `plans` requested, to the
    /// server at `address`, whose port is 0, and `port`. `config`, `plans` and `bodies` must
    /// outlive the session.
    pub fn init(
        session: *Session,
        config: *const client.Config,
        address: client.Address,
        port: u16,
        random: tls.Random,
        now_seconds: u64,
        plans: []const Plan,
        bodies: *Bodies,
    ) !void {
        assert(plans.len > 0 and plans.len <= constants.exchanges_max);
        assert(address.port == 0);
        session.exchanges_count = 0;
        session.addresses = .{address};
        try session.channel.init(config, .{ .addresses = &session.addresses, .port = port }, null);
        session.random = random;
        session.now_seconds = now_seconds;
        session.now_ns = 0;
        session.closed = false;
        session.protocol = null;
        session.close_asked = false;
        session.open_asked = null;
        for (plans, session.exchanges[0..plans.len], bodies[0..plans.len]) |plan, *exchange, *body| {
            exchange.* = .init(plan, body);
            exchange.id = try session.channel.request(&exchange.carried);
            session.exchanges_count += 1;
        }
        // The channel takes no request after `shutdown`, so the requests come first.
        session.channel.shutdown();
    }

    /// Consumes what it can of `input`, the octets the socket read and the caller still holds, and
    /// writes what it can into `output`. Over TLS the channel opens records in place in `input`.
    pub fn step(session: *Session, input: []u8, output: []u8) Step {
        session.now_ns += constants.tick_ns;
        session.close_asked = false;
        session.open_asked = null;
        var consumed = session.read(input);
        const written = session.channel.send_stream(output, session.now_ns);
        // After a send the channel reads again, with the octets the caller still holds: h11 reads
        // a held octet only once the response before it ends (decision 119).
        consumed += session.read(input[consumed..]);
        return .{
            .consumed = consumed,
            .written = written,
            .close = session.close_asked,
            .open = session.open_asked,
            .done = session.closed,
        };
    }

    /// The socket the channel asked for connected, so the channel starts its connection on it.
    /// False when chapulin refused the start: the attempt ends, and the caller closes the socket,
    /// since the channel owes no `close` for a connection that never started.
    pub fn started(session: *Session) bool {
        session.channel.start_tcp(session.random, session.now_seconds, null) catch return false;
        return true;
    }

    /// Reads events, passing the octets still held each time, until the channel consumes nothing
    /// and reports nothing.
    fn read(session: *Session, input: []u8) usize {
        var consumed: usize = 0;
        // Bounded: each pass consumes an octet or reports one of the finitely many events.
        for (0..input.len + constants.exchanges_max * constants.steps_per_read_max) |_| {
            const held = input[consumed..];
            const passed: client.Input = if (held.len > 0) .{ .stream = held } else .none;
            const received = session.channel.receive(passed, session.now_ns);
            consumed += received.consumed;
            const reported = received.event orelse {
                if (received.consumed == 0) return consumed;
                continue;
            };
            session.record(reported);
        }
        return consumed;
    }

    fn record(session: *Session, reported: client.Event) void {
        switch (reported) {
            .finished => |ended| session.exchange_of(ended.id).finished = true,
            // The client offers no ticket, so it keeps none it is given.
            .ticket => |transport| if (session.channel.take_ticket(transport)) |ticket| {
                var held = ticket;
                held.wipe();
            },
            .closed => session.closed = true,
            .connected => |protocol| session.protocol = protocol,
            // The channel holds no receive pool, so it offers TCP alone.
            .open => |asked| {
                assert(asked.transport == .tcp);
                session.open_asked = asked.to;
            },
            .close => |transport| {
                assert(transport == .tcp);
                session.asked_close();
            },
        }
    }

    /// The channel is done with a connection. One whose `open` came in this step never had a
    /// socket, so the caller opens none for it. Any other is the socket's.
    fn asked_close(session: *Session) void {
        if (session.open_asked != null) {
            session.open_asked = null;
            return;
        }
        session.close_asked = true;
    }

    fn exchange_of(session: *Session, id: client.Id) *Exchange {
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.id == id) return exchange;
        }
        unreachable; // The channel reports only the exchanges `init` requested.
    }

    /// Whether every exchange ended the way a working peer ends one.
    pub fn succeeded(session: *const Session) bool {
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (!exchange.succeeded()) return false;
        }
        return true;
    }

    /// The exchanges of the plan, as they stand.
    pub fn exchanges_held(session: *const Session) []const Exchange {
        return session.exchanges[0..session.exchanges_count];
    }

    /// The socket ended before the channel was done with it: the peer closed it, it failed, or its
    /// connect failed. In h11 the close ends a body that runs until it (RFC 9112 §6.3 rule 8), and
    /// every exchange left ends or moves. The next step reads what the channel asks for then.
    pub fn peer_closed(session: *Session) void {
        session.channel.transport_closed(.tcp);
    }
};

const testing = std.testing;
const server_session = @import("../server/server_session.zig");
const entropy = @import("../entropy.zig");
const client_options = @import("client_options.zig");

/// The server's session, which holds the one connection the client opens. Test-only.
const ServerSession = server_session.SessionOf(1);

/// The two sessions the tests run, their bodies, and the octets each has written that the other
/// has not read. Placed outside any stack frame. Test-only.
var test_client: Session align(@alignOf(Session)) = undefined;
var test_server: ServerSession align(@alignOf(ServerSession)) = undefined;
/// Decision 117: the server names no version, and reads it from the client's first octets.
var test_server_config: server_session.server.Config align(@alignOf(server_session.server.Config)) = .{};
var test_bodies: Bodies align(@alignOf(Bodies)) = undefined;
var test_to_server: [constants.write_buffer_len]u8 = @splat(0);
var test_to_client: [constants.write_buffer_len]u8 = @splat(0);
var test_config: client.Config align(@alignOf(client.Config)) = .{ .authority = "localhost" };
/// The server's address, which no socket reads: the test passes the octets itself. Test-only.
const test_octets: [client_options.ipv4_octets]u8 = @splat(0);
const test_address = client.Address.of(&test_octets, 0);

/// Most rounds a test exchanges octets for, which bounds its loop. Test-only.
const test_rounds_max: u32 = 4096;

/// The instant of the server's last step, a tick after the one before. Test-only.
var test_server_now_ns: u64 = 0;
/// The octets the step that reported the channel's `close` wrote, once one did. Test-only.
var test_close_written: ?usize = null;

fn test_drop(buffer: []u8, len: usize, consumed: usize) usize {
    std.mem.copyForwards(u8, buffer[0 .. len - consumed], buffer[consumed..len]);
    return len - consumed;
}

/// Starts the server's session with one connection accepted in cleartext. Test-only.
fn test_start_server() !void {
    test_server_now_ns = 0;
    try test_server.init(&test_server_config, entropy.random(), test_server_now_ns);
    try testing.expect(test_server.accept(0, .cleartext, null, test_server_now_ns));
}

/// Runs the client against the server until the client is done or neither moves. The one socket
/// the channel asks for connects at once, to the server's one accepted connection. Test-only.
fn test_run() !u32 {
    var to_server_len: usize = 0;
    var to_client_len: usize = 0;
    var opens: u32 = 0;
    test_close_written = null;
    for (0..test_rounds_max) |round| {
        const stepped = test_client.step(test_to_client[0..to_client_len], test_to_server[to_server_len..]);
        to_client_len = test_drop(&test_to_client, to_client_len, stepped.consumed);
        to_server_len += stepped.written;
        const opened: u32 = @intFromBool(stepped.open != null);
        if (opened > 0) try testing.expect(test_client.started());
        opens += opened;
        if (stepped.close) test_close_written = stepped.written;
        test_server_now_ns += constants.tick_ns;
        const served = test_server.step(0, test_to_server[0..to_server_len], test_to_client[to_client_len..], test_server_now_ns);
        to_server_len = test_drop(&test_to_server, to_server_len, served.consumed);
        to_client_len += served.written;
        const moved = stepped.consumed + stepped.written + served.consumed + served.written + opened;
        // The server has one connection, so the channel asks for one socket alone.
        try testing.expect(opens <= 1);
        if (stepped.done or moved == 0) return @intCast(round + 1);
    }
    return test_rounds_max;
}

test "h2: every exchange of the plan shares the connection, and content past the window goes out" {
    client_exchange.fill_content();
    // Decision 117: the server names no version and reads h2 from the client's preface.
    try test_start_server();
    test_config = .{ .authority = "localhost", .versions = .{ .h11 = false } };
    // RFC 9113 §6.9.2: a stream starts with 65,535 octets of window.
    const content_len = 3 * 65_535;
    try test_client.init(&test_config, test_address, constants.default_port, entropy.random(), 0, &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "POST", .path = "/upload", .content_len = content_len },
    }, &test_bodies);
    try testing.expect(try test_run() < test_rounds_max);
    try testing.expect(test_client.succeeded() and test_client.closed);
    try testing.expectEqual(client.Protocol.h2, test_client.protocol.?);
    const upload = &test_client.exchanges[1];
    try testing.expectEqual(content_len, upload.carried.content_sent);
    try testing.expectEqual(client_exchange.content_crc32(content_len), upload.sent_crc32());
    try testing.expectEqual(constants.response_status, upload.carried.status);
    try testing.expectEqualStrings(constants.response_body, test_client.exchanges[0].carried.content_received());
    // RFC 9113 §6.8: the step that writes the GOAWAY reads again after it, and reports the close,
    // so the caller closes the socket once the GOAWAY is sent.
    try testing.expect(test_close_written.? > 0);
}

test "h11: the exchanges go out in order, and the connection ends after the last" {
    client_exchange.fill_content();
    // Decision 117: the server names no version and reads h11 from the client's first octets.
    try test_start_server();
    test_config = .{ .authority = "localhost", .versions = .{ .h2 = false } };
    try test_client.init(&test_config, test_address, constants.default_port, entropy.random(), 0, &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "GET", .path = "/index.html", .content_len = 0 },
    }, &test_bodies);
    try testing.expect(try test_run() < test_rounds_max);
    try testing.expect(test_client.succeeded() and test_client.closed);
    try testing.expectEqual(client.Protocol.h11, test_client.protocol.?);
    for (test_client.exchanges_held()) |*exchange| {
        try testing.expectEqual(constants.response_status, exchange.carried.status);
    }
}

/// A request with no content, and how many of them the pipelining test makes. Test-only.
const test_get: Plan = .{ .method = "GET", .path = "/", .content_len = 0 };
const test_pipelined: usize = 3;
/// A response with one octet of content (RFC 9112 §6.3 rule 6). Test-only.
const test_short_response = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";

test "decision 119: one step reads every pipelined h11 response the socket holds" {
    client_exchange.fill_content();
    test_config = .{ .authority = "localhost", .versions = .{ .h2 = false } };
    try test_client.init(&test_config, test_address, constants.default_port, entropy.random(), 0, &(.{test_get} ** test_pipelined), &test_bodies);
    // The channel asks for its socket, which connects at once, and its connection writes the
    // requests.
    try testing.expect(test_client.step(test_to_client[0..0], &test_to_server).open != null);
    try testing.expect(test_client.started());
    try testing.expect(test_client.step(test_to_client[0..0], &test_to_server).written > 0);
    // h11 reads a held response only once the one before it ends, so the step passes the octets
    // it still holds after each event.
    const held = test_short_response ** test_pipelined;
    @memcpy(test_to_client[0..held.len], held);
    const stepped = test_client.step(test_to_client[0..held.len], &test_to_server);
    try testing.expectEqual(held.len, stepped.consumed);
    try testing.expect(test_client.succeeded());
}
