//! One connection of the test-only client, on the `client` module (design §8 step 17c): the plan's
//! exchanges handed to `client.Connection`, which speaks h2 or h11 and runs TLS itself.
//! `client_loop.zig` is the socket around it, and these tests run it against §9's server in one
//! process.
//!
//! Every exchange of the plan is requested at once, so h2 multiplexes them and h11 pipelines them
//! as decision 88 allows, and the connection is shut down at once: it ends after its last exchange,
//! h2 with its GOAWAY (RFC 9113 §6.8).
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

/// What one step did.
pub const Step = struct {
    /// Octets of the caller's input the connection consumed.
    consumed: usize,
    /// Octets written into the caller's output, to be sent in order.
    written: usize,
    /// Whether the connection is over and has written every octet it owes: the caller closes.
    done: bool,
};

/// The response content of each exchange of one connection, which `client` fills.
pub const Bodies = [constants.exchanges_max][constants.response_content_len_max]u8;

/// One connection's client state, in storage the caller places.
pub const Session = struct {
    connection: client.Connection,
    exchanges: [constants.exchanges_max]Exchange,
    exchanges_count: u32,
    /// The instant the next step passes (design §4.2).
    now_ns: u64,
    /// Whether the connection's `closed` event arrived.
    closed: bool,
    /// The protocol the connection speaks, once its `connected` event arrived.
    protocol: ?client.Protocol,

    /// Makes a client connection that has read nothing and written nothing, with every exchange of
    /// `plans` requested. `config`, `plans` and `bodies` must outlive the session.
    pub fn init(session: *Session, config: *const client.Config, random: tls.Random, now_seconds: u64, plans: []const Plan, bodies: *Bodies) !void {
        assert(plans.len > 0 and plans.len <= constants.exchanges_max);
        try session.connection.init(config, random, now_seconds, null);
        session.exchanges_count = @intCast(plans.len);
        session.now_ns = 0;
        session.closed = false;
        session.protocol = null;
        for (plans, session.exchanges[0..plans.len], bodies[0..plans.len]) |plan, *exchange, *body| {
            exchange.* = .init(plan, body);
            exchange.id = try session.connection.request(&exchange.carried);
        }
        session.connection.shutdown();
    }

    /// Consumes what it can of `input` and writes what it can into `output`.
    pub fn step(session: *Session, input: []u8, output: []u8) Step {
        session.now_ns += constants.tick_ns;
        const consumed = session.read(input);
        const written = session.connection.send(output, session.now_ns);
        return .{ .consumed = consumed, .written = written, .done = session.connection.should_close() };
    }

    /// Reads events until the connection consumes nothing and reports nothing.
    fn read(session: *Session, input: []u8) usize {
        var consumed: usize = 0;
        // Bounded: each pass consumes an octet or reports one of the finitely many events.
        for (0..input.len + constants.exchanges_max * constants.steps_per_read_max) |_| {
            const received = session.connection.receive(input[consumed..], session.now_ns);
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
            .ticket => if (session.connection.take_ticket()) |ticket| {
                var held = ticket;
                held.wipe();
            },
            .closed => session.closed = true,
            .connected => |protocol| session.protocol = protocol,
            .draining => {},
        }
    }

    fn exchange_of(session: *Session, id: client.Id) *Exchange {
        for (session.exchanges[0..session.exchanges_count]) |*exchange| {
            if (exchange.id == id) return exchange;
        }
        unreachable; // `client` reports only the exchanges `init` requested.
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

    /// The transport closed. In h11 the close ends a body that runs until it (RFC 9112 §6.3 rule
    /// 8), and every exchange left ends. Returns whether the run is still a success.
    pub fn peer_closed(session: *Session) bool {
        session.connection.transport_closed();
        var none: [0]u8 = .{};
        _ = session.read(&none);
        return session.succeeded();
    }
};

const testing = std.testing;
const server_session = @import("../server_session.zig");
const entropy = @import("../entropy.zig");

/// The two sessions the tests run, their bodies, and the octets each has written that the other
/// has not read. Placed outside any stack frame. Test-only.
var test_client: Session align(@alignOf(Session)) = undefined;
var test_server: server_session.Session align(@alignOf(server_session.Session)) = undefined;
var test_bodies: Bodies align(@alignOf(Bodies)) = undefined;
var test_to_server: [constants.write_buffer_len]u8 = @splat(0);
var test_to_client: [constants.write_buffer_len]u8 = @splat(0);
var test_config: client.Config align(@alignOf(client.Config)) = .{ .authority = "localhost" };

/// Most rounds a test exchanges octets for, which bounds its loop. Test-only.
const test_rounds_max: u32 = 4096;

fn test_drop(buffer: []u8, len: usize, consumed: usize) usize {
    std.mem.copyForwards(u8, buffer[0 .. len - consumed], buffer[consumed..len]);
    return len - consumed;
}

/// Runs the client against the server until the client is done or neither moves. Test-only.
fn test_run() u32 {
    var to_server_len: usize = 0;
    var to_client_len: usize = 0;
    for (0..test_rounds_max) |round| {
        const stepped = test_client.step(test_to_client[0..to_client_len], test_to_server[to_server_len..]);
        to_client_len = test_drop(&test_to_client, to_client_len, stepped.consumed);
        to_server_len += stepped.written;
        const served = test_server.step(test_to_server[0..to_server_len], test_to_client[to_client_len..]);
        to_server_len = test_drop(&test_to_server, to_server_len, served.consumed);
        to_client_len += served.written;
        const moved = stepped.consumed + stepped.written + served.consumed + served.written;
        if (stepped.done or moved == 0) return @intCast(round + 1);
    }
    return test_rounds_max;
}

test "h2: every exchange of the plan shares the connection, and content past the window goes out" {
    client_exchange.fill_content();
    try test_server.init(&.{ .cleartext = .h2 }, entropy.random(), null);
    test_config = .{ .authority = "localhost", .cleartext = .h2 };
    // RFC 9113 §6.9.2: a stream starts with 65,535 octets of window.
    const content_len = 3 * 65_535;
    try test_client.init(&test_config, entropy.random(), 0, &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "POST", .path = "/upload", .content_len = content_len },
    }, &test_bodies);
    try testing.expect(test_run() < test_rounds_max);
    try testing.expect(test_client.succeeded() and test_client.closed);
    try testing.expectEqual(client.Protocol.h2, test_client.protocol.?);
    const upload = &test_client.exchanges[1];
    try testing.expectEqual(content_len, upload.carried.content_sent);
    try testing.expectEqual(client_exchange.content_crc32(content_len), upload.sent_crc32());
    try testing.expectEqual(constants.response_status, upload.carried.status);
    try testing.expectEqualStrings(constants.response_body, test_client.exchanges[0].carried.content_received());
}

test "h11: the exchanges go out in order, and the connection ends after the last" {
    client_exchange.fill_content();
    try test_server.init(&.{ .cleartext = .h11 }, entropy.random(), null);
    test_config = .{ .authority = "localhost", .cleartext = .h11 };
    try test_client.init(&test_config, entropy.random(), 0, &.{
        .{ .method = "GET", .path = "/", .content_len = 0 },
        .{ .method = "GET", .path = "/index.html", .content_len = 0 },
    }, &test_bodies);
    try testing.expect(test_run() < test_rounds_max);
    try testing.expect(test_client.succeeded() and test_client.closed);
    try testing.expectEqual(client.Protocol.h11, test_client.protocol.?);
    for (test_client.exchanges_held()) |*exchange| {
        try testing.expectEqual(constants.response_status, exchange.carried.status);
    }
}
