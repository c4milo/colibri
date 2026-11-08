//! A client that runs a `client.ConnectionPool` on Rotor's loop (decision 153 ruling 8, design §8
//! step 42): h11 and h2 over TCP, and h3 over QUIC on a UDP socket. It is the counterpart of
//! `colibri.Server`. It owns the TCP sockets, the UDP socket, the loop and its clock, and the pool.
//! A program places one, hands it requests, and keeps it in place while it runs.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const tls = @import("tls");
const rotor = @import("rotor");
const entropy = @import("entropy.zig");
const server_loop = @import("server_loop.zig");
const datagram_socket = @import("datagram_socket.zig");
const socket_module = @import("socket.zig");
const client_tcp = @import("client_tcp.zig");
const client_loop = @import("client_loop.zig");
const server_module = @import("server.zig");

/// Where a client connects and how its pool runs. The program keeps each slice the pool's
/// configuration names alive while the client runs: the authority, the TLS anchors and pins, and
/// the decoder pools.
pub const ClientConfig = struct {
    /// The server's address: an IPv4 or IPv6 literal. The client looks up no name.
    host: []const u8,
    /// The server's port for TCP and UDP: 443 for "https" unless the URI names another (RFC 9110
    /// §4.2.2).
    port: u16 = 443,
    /// What the pool starts from: the authority, the protocols, the TLS value, the codings and the
    /// timeouts. `init` sets its `tcp_connections` and `requests` to the client's own counts, and
    /// sets its `ecn`, because the client's loop reads and sets each datagram's ECN codepoint
    /// (decision 68). `timeouts.connect_ns` bounds each TCP connect, to one day at most, the
    /// longest deadline Rotor takes.
    pool: client.Config,
    /// The source each TLS session and each QUIC connection draws from. Null draws from the
    /// operating system's entropy (decision 150 ruling 9).
    random: ?tls.Random = null,
    /// The seconds since 1970-01-01T00:00:00Z when `run` starts, which the program reads from its
    /// clock. The client reads no clock (non-negotiable 3), so the field has no default. A web
    /// PKI trust judges the dates of each chain at it, plus the time the loop has run since (RFC
    /// 5280 §4.1.2.5). A trust in pins judges no date.
    unix_seconds: u64,
};

/// What a client holds, fixed at build time: whether it holds a QUIC connection, the TCP
/// connections, and the requests at once. `Client` holds the defaults, and `ClientOf` takes
/// another capacity.
pub const ClientCapacity = struct {
    quic: bool = true,
    tcp_connections: u16 = 1,
    requests: u16 = client.constants.limits.requests_max,
};

/// A client of the default capacity: QUIC, one TCP connection, and `requests_max` requests.
pub const Client = ClientOf(.{});

/// A client whose pool holds `capacity`'s connections and requests.
pub fn ClientOf(comptime capacity: ClientCapacity) type {
    return struct {
        const Self = @This();

        const Pool = client.ConnectionPool(.{ .quic = capacity.quic });
        const pool_memory_len = Pool.memory_bytes(.{ .tcp_connections = capacity.tcp_connections, .requests = capacity.requests });
        const ReceivePool = receive_pool_type(capacity.quic);
        const tcp_connections = capacity.tcp_connections;
        const Bits = std.bit_set.IntegerBitSet(tcp_connections);
        /// The operations the loop holds in flight: for each TCP socket a receive, a send and a
        /// close, or its connect alone, and the UDP socket's receive and sends.
        const loop_options: rotor.Loop.Options = .{
            .operations = tcp_connections * socket_module.operations_per_socket + udp_operations(capacity.quic),
        };
        comptime {
            assert(capacity_valid(capacity, loop_options));
        }

        config: ClientConfig,
        /// The pool, the configuration and the address it borrows, and its memory. The pool stays
        /// in place after `init`: its TLS configurations point into it.
        pool: Pool,
        pool_config: client.Config,
        addresses: [1]client.Address,
        pool_memory: [pool_memory_len]u8 align(Pool.memory_alignment),
        /// The pool each QUIC connection holds the server's unread octets in (decision 61).
        receive_pool: ReceivePool,
        /// The UDP socket, open when the pool offers QUIC. `run` or `deinit` closes it once.
        udp: datagram_socket.DatagramSocket,
        /// The loop, and each TCP slot's socket and what the client holds for it
        /// (`client_tcp.zig`).
        loop_memory: [rotor.Loop.memory_bytes(&loop_options)]u8 align(rotor.memory_alignment),
        loop: rotor.Loop,
        events: [loop_options.operations]rotor.Event,
        sockets: [tcp_connections]socket_module.Socket,
        connections: [tcp_connections]client_tcp.Connection,
        /// The sockets an event named since their last step, and the sockets a turn changed.
        pending: Bits,
        touched: Bits,
        /// Whether a read of the pool's events stopped at its bound, or a call left events to
        /// read.
        undrained: bool,
        /// The loop's instant when `run` started, which `unix_seconds` counts from.
        started_ns: u64,
        /// `shutdown` asked, the loop passed it to the pool, and the pool reported `closed`.
        stopping: std.atomic.Value(bool),
        shut_down: bool,
        closed: bool,
        /// `run` was called since `init`.
        ran: bool,

        /// Keeps the configuration, prepares the pool, and opens the UDP socket when the pool
        /// offers QUIC: h3 allowed, a TLS value, and a client that holds QUIC (RFC 9114 §3.1).
        pub fn init(self: *Self, config: ClientConfig) !void {
            self.config = config;
            self.udp.open = false;
            self.ran = false;
            // A run that fails before its first turn closes the sockets that are live
            // (`socket.close_left`).
            for (&self.sockets) |*socket| socket.live = false;
            if (self.config.random == null) self.config.random = entropy.random();
            const address = try server_loop.address_of(config.host, 0);
            self.addresses = .{datagram_socket.peer_address(address)};
            self.pool_config = config.pool;
            self.pool_config.tcp_connections = capacity.tcp_connections;
            self.pool_config.requests = capacity.requests;
            // Decision 68: the client's loop reads each datagram's codepoint and sets the one the
            // pool names, so the pool reads ECN whatever the program set. A pool that does not
            // read it halts on a datagram marked ECT(0), as a `colibri.Server` marks them.
            self.pool_config.ecn = true;
            const destination: client.Destination = .{ .addresses = &self.addresses, .port = config.port };
            try self.pool.init(&self.pool_memory, &self.pool_config, destination, self.receive_storage());
            if (self.offers_quic()) try self.udp.bind(&unspecified(address.family));
            self.stopping = .init(false);
            self.undrained = false;
        }

        /// Closes the UDP socket when `run` did not close it. The program calls it once after
        /// `init` returns, and after `run` returns when it calls `run`. The client keeps no ticket
        /// and no private key, so it wipes nothing. The next `run` comes after the next `init`.
        pub fn deinit(self: *Self) void {
            // `init` sets the source on each path, before any step that can fail.
            assert(self.config.random != null);
            self.udp.close();
        }

        /// Hands the pool a request and the response it fills, and returns the exchange's id. The
        /// program keeps both in place, and each slice they name, until the exchange's `finished`
        /// event (decision 124). It calls `request` before `run`, or from a handler `run` calls,
        /// on the loop's thread. After `shutdown`, from any thread, it returns `ShutDown`. The
        /// request and its response have whole bodies: `message.streamed` asks for nothing.
        pub fn request(self: *Self, message: *const client.Request, response: *client.Response) (client.RequestError || error{ShutDown})!client.RequestId {
            // The client has no call that hands a piece or gives one back, so a streamed exchange
            // could never finish (design §8 step 42).
            assert(!message.streamed.request and !message.streamed.response);
            // The pool takes no request after its own shutdown, which the loop passes it at its
            // next turn (`ConnectionPool.request`).
            if (self.stopping.load(.acquire)) return error.ShutDown;
            const id = try self.pool.request(message, response);
            // The pool reports the open or the send the request needs at the next read.
            self.undrained = true;
            return id;
        }

        /// Asks the client to stop: `request` returns `ShutDown` from now on, and `run` returns
        /// once each exchange has finished and each connection has closed. Any thread may call it.
        pub fn shutdown(self: *Self) void {
            self.stopping.store(true, .release);
        }

        /// Runs the pool on the thread that calls it until `shutdown`, and returns once each
        /// exchange has finished and each connection has closed. `handler` points at the
        /// program's struct, which declares `on_finished(handler, *Client, client.Finished)` and
        /// may declare `on_connected(handler, *Client, client.Connected)`. Each runs on this
        /// thread, and may call `request` and `shutdown`. The loop runs here because a Rotor loop
        /// belongs to the thread that starts it (decision 150 ruling 7). A program calls `run`
        /// once for each `init`.
        pub fn run(self: *Self, handler: anytype) server_module.RunError!void {
            return client_loop.run_loop(self, handler, loop_options);
        }

        /// The receive pool the pool's QUIC connections use, or null for a client with no QUIC.
        fn receive_storage(self: *Self) ?client.ReceiveStorage {
            return if (capacity.quic) self.receive_pool.storage() else null;
        }

        /// Whether the pool offers QUIC, which the pool decided from the configuration. A pool with
        /// no QUIC offers none.
        fn offers_quic(self: *const Self) bool {
            return self.pool.offered.quic;
        }
    };
}

/// The type of the receive pool a client holds: the default one with QUIC, and none without.
fn receive_pool_type(quic: bool) type {
    return if (quic) client.ReceivePool(.{}) else void;
}

/// The operations the UDP socket holds in flight, or none for a client with no QUIC.
fn udp_operations(quic: bool) u32 {
    return if (quic) datagram_socket.operations else 0;
}

/// Whether each count of `capacity` is inside the pool's limits, and the loop holds every
/// operation the client submits.
fn capacity_valid(capacity: ClientCapacity, loop_options: rotor.Loop.Options) bool {
    if (capacity.tcp_connections == 0 or capacity.tcp_connections > client.constants.limits.pool_tcp_connections_max) return false;
    if (capacity.requests == 0 or capacity.requests > client.constants.limits.pool_requests_max) return false;
    if (loop_options.operations > rotor.constants.batch_max) return false;
    return capacity.tcp_connections < datagram_socket.send_user_data_last >> socket_module.kind_bits;
}

/// The address that binds a UDP socket of `family` on every interface, on a port the system
/// chooses.
fn unspecified(family: rotor.Address.Family) rotor.Address {
    return switch (family) {
        .ipv4 => rotor.Address.ipv4(@splat(0), 0),
        .ipv6 => rotor.Address.ipv6(@splat(0), 0, 0),
    };
}

const testing = std.testing;
const testdata = @import("testdata");
const support = @import("test_support.zig");

const fixture = @import("client_test_support.zig");

/// A client of the default capacity, and one with no QUIC, which the tests place outside any stack
/// frame (`client_test_support.zig`). Test-only.
const test_client = &fixture.default_client;
const tcp_client = &fixture.tcp_client;
/// The instant the tests pass as `unix_seconds`, inside the test identity's dates. Test-only.
const now_seconds = testdata.now_seconds;

/// A pool configuration over TLS that trusts the test identity's root for `localhost`. Test-only.
const anchors = [_]tls.Anchor{.{ .subject = testdata.root_name, .spki = testdata.root_spki }};
fn tls_pool(protocols: client.Protocols) client.Config {
    return .{
        .authority = "localhost",
        .protocols = protocols,
        .tls = .{ .trust = .{ .web_pki = .{ .anchors = &anchors, .server_name = "localhost" } }, .cpu = support.cpu() },
    };
}

test "design §8 step 42: a client over TLS opens a UDP socket of the host's family" {
    var counter: support.Counter = .{};
    try test_client.init(.{ .host = "::1", .pool = tls_pool(.{}), .random = counter.random(), .unix_seconds = now_seconds });
    defer test_client.deinit();
    try testing.expect(test_client.udp.open);
    const local = try rotor.sync.local_address(test_client.udp.descriptor);
    try testing.expectEqual(rotor.Address.Family.ipv6, local.family);
    try testing.expect(local.port != 0);
    // The pool connects to the host, on the port the configuration names.
    try testing.expectEqual(16, test_client.addresses[0].len);
    try testing.expectEqual(1, test_client.addresses[0].octets[15]);
    try testing.expectEqual(443, test_client.pool.values.port);
}

test "design §8 step 42: a cleartext client opens no UDP socket" {
    var counter: support.Counter = .{};
    try test_client.init(.{ .host = "127.0.0.1", .port = 8080, .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = now_seconds });
    defer test_client.deinit();
    // RFC 9001 §4: QUIC needs TLS, so a cleartext pool offers TCP alone.
    try testing.expect(!test_client.udp.open);
    try testing.expectEqual(4, test_client.addresses[0].len);
    try testing.expectEqual(127, test_client.addresses[0].octets[0]);
    try testing.expectEqual(8080, test_client.pool.values.port);
}

test "design §8 step 42: init takes the counts of the client's capacity" {
    var counter: support.Counter = .{};
    var config: client.Config = .{ .authority = "localhost", .tcp_connections = 3, .requests = 2 };
    config.protocols.h3 = false;
    try test_client.init(.{ .host = "127.0.0.1", .pool = config, .random = counter.random(), .unix_seconds = now_seconds });
    defer test_client.deinit();
    try testing.expectEqual(1, test_client.pool.counts.tcp_connections);
    try testing.expectEqual(client.constants.limits.requests_max, test_client.pool.counts.requests);
    // Decision 68: the client's loop reads and sets each codepoint, whatever the program set.
    try testing.expect(!config.ecn and test_client.pool_config.ecn);
}

test "decision 150 ruling 9: a client given no source draws from the system" {
    try test_client.init(.{ .host = "127.0.0.1", .pool = .{ .authority = "localhost" }, .unix_seconds = now_seconds });
    defer test_client.deinit();
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    test_client.config.random.?.bytes(&first);
    test_client.config.random.?.bytes(&second);
    // Two draws of thirty-two octets from the system differ.
    try testing.expect(!std.mem.eql(u8, &first, &second));
}

test "design §8 step 42: a host that is no IP literal is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.HostInvalid, test_client.init(.{ .host = "localhost", .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = now_seconds }));
}

test "decision 124: a client with no QUIC refuses h3" {
    var counter: support.Counter = .{};
    // RFC 9114 §3.1: h3 runs over QUIC alone.
    try testing.expectError(error.VersionUnavailable, tcp_client.init(.{ .host = "127.0.0.1", .pool = tls_pool(.{}), .random = counter.random(), .unix_seconds = now_seconds }));
    try tcp_client.init(.{ .host = "127.0.0.1", .pool = tls_pool(.{ .h3 = false }), .random = counter.random(), .unix_seconds = now_seconds });
    defer tcp_client.deinit();
    try testing.expect(!tcp_client.udp.open);
}

test {
    _ = @import("client_close_test.zig");
    _ = @import("client_tcp_test.zig");
    _ = @import("client_udp_test.zig");
}

test "design §8 step 42: a request leaves the pool's events for the next turn to read at once" {
    var counter: support.Counter = .{};
    try test_client.init(.{ .host = "127.0.0.1", .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = now_seconds });
    defer test_client.deinit();
    try testing.expect(!test_client.undrained);
    const request: client.Request = .{ .method = "GET", .path = "/" };
    var response: client.Response = .{};
    _ = try test_client.request(&request, &response);
    // A request from a handler would otherwise wait for the tick's longest wait.
    try testing.expect(test_client.undrained);
}

test "design §8 step 42: a turn passes a shutdown to the pool once, and steps each running socket" {
    var counter: support.Counter = .{};
    try test_client.init(.{ .host = "127.0.0.1", .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = now_seconds });
    defer test_client.deinit();
    test_client.connections = @splat(.empty);
    test_client.connections[0].started = true;
    test_client.pending = .initEmpty();
    test_client.shut_down = false;
    client_loop.pass_shutdown(test_client);
    // No shutdown was asked.
    try testing.expectEqual(0, test_client.pending.count());
    test_client.shutdown();
    client_loop.pass_shutdown(test_client);
    try testing.expect(test_client.pool.shut and test_client.pending.isSet(0));
    // A step of each running socket on each turn would leave the loop no wait until the run ends.
    test_client.pending = .initEmpty();
    client_loop.pass_shutdown(test_client);
    try testing.expectEqual(0, test_client.pending.count());
}

test "design §8 step 42: deinit closes the UDP socket" {
    var counter: support.Counter = .{};
    try test_client.init(.{ .host = "127.0.0.1", .pool = tls_pool(.{}), .random = counter.random(), .unix_seconds = now_seconds });
    const udp_socket = test_client.udp.descriptor;
    test_client.deinit();
    // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
    try testing.expectError(error.Unexpected, rotor.sync.local_address(udp_socket));
    try testing.expect(!test_client.udp.open);
}
