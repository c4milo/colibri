//! A client that runs a `client.ConnectionPool` (decision 153 ruling 8, design §8 step 42): h11
//! and h2 over TCP, and h3 over QUIC on a UDP socket. It is the counterpart of `colibri.Server`. It
//! owns the TCP sockets, the UDP socket, and the pool. Its driver (`client_loop.zig`) does no I/O
//! (decision 159). With `.private`, colibri's own Rotor host (`rotor_host.zig`) opens the sockets
//! and runs the loop and its clock. With `.hosted`, the program's host opened the UDP sockets
//! before `init`, and calls `turn` and `complete`. A program places one, hands it requests, and
//! keeps it in place while it runs.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const tls = @import("tls");
const socket_module = @import("socket.zig");
const operation_table = @import("operation_table.zig");
const client_tcp = @import("client_tcp.zig");
const client_loop = @import("client_loop.zig");
const errors = @import("errors.zig");
const host = @import("host.zig");
const erased = @import("erased.zig");
const kinds = @import("client_kinds.zig");
const client_fetch = @import("client_fetch.zig");

/// Where a `.private` client connects and how its pool runs. The program keeps each slice the
/// pool's configuration names alive while the client runs: the authority, the TLS anchors and
/// pins, and the decoder pools.
pub const ClientConfig = struct {
    /// The server's addresses, each with port 0, in the order the program wants them tried, and
    /// the origin's port: 443 for "https" unless the URI names another (RFC 9110 §4.2.2). The
    /// client looks up no name (decision 100). The program keeps `addresses` alive until the next
    /// `set_destination` or `deinit` (decision 156 ruling 11).
    destination: client.Destination,
    /// What the pool starts from: the authority, the protocols, the TLS value, the codings and the
    /// timeouts. `init` sets its `tcp_connections` and `requests` to the client's own counts, and
    /// sets its `ecn`, because the client's host reads and sets each datagram's ECN codepoint
    /// (decision 68). `timeouts.connect_ns` bounds each TCP connect.
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
/// connections, and the requests at once.
pub const ClientCapacity = struct {
    quic: bool = true,
    tcp_connections: u16 = 1,
    requests: u16 = client.constants.limits.requests_max,
};

/// A client whose pool holds `capacity`'s connections and requests, on colibri's own loop
/// (`.private`) or on the program's (`.hosted`). Each kind has the same calls. A call that the
/// kind does not have is a compile error with colibri's message (decision 156 ruling 4 as
/// amended). `.private` runs on Rotor, so a build with no Rotor refuses it the same way (decision
/// 159).
pub fn Client(comptime capacity: ClientCapacity, comptime kind: host.ObjectKind) type {
    comptime host.require_rotor(kind);
    return struct {
        const Self = @This();

        const Pool = client.ConnectionPool(.{ .quic = capacity.quic });
        const pool_memory_len = Pool.memory_bytes(.{ .tcp_connections = capacity.tcp_connections, .requests = capacity.requests });
        const ReceivePool = receive_pool_type(capacity.quic);
        const tcp_connections = capacity.tcp_connections;
        const Bits = std.bit_set.IntegerBitSet(tcp_connections);
        /// What each kind does: `client_kinds.zig`.
        const Kinded = @field(kinds, @tagName(kind));
        const Host = Kinded.Host(sockets_max, operations_max, capacity.quic);
        comptime {
            assert(capacity_valid(capacity));
        }

        /// What `init` returns: on `.private` the pool's refusals and the UDP socket's open, and on
        /// `.hosted` the pool's refusals alone (decision 159).
        pub const InitError = Kinded.InitError;
        /// What `run` returns on `.private`: the loop failed. A hosted client has no run, so the
        /// set is empty.
        pub const RunError = Kinded.RunError;
        /// What `fetch` takes and returns (decision 156 ruling 12).
        pub const FetchOptions = client_fetch.FetchOptions;
        pub const FetchResult = client_fetch.FetchResult;
        /// What `fetch` returns on `.private`: the loop failed, the pool refused the request, or
        /// the client was shut down. A hosted client has no fetch, so the set is empty.
        pub const FetchError = Kinded.FetchError;
        /// The most operations in flight, which a host sizes its table of operations by.
        pub const operations_max: u32 = client_loop.operations_max(tcp_connections, capacity.quic);
        /// The size of the host's table of sockets.
        pub const sockets_max: u16 = client_loop.sockets_max(tcp_connections);
        /// The UDP socket of each family, which a hosted client's host opened before `init`.
        pub const datagram_ipv4: host.SocketId = client_loop.datagram_id(tcp_connections, .ipv4);
        pub const datagram_ipv6: host.SocketId = client_loop.datagram_id(tcp_connections, .ipv6);

        random: tls.Random,
        unix_seconds: u64,
        /// The program's handler (`erased.zig`).
        handler: erased.Handler(Self),
        /// The pool, its configuration and its memory. The pool stays in place after `init`: its
        /// TLS configurations point into it.
        pool: Pool,
        pool_config: client.Config,
        pool_memory: [pool_memory_len]u8 align(Pool.memory_alignment),
        /// The pool each QUIC connection holds the server's unread octets in (decision 61).
        receive_pool: ReceivePool,
        /// The UDP socket of each family that the host opened, which the client has when the pool
        /// offers QUIC, and whether its host sends segments (decision 156 ruling 13).
        udp: client_loop.Datagrams,
        datagram_segments: bool,
        /// Each TCP slot's socket and what the client holds for it (`client_tcp.zig`), and the
        /// operations in flight.
        sockets: [tcp_connections]socket_module.Socket,
        connections: [tcp_connections]client_tcp.Connection,
        operations: operation_table.Table(client_loop.slot_count(tcp_connections, capacity.quic)),
        /// The sockets a completion named since their last step, and the sockets a turn changed.
        pending: Bits,
        touched: Bits,
        /// Whether a read of the pool's events stopped at its bound, or a call left events to
        /// read.
        undrained: bool,
        /// The instant of the run's first turn, which `unix_seconds` counts from, and whether it
        /// came.
        started_ns: u64,
        started: bool,
        /// `shutdown` asked, the turn passed it to the pool, and the pool reported `closed`.
        stopping: std.atomic.Value(bool),
        shut_down: bool,
        closed: bool,
        /// `run` was called since `init`.
        ran: bool,
        /// The loop of `.private` is made: a `fetch` or a `run` made it, and no `run` or `deinit`
        /// freed it since (`client_loop.begin`).
        begun: bool,
        /// The exchange that a `fetch` runs, whose `finished` the handler does not get, and
        /// whether it ended. Its request and its response stay here until it does
        /// (`client_fetch.zig`).
        fetching: ?client.RequestId,
        fetched: bool,
        fetch_request: client.Request,
        fetch_response: client.Response,
        /// The instant of the last `turn` or `complete`, which `cancel` passes to the pool.
        latest_ns: u64,
        /// A `turn` or a `complete` runs, and the handler with it (decision 159, rule 4).
        in_turn: bool,
        /// colibri's own Rotor host of `.private`: the loop and the descriptors
        /// (`rotor_host.zig`).
        host: Host,

        /// Keeps the handler, prepares the pool for the destination, and takes the UDP socket of
        /// each family when the pool offers QUIC: h3 allowed, a TLS value, and a client that holds
        /// QUIC (RFC 9114 §3.1). `handler` points at the program's struct, or is null for a client
        /// that only fetches. The struct declares `on_finished(handler, *Client,
        /// client.Finished)` and may declare `on_connected(handler, *Client, client.Connected)`.
        /// Each runs inside a turn, on the object's thread, and may call `request`, `cancel`,
        /// `set_destination` and `shutdown`.
        /// - `.private` opens the UDP socket.
        /// - `.hosted` does no I/O. Its host opened the UDP sockets.
        /// colibri keeps no pointer to `config` after `init` (decision 158 ruling 2).
        pub fn init(self: *Self, config: *const Kinded.Config, handler: anytype) InitError!void {
            self.handler = .of(handler);
            self.udp.close_all();
            self.ran = false;
            self.begun = false;
            self.fetching = null;
            self.fetched = false;
            self.latest_ns = 0;
            self.in_turn = false;
            // A run that fails before its first turn holds no live socket, and `stopped()` is
            // false until a run ends.
            client_loop.reset(self);
            self.unix_seconds = config.unix_seconds;
            self.pool_config = config.pool;
            self.pool_config.tcp_connections = capacity.tcp_connections;
            self.pool_config.requests = capacity.requests;
            self.stopping = .init(false);
            return Kinded.init(self, config);
        }

        /// Ends the client. The program calls it once after `init` returns, and after `run`
        /// returns when it calls `run`.
        /// - `.private` stops the loop that a `fetch` made and no `run` ended: it calls
        ///   `shutdown`, and runs the loop until each exchange has finished and each connection
        ///   has closed (decision 156 ruling 10). Then it closes each UDP socket that is open.
        /// - `.hosted`: the host calls it once `stopped()` holds (decision 159, rule 2).
        /// The client keeps no ticket and no private key, so it wipes nothing.
        pub fn deinit(self: *Self) void {
            Kinded.deinit(self);
        }

        /// Hands the pool a request and the response it fills, and returns the exchange's id. The
        /// program keeps both in place, and each slice they name, until the exchange's `finished`
        /// event (decision 124). It calls `request` on the object's thread: before `run` or from a
        /// handler on `.private`, and between turns or from a handler on `.hosted`. After
        /// `shutdown` it returns `ShutDown`. The request and its response have whole bodies:
        /// `message.streamed` asks for nothing.
        pub fn request(self: *Self, message: *const client.Request, response: *client.Response) (client.RequestError || error{ShutDown})!client.RequestId {
            // The client has no call that hands a piece or gives one back, so a streamed exchange
            // could never finish (design §8 step 42).
            assert(!message.streamed.request and !message.streamed.response);
            // The pool takes no request after its own shutdown, which the driver passes it at its
            // next turn (`ConnectionPool.request`).
            if (self.stopping.load(.acquire)) return error.ShutDown;
            const id = try self.pool.request(message, response);
            // The pool reports the open or the send the request needs at the next read.
            self.undrained = true;
            return id;
        }

        /// Runs one exchange on the thread that calls it, and returns how it ended (decision 156
        /// ruling 12).
        /// - The loop runs inside the call. The handler gets each other exchange that ends in
        ///   that time, and a handler never calls `fetch`.
        /// - The first `fetch` makes the loop, which stays made for the next `fetch` or `run`
        ///   until `deinit`. The program calls `fetch`, `run` and `deinit` on one thread.
        /// - `options` and each slice it names stay the program's. The slices of the result
        ///   point into the buffers that `options` names.
        /// - A protocol failure is the result's `result`, not an error. After `shutdown` the
        ///   call returns `ShutDown`.
        /// - When the loop fails, the exchange ends with no result, and the program calls
        ///   `deinit`.
        pub fn fetch(self: *Self, options: *const FetchOptions) FetchError!FetchResult {
            comptime host.require(kind, .private, "colibri: a .hosted object has no fetch(); call request() and read on_finished (decision 159)");
            host.refuse_inside(self.in_turn, "fetch()");
            return client_fetch.fetch(self, options);
        }

        /// Ends exchange `id`, which `request` returned, and the handler gets no `finished` for
        /// it (decision 156 ruling 12). The memory of its request and its response is the
        /// program's again when the call returns (decision 124). An id of an exchange that has
        /// ended changes nothing. The program calls `cancel` on the object's thread, as it calls
        /// `request`. A hosted client's host calls `turn` after it: a connection may owe octets
        /// for the end, such as h2's RST_STREAM (RFC 9113 §8.1). The pool counts an h11 drop's
        /// time from the instant of the last `turn` or `complete` (decision 146 ruling 3).
        pub fn cancel(self: *Self, id: client.RequestId) void {
            // `fetch` returns no id, and its exchange ends when `fetch` returns.
            assert(self.fetching == null or self.fetching.? != id);
            // Each turn reads the pool's events first, so `undrained` stays as it is.
            self.pool.cancel(id, self.latest_ns);
        }

        /// Gives the pool new addresses, for example from a later DNS answer, while exchanges run
        /// (decision 156 ruling 11). Each connection that opens after the call goes to
        /// `destination.addresses`, from the first, and each open connection keeps its exchanges
        /// (decision 125). The port stays the origin's (RFC 9110 §4.3.1). The program keeps the
        /// addresses alive until the next `set_destination` or `deinit`. It calls
        /// `set_destination` on the object's thread, as it calls `request`. An open of QUIC to a
        /// family with no UDP socket ends, and the pool opens TCP (decision 156 ruling 13).
        pub fn set_destination(self: *Self, destination: client.Destination) void {
            // The pool reports no event for the call, and each turn reads the pool's events
            // first, so `undrained` stays as it is.
            self.pool.set_destination(destination);
        }

        /// Runs the pool on the thread that calls it until `shutdown`, and returns once each
        /// exchange has finished and each connection has closed. The handler that `init` took
        /// runs on this thread. The loop runs here because a Rotor loop belongs to the thread
        /// that starts it (decision 150 ruling 7). A program calls `run` once for each `init`.
        pub fn run(self: *Self) RunError!void {
            comptime host.require(kind, .private, "colibri: a .hosted object has no run(); its host calls turn() and complete() (decision 159)");
            host.refuse_inside(self.in_turn, "run()");
            return client_loop.run_loop(self);
        }

        /// Does the work of one turn at `now_ns`, and writes up to `operations.len` operations,
        /// which the host does (decision 159). The handler runs inside it. The host calls it again
        /// at the instant that the returned `Wait` names, after a completion, and after a
        /// program's call.
        pub fn turn(self: *Self, now_ns: u64, operations: []host.Operation) host.Turn {
            comptime host.require(kind, .hosted, "colibri: a .private object has no turn(); run() calls it on colibri's own loop (decision 159)");
            return client_loop.turn(self, now_ns, operations);
        }

        /// Records one completion at `now_ns`. It feeds a datagram to the pool at once, because
        /// the host lends the bytes for the call alone. A completion of an operation that the
        /// client does not hold is a halt (decision 159, rule 6).
        pub fn complete(self: *Self, completion: *const host.Completion, now_ns: u64) void {
            comptime host.require(kind, .hosted, "colibri: a .private object has no complete(); run() calls it on colibri's own loop (decision 159)");
            client_loop.complete(self, completion, now_ns);
        }

        /// Asks the client to stop: `request` returns `ShutDown` from now on, and `stopped()` holds
        /// and `run` returns once each exchange has finished and each connection has closed. On
        /// `.private` any thread may call it. A hosted client's host calls `turn` after it.
        pub fn shutdown(self: *Self) void {
            self.stopping.store(true, .release);
        }

        /// Whether the client stopped: the pool closed after `shutdown`, each TCP socket is free,
        /// and each operation had its final completion (decision 159, rule 1).
        pub fn stopped(self: *const Self) bool {
            return client_loop.finished(self);
        }
    };
}

/// The type of the receive pool a client holds: the default one with QUIC, and none without.
fn receive_pool_type(quic: bool) type {
    return if (quic) client.ReceivePool(.{}) else void;
}

/// Whether each count of `capacity` is inside the pool's limits. The host checks that its loop
/// holds every operation the client has in flight.
fn capacity_valid(capacity: ClientCapacity) bool {
    if (capacity.tcp_connections == 0 or capacity.tcp_connections > client.constants.limits.pool_tcp_connections_max) return false;
    return capacity.requests > 0 and capacity.requests <= client.constants.limits.pool_requests_max;
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

test "design §8 step 42: a cleartext client opens no UDP socket" {
    var counter: support.Counter = .{};
    try test_client.init(&.{ .destination = fixture.loopback(8080), .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = now_seconds }, null);
    defer test_client.deinit();
    // RFC 9001 §4: QUIC needs TLS, so a cleartext pool offers TCP alone.
    try testing.expect(!test_client.udp.served);
    try testing.expectEqual(4, test_client.pool.values.addresses[0].len);
    try testing.expectEqual(127, test_client.pool.values.addresses[0].octets[0]);
    try testing.expectEqual(8080, test_client.pool.values.port);
}

test "design §8 step 42: init takes the counts of the client's capacity" {
    var counter: support.Counter = .{};
    var config: client.Config = .{ .authority = "localhost", .tcp_connections = 3, .requests = 2 };
    config.protocols.h3 = false;
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = config, .random = counter.random(), .unix_seconds = now_seconds }, null);
    defer test_client.deinit();
    try testing.expectEqual(1, test_client.pool.counts.tcp_connections);
    try testing.expectEqual(client.constants.limits.requests_max, test_client.pool.counts.requests);
    // Decision 68: the client's loop reads and sets each codepoint, whatever the program set.
    try testing.expect(!config.ecn and test_client.pool_config.ecn);
}

test "decision 150 ruling 9: a client given no source draws from the system" {
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = .{ .authority = "localhost" }, .unix_seconds = now_seconds }, null);
    defer test_client.deinit();
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    test_client.random.bytes(&first);
    test_client.random.bytes(&second);
    // Two draws of thirty-two octets from the system differ.
    try testing.expect(!std.mem.eql(u8, &first, &second));
}

test "decision 124: a client with no QUIC refuses h3" {
    var counter: support.Counter = .{};
    // RFC 9114 §3.1: h3 runs over QUIC alone.
    try testing.expectError(error.VersionUnavailable, tcp_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = tls_pool(.{}), .random = counter.random(), .unix_seconds = now_seconds }, null));
    try tcp_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = tls_pool(.{ .h3 = false }), .random = counter.random(), .unix_seconds = now_seconds }, null);
    defer tcp_client.deinit();
    try testing.expect(!tcp_client.udp.served);
}

test {
    _ = @import("rotor_host_client_test.zig");
    _ = @import("client_tcp_test.zig");
    _ = @import("client_fetch_test.zig");
    _ = @import("client_udp_test.zig");
}

test "design §8 step 42: a request leaves the pool's events for the next turn to read at once" {
    var counter: support.Counter = .{};
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = now_seconds }, null);
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
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = .{ .authority = "localhost" }, .random = counter.random(), .unix_seconds = now_seconds }, null);
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
