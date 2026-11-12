//! A server that runs `server.Engine` (decision 150): h11 and h2 over TCP, and h3 over QUIC on a
//! UDP socket. A program places one, as it places an engine, and keeps it in place while it runs.
//! Its driver (`server_loop.zig`) does no I/O (decision 159). With `.private`, colibri's own Rotor
//! host (`rotor_host.zig`) binds one port for TCP and UDP and runs the loop. With `.hosted`, the
//! program's host opened the sockets before `init`, and calls `turn` and `complete`.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const tls = @import("tls");
const identity_module = @import("identity.zig");
const socket_module = @import("socket.zig");
const pump = @import("server_pump.zig");
const server_loop = @import("server_loop.zig");
const server_udp = @import("server_udp.zig");
const operation_table = @import("operation_table.zig");
const errors = @import("errors.zig");
const host = @import("host.zig");
const erased = @import("erased.zig");
const kinds = @import("server_kinds.zig");

const Identity = identity_module.Identity;

/// What a `.private` server binds and how it answers. The program keeps the PEM text of `identity`
/// alive until `init` returns.
pub const ServerConfig = struct {
    /// The address bound: an IPv4 or IPv6 literal.
    host: []const u8 = "127.0.0.1",
    /// The port bound for TCP and UDP. 0 asks the operating system for one, which `port()` returns.
    /// When another program holds UDP on the number it gives, `init` asks again, up to
    /// `bind_tries_max` times (decision 150).
    port: u16 = 0,
    /// The server's certificate chain and key. Null serves h11 and h2 in cleartext, and no h3,
    /// which needs TLS (RFC 9001 §4).
    identity: ?Identity = null,
    /// The program's CPU and its thread's timing, which every TLS session runs on (decision 97).
    cpu: tls.Cpu,
    /// The seconds since 1970 when `run` starts, which the program reads from its clock: the
    /// server's session tickets carry it (decision 161). It has no default, because no instant is
    /// right to assume.
    unix_seconds: u64,
    /// The source each TLS session and each QUIC connection draws from. Null draws from the
    /// operating system's entropy (decision 150 ruling 9).
    random: ?tls.Random = null,
    /// The key the server seals its session tickets under, which it copies, or null to draw one
    /// from `random` (decision 161). A program that runs several servers passes each the same
    /// key, so each resumes the tickets of the others. The server wipes its copy at `deinit`.
    ticket_key: ?[tls.constants.protocol.server_key_len]u8 = null,
    /// The key the server sealed its tickets under before `ticket_key`, which it copies, or null
    /// to draw one that opens no ticket. A ticket that either key sealed resumes, so a program
    /// that starts again with a new key keeps its clients' tickets (decision 161 as amended). It
    /// differs from `ticket_key`, or the engine does not start: `run`, or a hosted `init`, returns
    /// `error.IdentityRefused`.
    ticket_key_previous: ?[tls.constants.protocol.server_key_len]u8 = null,
    /// What the engine starts from. `colibri` fills its `tls` from `identity`, and sets its `ecn`:
    /// the server's host reads each datagram's ECN codepoint and sets the one the engine names
    /// (decision 68). Decision 158 ruling 16 names the field after the engine.
    engine: server.Config = .{},
};

pub const InitError = identity_module.LoadError || errors.BindError;

pub const RunError = errors.RunError;

/// A server whose engine holds `capacity`'s connections, on colibri's own loop (`.private`) or on
/// the program's (`.hosted`). Each kind has the same calls. A call that the kind does not have is
/// a compile error with colibri's message (decision 156 ruling 4 as amended). `.private` runs on
/// Rotor, so a build with no Rotor refuses it the same way (decision 159).
pub fn Server(comptime capacity: server.Capacity, comptime kind: host.ObjectKind) type {
    comptime host.require_rotor(kind);
    return struct {
        const Self = @This();

        const tcp_connections = capacity.tcp_connections;
        const Bits = std.bit_set.IntegerBitSet(tcp_connections);
        const Engine = server.Engine(capacity);
        /// What each kind does: `server_kinds.zig`.
        const Kinded = @field(kinds, @tagName(kind));
        const Host = Kinded.Host(sockets_max, operations_max, capacity.quic_connections > 0);
        comptime {
            assert(tcp_connections > 0);
        }

        /// What `init` returns: on `.private` the identity's PEM text refused or the bind
        /// refused, and on `.hosted` the identity's PEM text refused or the engine's start
        /// refused (decision 159 as amended on 2026-11-10).
        pub const InitError = Kinded.InitError;
        /// The most operations in flight, which a host sizes its table of operations by.
        pub const operations_max: u32 = server_loop.operations_max(tcp_connections);
        /// The size of the host's table of sockets.
        pub const sockets_max: u16 = server_loop.sockets_max(tcp_connections);
        /// The TCP listener and the UDP socket that a hosted server's host opened before `init`.
        pub const listener: host.SocketId = server_loop.listener_id(tcp_connections);
        pub const datagram: host.SocketId = server_loop.datagram_id(tcp_connections);

        random: tls.Random,
        /// The Unix seconds the engine starts at, which its tickets carry (decision 161).
        unix_seconds: u64,
        identity: identity_module.Storage,
        engine_config: server.Config,
        /// The engine, the program's router, and the server's entry for each socket's
        /// connection (`server_pump.zig`).
        engine: Engine,
        router: erased.Router(Engine),
        entries: [tcp_connections]pump.Entry,
        entry_of: [tcp_connections]?u32,
        /// The TCP sockets, the UDP socket and the operations in flight (`server_loop.zig`).
        sockets: [tcp_connections]socket_module.Socket,
        /// The UDP socket, which the server has when it has an identity and QUIC slots (design
        /// §8 step 37c), and a hosted server when its host opened it.
        udp: server_loop.Datagrams,
        operations: operation_table.Table(server_loop.slot_count(tcp_connections)),
        /// Whether the server accepts on its listener, and whether its host sends segments.
        listening: bool,
        datagram_segments: bool,
        /// The one accept: whether it is in flight, whether its cancel was written, and the
        /// socket it takes.
        accepting: bool,
        accept_canceled: bool,
        accept_into: u32,
        /// The entries a completion named since their last step, and the sockets a turn changed.
        pending: Bits,
        touched: Bits,
        /// Whether a read of the engine's events stopped at its bound.
        undrained: bool,
        /// The instant of the last `turn` or `complete`, which each call into the engine passes.
        /// The next call may not go before it, nor the first before the run's start (decision
        /// 159, rule 6).
        now_ns: u64,
        /// `shutdown` asked, the turn passed it to the engine, and the engine reported
        /// `closed`.
        stopping: std.atomic.Value(bool),
        shut_down: bool,
        over: bool,
        /// A `turn` or a `complete` runs, and the router with it (decision 159, rule 4).
        in_turn: bool,
        /// colibri's own Rotor host of `.private`: the loop and the descriptors
        /// (`rotor_host.zig`).
        host: Host,

        /// Keeps the router, a pointer to the program's `server.Router`, and `context`, which
        /// each route's function takes, and reads the identity.
        /// - `.private` binds the listener and the UDP socket, so `port()` holds the port bound
        ///   once `init` returns. The server runs on Rotor's own loop (decision 150 ruling 10).
        /// - `.hosted` starts the engine, and does no I/O. Its host opened the sockets.
        /// colibri keeps no pointer to `config` after `init` (decision 158 ruling 2).
        pub fn init(self: *Self, config: *const Kinded.Config, router: anytype, context: anytype) Kinded.InitError!void {
            self.router = .of(router, context);
            self.udp.close_all();
            // A run that fails before `start` holds no live socket, and `stopped()` is false
            // until a run ends.
            server_loop.reset(self, 0);
            self.engine_config = config.engine;
            assert(self.engine_config.tls == null);
            self.stopping = .init(false);
            self.in_turn = false;
            return Kinded.init(self, config, capacity.quic_connections > 0);
        }

        /// Closes the listener and the UDP socket of `.private`, and wipes the private key, the
        /// cookie key and both ticket keys. The program calls it after `init` returns, and after `run` returns when it
        /// calls `run`. It does not close a socket that `run` closed: the system can give that
        /// number to another file of the program. A hosted server's host calls it once
        /// `stopped()` holds (decision 159, rule 2).
        pub fn deinit(self: *Self) void {
            Kinded.deinit(self);
            wipe_keys(self);
        }

        /// The port the server bound: the configured one, or the one the system chose for 0.
        pub fn port(self: *const Self) u16 {
            comptime host.require(kind, .private, "colibri: a .hosted Server has no port(); its host bound the sockets (decision 159)");
            assert(self.host.bound_port != 0);
            return self.host.bound_port;
        }

        /// Serves on the thread that calls it until `shutdown`: each request goes to the router
        /// that `init` took (decision 150). The loop runs here because a Rotor loop belongs to the
        /// thread that starts it.
        pub fn run(self: *Self) RunError!void {
            comptime host.require(kind, .private, "colibri: a .hosted object has no run(); its host calls turn() and complete() (decision 159)");
            host.refuse_inside(self.in_turn, "run()");
            assert(self.host.open(listener));
            defer self.host.close_open();
            const now_ns = try self.host.begin();
            defer self.host.end();
            // The first tick read the clock, so this instant pairs with the Unix seconds the program
            // read when the run started (decision 161).
            assert(now_ns > 0);
            try server_loop.start(self, .{ .unix_seconds = self.unix_seconds, .monotonic_ns = now_ns });
            try self.host.run(self, server_loop, self);
        }

        /// Does the work of one turn at `now_ns`, and writes up to `operations.len` operations,
        /// which the host does (decision 159). The host calls it again at the instant that the
        /// returned `Wait` names, after a completion, and after a program's call.
        pub fn turn(self: *Self, now_ns: u64, operations: []host.Operation) host.Turn {
            comptime host.require(kind, .hosted, "colibri: a .private object has no turn(); run() calls it on colibri's own loop (decision 159)");
            return server_loop.turn(self, now_ns, operations);
        }

        /// Records one completion at `now_ns`. It feeds a datagram to the engine at once, because
        /// the host lends the bytes for the call alone. A completion of an operation that the
        /// server does not hold is a halt (decision 159, rule 6).
        pub fn complete(self: *Self, completion: *const host.Completion, now_ns: u64) void {
            comptime host.require(kind, .hosted, "colibri: a .private object has no complete(); run() calls it on colibri's own loop (decision 159)");
            server_loop.complete(self, completion, now_ns);
        }

        /// Seals the server's next session tickets under `key`, which it copies. The current key
        /// becomes the previous one, which still opens the tickets it sealed, and the key before
        /// it is gone (decision 161 as amended, https://github.com/c4milo/chapulin/issues/220).
        /// The same key again changes nothing. A server with no identity issues no ticket, and
        /// the call does nothing. The program calls it on the server's thread, because each TLS
        /// session reads the keys while it runs: on `.hosted` between two calls, and on
        /// `.private` from a route or a middleware.
        pub fn set_ticket_key(self: *Self, key: *const [tls.constants.protocol.server_key_len]u8) void {
            if (self.engine_config.tls == null) return;
            identity_module.change_ticket_key(&self.identity, key);
        }

        /// Asks the server to stop: it takes no new connection, ends each one it holds, and
        /// `stopped()` then holds, and `run` returns. On `.private` any thread may call it. A
        /// hosted server's host calls `turn` after it.
        pub fn shutdown(self: *Self) void {
            self.stopping.store(true, .release);
        }

        /// Whether the server stopped: the engine ended each connection after `shutdown`, each
        /// socket is free, and each operation had its final completion (decision 159, rule 1).
        pub fn stopped(self: *const Self) bool {
            return server_loop.finished(self);
        }
    };
}

/// Writes zero over a server's private key, its cookie key and its two ticket keys.
pub fn wipe_keys(state: anytype) void {
    state.identity.key.wipe();
    std.crypto.secureZero(u8, &state.identity.cookie_key);
    std.crypto.secureZero(u8, &state.identity.ticket_key);
    std.crypto.secureZero(u8, &state.identity.ticket_key_previous);
}

const testing = std.testing;
const testdata = @import("testdata");
const support = @import("test_support.zig");

/// A server the tests place, outside any stack frame, and its router. Test-only.
const fixture = @import("server_test_support.zig");
const test_server = &fixture.test_server;

test "decision 150: init reads a PEM identity into the engine's TLS values" {
    var counter: support.Counter = .{};
    try test_server.init(&.{
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .unix_seconds = testdata.now_seconds,
        .random = counter.random(),
    }, &fixture.router, &fixture.context);
    const values = test_server.engine_config.tls.?;
    try testing.expectEqual(1, values.identities.len);
    try testing.expectEqual(.ecdsa_secp256r1_sha256, values.identities[0].key.scheme);
    try testing.expectEqualSlices(u8, testdata.leaf, values.identities[0].chain[0]);
    // RFC 9846 §4.3.2: the cookie key comes from the program's source.
    try testing.expectEqual(0, values.cookie_key[0]);
    try testing.expectEqual(1, values.cookie_key[1]);
    test_server.deinit();
}

test "decision 161: the TLS values hold the server's copy of a ticket key, or one drawn after the cookie key" {
    var counter: support.Counter = .{};
    const identity: Identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    try test_server.init(&.{ .identity = identity, .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random() }, &fixture.router, &fixture.context);
    // The counter gives the cookie key 0 to 31, and then the ticket key 32 to 63.
    const key_len = tls.constants.protocol.server_key_len;
    try testing.expectEqual(key_len, test_server.engine_config.tls.?.ticket_key.?[0]);
    test_server.deinit();
    const given: [key_len]u8 = @splat(0xa5);
    try test_server.init(&.{ .identity = identity, .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random(), .ticket_key = given }, &fixture.router, &fixture.context);
    const values = test_server.engine_config.tls.?;
    try testing.expect(values.ticket_key.? == &test_server.identity.ticket_key);
    try testing.expectEqualSlices(u8, &given, values.ticket_key.?);
    test_server.deinit();
    // `deinit` wipes the server's copy, and the program's key is the program's to wipe.
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.ticket_key, 0));
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.ticket_key_previous, 0));
}

test "chapulin's issue 220: set_ticket_key writes the new key where each session reads it" {
    var counter: support.Counter = .{};
    const key_len = tls.constants.protocol.server_key_len;
    const first: [key_len]u8 = @splat(0x11);
    const before: [key_len]u8 = @splat(0x22);
    const identity: Identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    try test_server.init(&.{ .identity = identity, .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random(), .ticket_key = first, .ticket_key_previous = before }, &fixture.router, &fixture.context);
    const values = test_server.engine_config.tls.?;
    try testing.expectEqualSlices(u8, &before, values.ticket_key_previous.?);
    const next: [key_len]u8 = @splat(0x33);
    test_server.set_ticket_key(&next);
    // The pointers that the TLS values hold now read the new key and the key before it.
    try testing.expectEqualSlices(u8, &next, values.ticket_key.?);
    try testing.expectEqualSlices(u8, &first, values.ticket_key_previous.?);
    test_server.deinit();
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.ticket_key_previous, 0));
}

test "chapulin's issue 220: two equal ticket keys stop the engine, and a cleartext server ignores a key" {
    var counter: support.Counter = .{};
    const given: [tls.constants.protocol.server_key_len]u8 = @splat(0x44);
    const hosted = &fixture.hosted_server;
    try testing.expectError(error.IdentityRefused, hosted.init(&.{
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .random = counter.random(),
        .now = .{ .unix_seconds = testdata.now_seconds, .monotonic_ns = 0 },
        .ticket_key = given,
        .ticket_key_previous = given,
        .sockets = .{ .listener = false },
    }, &fixture.router, &fixture.context));
    try testing.expect(std.mem.allEqual(u8, &hosted.identity.ticket_key_previous, 0));
    try test_server.init(&.{ .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random() }, &fixture.router, &fixture.context);
    test_server.set_ticket_key(&given);
    try testing.expectEqual(null, test_server.engine_config.tls);
    test_server.deinit();
}

test "decision 161: a hosted server takes its ticket key and its tickets' Unix seconds from its configuration" {
    var counter: support.Counter = .{};
    const given: [tls.constants.protocol.server_key_len]u8 = @splat(0x5a);
    const hosted = &fixture.hosted_server;
    try hosted.init(&.{
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .random = counter.random(),
        .now = .{ .unix_seconds = testdata.now_seconds, .monotonic_ns = 0 },
        .ticket_key = given,
        .sockets = .{ .listener = false },
    }, &fixture.router, &fixture.context);
    // The server never runs, so the test wipes the keys that `deinit` wipes once it stopped.
    defer wipe_keys(hosted);
    try testing.expectEqualSlices(u8, &given, hosted.engine_config.tls.?.ticket_key.?);
    try testing.expectEqual(testdata.now_seconds, hosted.engine.state.connections.base_seconds);
}

test "decision 150 ruling 9: a server given no source draws from the system" {
    try test_server.init(&.{ .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem }, .cpu = support.cpu(), .unix_seconds = testdata.now_seconds }, &fixture.router, &fixture.context);
    const values = test_server.engine_config.tls.?;
    // Thirty-two octets from the system are not the counter's 0, 1, 2, ...
    try testing.expect(!(values.cookie_key[0] == 0 and values.cookie_key[1] == 1 and values.cookie_key[2] == 2));
    test_server.deinit();
}

test "decision 150: no identity serves cleartext" {
    var counter: support.Counter = .{};
    try test_server.init(&.{ .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random() }, &fixture.router, &fixture.context);
    try testing.expectEqual(null, test_server.engine_config.tls);
    // RFC 9001 §4: QUIC needs TLS, so a cleartext server opens no UDP socket.
    try testing.expect(!test_server.udp.served);
    try testing.expectEqual(null, test_server.engine_config.h3_alternative);
    test_server.deinit();
}

test "decision 159 as amended: each kind of Server names the errors of its init" {
    // A hosted server binds nothing, and starts its engine in `init`.
    const Hosted = Server(.{}, .hosted);
    try testing.expect(Hosted.InitError == (identity_module.LoadError || server.StartError));
    try testing.expect(Server(.{}, .private).InitError == InitError);
}

test "decision 150: a host that is no IP literal is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.HostInvalid, test_server.init(&.{ .host = "localhost", .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random() }, &fixture.router, &fixture.context));
}

test "decision 150: an init that fails after it reads the key wipes the key and the cookie key" {
    var counter: support.Counter = .{};
    const identity: Identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    // The bind refuses the host after `load` has read the key and drawn the cookie key.
    try testing.expectError(error.HostInvalid, test_server.init(&.{ .host = "localhost", .identity = identity, .cpu = support.cpu(), .unix_seconds = testdata.now_seconds, .random = counter.random() }, &fixture.router, &fixture.context));
    try testing.expect(counter.next != 0);
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.key.private_key, 0));
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.cookie_key, 0));
}

test {
    _ = @import("server_tcp_test.zig");
    _ = @import("rotor_host_server_test.zig");
    _ = @import("server_udp_test.zig");
    _ = @import("server_stream_test.zig");
    _ = @import("fake_host_test.zig");
    _ = @import("server_half_close_test.zig");
    _ = @import("fake_host_pair_test.zig");
}
