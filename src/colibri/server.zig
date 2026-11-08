//! A server that binds one port and runs `server.Engine` (decision 150): h11 and h2 over TCP, and
//! h3 over QUIC on the UDP socket of the same port. A program places one, as it places an engine,
//! and keeps it in place while it runs. Its driver (`server_loop.zig`) does no I/O, and colibri's
//! own Rotor host (`rotor_host.zig`) binds and runs the loop (decision 159).
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const tls = @import("tls");
const identity_module = @import("identity.zig");
const socket_module = @import("socket.zig");
const pump = @import("server_pump.zig");
const server_loop = @import("server_loop.zig");
const server_udp = @import("server_udp.zig");
const datagram_socket = @import("datagram_socket.zig");
const operation_table = @import("operation_table.zig");
const errors = @import("errors.zig");
const rotor_host = @import("rotor_host.zig");
const entropy = @import("rotor_host_entropy.zig");

const Identity = identity_module.Identity;

/// What a server binds and how it answers. The program keeps the PEM text of `identity` alive
/// until `init` returns.
pub const ServerConfig = struct {
    /// The address bound: an IPv4 or IPv6 literal.
    host: []const u8 = "127.0.0.1",
    /// The port bound for TCP and UDP. 0 asks the operating system for one, which `port()` returns.
    port: u16 = 0,
    /// The server's certificate chain and key. Null serves h11 and h2 in cleartext, and no h3,
    /// which needs TLS (RFC 9001 §4).
    identity: ?Identity = null,
    /// The program's CPU and its thread's timing, which every TLS session runs on (decision 97).
    cpu: tls.Cpu,
    /// The source each TLS session and each QUIC connection draws from. Null draws from the
    /// operating system's entropy (decision 150 ruling 9).
    random: ?tls.Random = null,
    /// What the engine starts from. `colibri` fills its `tls` from `identity`, and sets its `ecn`:
    /// the server's host reads each datagram's ECN codepoint and sets the one the engine names
    /// (decision 68).
    endpoint: server.Config = .{},
};

pub const InitError = identity_module.LoadError || errors.BindError;

pub const RunError = errors.RunError;

/// A server of the default capacity.
pub const Server = ServerOf(.{});

/// A server whose engine holds `capacity`'s connections.
pub fn ServerOf(comptime capacity: server.Capacity) type {
    return struct {
        const Self = @This();

        const tcp_connections = capacity.tcp_connections;
        const Bits = std.bit_set.IntegerBitSet(tcp_connections);
        /// colibri's own Rotor host holds each operation of the driver, and the shutdown of each
        /// socket's write side for a staged close, which the host contract has no operation for
        /// (decision 160).
        const Host = rotor_host.Host(server_loop.sockets_max(tcp_connections), server_loop.operations_max(tcp_connections) + tcp_connections, capacity.quic_connections > 0);
        comptime {
            assert(tcp_connections > 0);
        }

        config: ServerConfig,
        identity: identity_module.Storage,
        engine_config: server.Config,
        /// The engine, and the server's entry for each socket's connection
        /// (`server_pump.zig`).
        engine: server.Engine(capacity),
        entries: [tcp_connections]pump.Entry,
        entry_of: [tcp_connections]?u32,
        /// The TCP sockets, the UDP socket and the operations in flight (`server_loop.zig`).
        sockets: [tcp_connections]socket_module.Socket,
        /// The UDP socket, which the server has when it has an identity and QUIC slots (design
        /// §8 step 37c).
        udp: datagram_socket.DatagramSocket,
        operations: operation_table.Table(server_loop.slot_count(tcp_connections)),
        /// The one accept: whether it is in flight, whether its cancel was written, and the
        /// socket it takes.
        accepting: bool,
        accept_canceled: bool,
        accept_into: u32,
        /// The entries a completion named since their last step, the sockets a turn changed, and
        /// the sockets whose write side closes now (`server_loop.take_half_close`).
        pending: Bits,
        touched: Bits,
        half_closes: Bits,
        /// Whether a read of the engine's events stopped at its bound.
        undrained: bool,
        /// The instant of the last call into the engine.
        now_ns: u64,
        /// `shutdown` asked, the turn passed it to the engine, and the engine reported
        /// `closed`.
        stopping: std.atomic.Value(bool),
        shut_down: bool,
        over: bool,
        /// colibri's own Rotor host: the loop and the descriptors (`rotor_host.zig`).
        host: Host,

        /// Reads the identity, keeps the configuration and binds the listener, so `port()` holds
        /// the port bound once `init` returns. The server runs on Rotor's own loop (decision 150
        /// ruling 10).
        pub fn init(self: *Self, config: ServerConfig) InitError!void {
            self.config = config;
            self.host.prepare();
            self.udp.served = false;
            // A run that fails before `start` holds no live socket.
            for (&self.sockets) |*socket| socket.live = false;
            if (self.config.random == null) self.config.random = entropy.random();
            self.engine_config = config.endpoint;
            // Decision 68: the server's own host reads each datagram's codepoint and sets the one
            // the engine names, so the engine reads ECN whatever the program set.
            self.engine_config.ecn = true;
            assert(self.engine_config.tls == null);
            // A server that `init` does not return keeps no private key and no cookie key.
            errdefer wipe_keys(self);
            if (config.identity) |identity| {
                self.engine_config.tls = try identity_module.load(identity, &self.identity, config.cpu, self.config.random.?);
            }
            assert((self.engine_config.tls != null) == (config.identity != null));
            try self.host.listen(server_loop.listener_id(tcp_connections), config.host, config.port);
            errdefer self.host.close_open();
            if (server_udp.served(self, capacity.quic_connections > 0)) {
                try self.host.bind_datagram(server_loop.datagram_id(tcp_connections), config.host, self.host.bound_port);
                server_udp.opened(self, self.host.bound_port);
            }
            self.stopping = .init(false);
        }

        /// Closes the listener and the UDP socket, and wipes the private key and the cookie key.
        /// The program calls it after `init` returns, and after `run` returns when it calls `run`.
        /// It does not close a socket that `run` closed: the system can give that number to
        /// another file of the program.
        pub fn deinit(self: *Self) void {
            // `init` sets the source on each path, before any step that can fail.
            assert(self.config.random != null);
            self.host.close_open();
            wipe_keys(self);
        }

        /// The port the server bound: the configured one, or the one the system chose for 0.
        pub fn port(self: *const Self) u16 {
            assert(self.host.bound_port != 0);
            return self.host.bound_port;
        }

        /// Asks a running server to stop: it takes no new connection, ends each one it holds, and
        /// `run` returns. Any thread may call it.
        pub fn shutdown(self: *Self) void {
            self.stopping.store(true, .release);
        }

        /// Serves on the thread that calls it until `shutdown`: each request goes to `router`, a
        /// pool of `server.Router`'s, with `context` (decision 150). The loop runs here because a
        /// Rotor loop belongs to the thread that starts it.
        pub fn run(self: *Self, router: anytype, context: anytype) RunError!void {
            assert(self.host.open(server_loop.listener_id(tcp_connections)));
            defer self.host.close_open();
            const now_ns = try self.host.begin();
            defer self.host.end();
            try server_loop.start(self, now_ns);
            const Run = struct { server: *Self, router: @TypeOf(router), context: @TypeOf(context) };
            var running: Run = .{ .server = self, .router = router, .context = context };
            try self.host.run(&running, server_loop, self);
        }
    };
}

/// Writes zero over a server's private key and its cookie key.
fn wipe_keys(state: anytype) void {
    state.identity.key.wipe();
    std.crypto.secureZero(u8, &state.identity.cookie_key);
}

const testing = std.testing;
const testdata = @import("testdata");
const support = @import("test_support.zig");

/// A server the tests place, outside any stack frame. Test-only.
const test_server = &@import("server_test_support.zig").test_server;

test "decision 150: init reads a PEM identity into the engine's TLS values" {
    var counter: support.Counter = .{};
    try test_server.init(.{
        .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem },
        .cpu = support.cpu(),
        .random = counter.random(),
    });
    const values = test_server.engine_config.tls.?;
    try testing.expectEqual(1, values.identities.len);
    try testing.expectEqual(.ecdsa_secp256r1_sha256, values.identities[0].key.scheme);
    try testing.expectEqualSlices(u8, testdata.leaf, values.identities[0].chain[0]);
    // RFC 9846 §4.3.2: the cookie key comes from the program's source.
    try testing.expectEqual(0, values.cookie_key[0]);
    try testing.expectEqual(1, values.cookie_key[1]);
    test_server.deinit();
}

test "decision 150 ruling 9: a server given no source draws from the system" {
    try test_server.init(.{ .identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem }, .cpu = support.cpu() });
    try testing.expect(test_server.config.random != null);
    const values = test_server.engine_config.tls.?;
    // Thirty-two octets from the system are not the counter's 0, 1, 2, ...
    try testing.expect(!(values.cookie_key[0] == 0 and values.cookie_key[1] == 1 and values.cookie_key[2] == 2));
    test_server.deinit();
}

test "decision 150: no identity serves cleartext" {
    var counter: support.Counter = .{};
    try test_server.init(.{ .cpu = support.cpu(), .random = counter.random() });
    try testing.expectEqual(null, test_server.engine_config.tls);
    // RFC 9001 §4: QUIC needs TLS, so a cleartext server opens no UDP socket.
    try testing.expect(!test_server.udp.served);
    try testing.expectEqual(null, test_server.engine_config.h3_alternative);
    test_server.deinit();
}

test "decision 150: a host that is no IP literal is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.HostInvalid, test_server.init(.{ .host = "localhost", .cpu = support.cpu(), .random = counter.random() }));
}

test "decision 150: an init that fails after it reads the key wipes the key and the cookie key" {
    var counter: support.Counter = .{};
    const identity: Identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    // The bind refuses the host after `load` has read the key and drawn the cookie key.
    try testing.expectError(error.HostInvalid, test_server.init(.{ .host = "localhost", .identity = identity, .cpu = support.cpu(), .random = counter.random() }));
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
}
