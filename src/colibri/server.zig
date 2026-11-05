//! A server that binds one port and runs `server.Endpoint` on Rotor's loop (decision 150): h11 and
//! h2 over TCP, and h3 over QUIC on the UDP socket of the same port. A program places one, as it
//! places an endpoint, and keeps it in place while it runs.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const tls = @import("tls");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const identity_module = @import("identity.zig");
const identity_files = @import("identity_files.zig");
const socket_module = @import("socket.zig");
const pump = @import("server_pump.zig");
const server_loop = @import("server_loop.zig");
const server_udp = @import("server_udp.zig");
const batch_module = @import("datagram_batch.zig");
const entropy = @import("entropy.zig");

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
    /// What the endpoint starts from. `colibri` fills its `tls` from `identity`.
    endpoint: server.Config = .{},
};

pub const InitError = identity_module.LoadError || server_loop.BindError || rotor.sync.SocketError;

pub const RunError = rotor.Loop.InitError || rotor.Loop.TickError || rotor.Loop.DrainError ||
    rotor.Loop.ProvideError || server.StartError;

/// A server of the default capacity.
pub const Server = ServerOf(.{});

/// A server whose endpoint holds `capacity`'s connections.
pub fn ServerOf(comptime capacity: server.Capacity) type {
    return struct {
        const Self = @This();

        const tcp_connections = capacity.tcp_connections;
        const Bits = std.bit_set.IntegerBitSet(tcp_connections);
        /// The operations the loop holds in flight: an accept, for each socket a receive, a send
        /// and a close, and the UDP socket's receive and sends.
        const loop_options: rotor.Loop.Options = .{
            .operations = tcp_connections * socket_module.operations_per_socket + 1 + server_udp.operations,
        };
        comptime {
            assert(tcp_connections > 0 and loop_options.operations <= rotor.constants.batch_max);
            // `init` reads `.files` on a loop of one slot in the memory `run`'s loop takes later.
            assert(identity_files.loop_memory_bytes <= rotor.Loop.memory_bytes(loop_options));
            assert(tcp_connections < server_udp.send_user_data_last >> socket_module.kind_bits);
        }

        loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment),
        config: ServerConfig,
        identity: identity_module.Storage,
        endpoint_config: server.Config,
        /// The endpoint, and the server's entry for each socket's connection
        /// (`server_pump.zig`).
        endpoint: server.EndpointOf(capacity),
        entries: [tcp_connections]pump.Entry,
        entry_of: [tcp_connections]?u32,
        /// The loop, its listener and its sockets (`server_loop.zig`).
        loop: rotor.Loop,
        events: [loop_options.operations]rotor.Event,
        listener: rotor.Descriptor,
        bound_port: u16,
        accepting: bool,
        sockets: [tcp_connections]socket_module.Socket,
        /// The UDP socket, open when the server has an identity and QUIC slots (design §8 step
        /// 37c), its receive buffers, its batches and their destinations, and the room each
        /// datagram is written in.
        udp_open: bool,
        udp_socket: rotor.Descriptor,
        udp_receiving: rotor.Handle,
        udp_group: [server_udp.group_bytes + rotor.buffers.group_alignment]u8 align(rotor.buffers.group_alignment),
        batches: batch_module.Batches,
        udp_outbound: [constants.limits.udp_batches]rotor.datagram.Outbound,
        udp_datagram: [constants.limits.udp_datagram_len_max]u8,
        /// The entries an event named since their last step, and the sockets a turn changed.
        pending: Bits,
        touched: Bits,
        /// Whether a read of the endpoint's events stopped at its bound.
        undrained: bool,
        /// The instant of the last call into the endpoint.
        now_ns: u64,
        /// `shutdown` asked, the loop passed it to the endpoint, and the endpoint reported
        /// `closed`.
        stopping: std.atomic.Value(bool),
        shut_down: bool,
        over: bool,

        /// Reads the identity, keeps the configuration and binds the listener, so `port()` holds
        /// the port bound once `init` returns. The server runs on Rotor's own loop (decision 150
        /// ruling 10).
        pub fn init(self: *Self, config: ServerConfig) InitError!void {
            self.config = config;
            if (self.config.random == null) self.config.random = entropy.random();
            self.endpoint_config = config.endpoint;
            assert(self.endpoint_config.tls == null);
            // A server that `init` does not return keeps no private key and no cookie key.
            errdefer {
                self.identity.key.wipe();
                std.crypto.secureZero(u8, &self.identity.cookie_key);
            }
            if (config.identity) |identity| {
                self.endpoint_config.tls = try identity_module.load(identity, &self.identity, &self.loop_memory, config.cpu, self.config.random.?);
            }
            assert((self.endpoint_config.tls != null) == (config.identity != null));
            try server_loop.bind(self);
            errdefer rotor.sync.close_now(self.listener);
            try server_udp.open_when_served(self, capacity.quic_connections > 0);
            self.stopping = .init(false);
        }

        /// The port the server bound: the configured one, or the one the system chose for 0.
        pub fn port(self: *const Self) u16 {
            assert(self.bound_port != 0);
            return self.bound_port;
        }

        /// Asks a running server to stop: it takes no new connection, ends each one it holds, and
        /// `run` returns. Any thread may call it.
        pub fn shutdown(self: *Self) void {
            self.stopping.store(true, .release);
        }

        /// Serves on the thread that calls it until `shutdown`: each request goes to `router`, a
        /// pool of `server.router`'s, with `context` (decision 150). The loop runs here because a
        /// Rotor loop belongs to the thread that starts it.
        pub fn run(self: *Self, router: anytype, context: anytype) RunError!void {
            defer rotor.sync.close_now(self.listener);
            defer if (self.udp_open) rotor.sync.close_now(self.udp_socket);
            try self.loop.init(&self.loop_memory, loop_options);
            defer self.loop.deinit();
            defer {
                self.loop.cancel_all();
                self.loop.drain(&self.events) catch {};
            }
            server_loop.reset(self);
            // The server issues no ticket unless the program gave a ticket key, so the instant in
            // seconds it judges tickets at is chapulin's 0 for none.
            try self.endpoint.init(&self.endpoint_config, self.config.random.?, 0, self.now_ns);
            if (self.udp_open) try server_udp.start(self);
            const Run = struct { server: *Self, router: @TypeOf(router), context: @TypeOf(context) };
            var running: Run = .{ .server = self, .router = router, .context = context };
            while (!server_loop.finished(self)) try server_loop.turn(&running);
        }
    };
}

const testing = std.testing;
const testdata = @import("testdata");
const support = @import("test_support.zig");

/// A server the tests place, outside any stack frame. Test-only.
threadlocal var test_server: Server align(@alignOf(Server)) = undefined;

test "design §8 step 37c: an identity opens UDP on the listener's port, which Alt-Svc names" {
    var counter: support.Counter = .{};
    try test_server.init(.{
        .identity = .{ .pem = .{ .chain = testdata.chain_pem, .key = testdata.key_pem } },
        .cpu = support.cpu(),
        .random = counter.random(),
    });
    defer rotor.sync.close_now(test_server.listener);
    try testing.expect(test_server.udp_open);
    defer rotor.sync.close_now(test_server.udp_socket);
    const local = try rotor.sync.local_address(test_server.udp_socket);
    try testing.expectEqual(test_server.port(), local.port);
    // RFC 7838 §3: the TCP connections over TLS advertise h3 on the same port.
    try testing.expectEqual(test_server.port(), test_server.endpoint_config.h3_alternative.?.port);
}

test "decision 150: init reads a PEM identity into the endpoint's TLS values" {
    var counter: support.Counter = .{};
    try test_server.init(.{
        .identity = .{ .pem = .{ .chain = testdata.chain_pem, .key = testdata.key_pem } },
        .cpu = support.cpu(),
        .random = counter.random(),
    });
    const values = test_server.endpoint_config.tls.?;
    try testing.expectEqual(1, values.identities.len);
    try testing.expectEqual(.ecdsa_secp256r1_sha256, values.identities[0].key.scheme);
    try testing.expectEqualSlices(u8, testdata.leaf, values.identities[0].chain[0]);
    rotor.sync.close_now(test_server.listener);
    if (test_server.udp_open) rotor.sync.close_now(test_server.udp_socket);
    // RFC 9846 §4.3.2: the cookie key comes from the program's source.
    try testing.expectEqual(0, values.cookie_key[0]);
    try testing.expectEqual(1, values.cookie_key[1]);
}

test "design §8 step 37e: init reads the identity from PEM files, and wipes the key's text" {
    var directory: support.TestDirectory = .init();
    defer directory.deinit();
    const chain = try directory.write(.chain, testdata.chain_pem);
    const key = try directory.write(.key, testdata.key_pem);
    var counter: support.Counter = .{};
    try test_server.init(.{ .identity = .{ .files = .{ .chain = chain, .key = key } }, .cpu = support.cpu(), .random = counter.random() });
    rotor.sync.close_now(test_server.listener);
    if (test_server.udp_open) rotor.sync.close_now(test_server.udp_socket);
    const values = test_server.endpoint_config.tls.?;
    try testing.expectEqual(.ecdsa_secp256r1_sha256, values.identities[0].key.scheme);
    try testing.expectEqualSlices(u8, testdata.leaf, values.identities[0].chain[0]);
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.files.key, 0));
    // A missing key file ends `init` before it binds.
    const missing = ".zig-cache/tmp/colibri-no-such-directory/key.pem";
    try testing.expectError(error.IdentityFileNotFound, test_server.init(.{ .identity = .{ .files = .{ .chain = chain, .key = missing } }, .cpu = support.cpu(), .random = counter.random() }));
}

test "decision 150 ruling 9: a server given no source draws from the system" {
    try test_server.init(.{ .identity = .{ .pem = .{ .chain = testdata.chain_pem, .key = testdata.key_pem } }, .cpu = support.cpu() });
    try testing.expect(test_server.config.random != null);
    const values = test_server.endpoint_config.tls.?;
    // Thirty-two octets from the system are not the counter's 0, 1, 2, ...
    try testing.expect(!(values.cookie_key[0] == 0 and values.cookie_key[1] == 1 and values.cookie_key[2] == 2));
    rotor.sync.close_now(test_server.listener);
    if (test_server.udp_open) rotor.sync.close_now(test_server.udp_socket);
}

test "decision 150: no identity serves cleartext" {
    var counter: support.Counter = .{};
    try test_server.init(.{ .cpu = support.cpu(), .random = counter.random() });
    try testing.expectEqual(null, test_server.endpoint_config.tls);
    // RFC 9001 §4: QUIC needs TLS, so a cleartext server opens no UDP socket.
    try testing.expect(!test_server.udp_open);
    try testing.expectEqual(null, test_server.endpoint_config.h3_alternative);
    rotor.sync.close_now(test_server.listener);
    if (test_server.udp_open) rotor.sync.close_now(test_server.udp_socket);
}

test "decision 150: a host that is no IP literal is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.HostInvalid, test_server.init(.{ .host = "localhost", .cpu = support.cpu(), .random = counter.random() }));
}

test "decision 150: an init that fails after it reads the key wipes the key and the cookie key" {
    var counter: support.Counter = .{};
    const identity: Identity = .{ .pem = .{ .chain = testdata.chain_pem, .key = testdata.key_pem } };
    // The bind refuses the host after `load` has read the key and drawn the cookie key.
    try testing.expectError(error.HostInvalid, test_server.init(.{ .host = "localhost", .identity = identity, .cpu = support.cpu(), .random = counter.random() }));
    try testing.expect(counter.next != 0);
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.key.private_key, 0));
    try testing.expect(std.mem.allEqual(u8, &test_server.identity.cookie_key, 0));
}

test {
    _ = @import("server_tcp_test.zig");
}
