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
const socket_module = @import("socket.zig");
const pump = @import("server_pump.zig");
const server_loop = @import("server_loop.zig");
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

pub const InitError = identity_module.LoadError || server_loop.BindError || error{
    /// A program passed a `std.Io`, which `colibri` takes once Rotor's adapter exists (decision 150
    /// ruling 6).
    IoUnavailable,
};

pub const RunError = rotor.Loop.InitError || rotor.Loop.TickError || rotor.Loop.DrainError || server.StartError;

/// A server of the default capacity.
pub const Server = ServerOf(.{});

/// A server whose endpoint holds `capacity`'s connections.
pub fn ServerOf(comptime capacity: server.Capacity) type {
    return struct {
        const Self = @This();

        const tcp_connections = capacity.tcp_connections;
        const Bits = std.bit_set.IntegerBitSet(tcp_connections);
        /// The operations the loop holds in flight: an accept, and for each socket a receive, a
        /// send and a close.
        const loop_options: rotor.Loop.Options = .{
            .operations = tcp_connections * socket_module.operations_per_socket + 1,
        };
        comptime {
            assert(tcp_connections > 0 and loop_options.operations <= rotor.constants.batch_max);
            assert(tcp_connections < server_loop.accept_user_data >> socket_module.kind_bits);
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
        /// the port bound once `init` returns. `io` must be null until Rotor's `std.Io` adapter
        /// exists, and the server then runs on Rotor's own loop.
        pub fn init(self: *Self, io: ?std.Io, config: ServerConfig) InitError!void {
            if (io != null) return error.IoUnavailable;
            self.config = config;
            if (self.config.random == null) self.config.random = entropy.random();
            self.endpoint_config = config.endpoint;
            assert(self.endpoint_config.tls == null);
            if (config.identity) |identity| {
                self.endpoint_config.tls = try identity_module.load(identity, &self.identity, config.cpu, self.config.random.?);
            }
            assert((self.endpoint_config.tls != null) == (config.identity != null));
            try server_loop.bind(self);
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
            try self.loop.init(&self.loop_memory, loop_options);
            defer self.loop.deinit();
            defer {
                self.loop.cancel_all();
                self.loop.drain(&self.events) catch {};
            }
            for (&self.sockets) |*socket| socket.live = false;
            for (&self.entries) |*entry| entry.* = .{ .handle = pump.no_connection, .attached = false, .closing = false, .send_owed = false };
            self.entry_of = @splat(null);
            self.pending = Bits.initEmpty();
            self.touched = Bits.initEmpty();
            self.accepting = false;
            self.undrained = false;
            self.shut_down = false;
            self.over = false;
            self.now_ns = self.loop.now_ns();
            // The server issues no ticket unless the program gave a ticket key, so the instant in
            // seconds it judges tickets at is chapulin's 0 for none.
            try self.endpoint.init(&self.endpoint_config, self.config.random.?, 0, self.now_ns);
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

test "decision 150: init reads a PEM identity into the endpoint's TLS values" {
    var counter: support.Counter = .{};
    try test_server.init(null, .{
        .identity = .{ .pem = .{ .chain = testdata.chain_pem, .key = testdata.key_pem } },
        .cpu = support.cpu(),
        .random = counter.random(),
    });
    const values = test_server.endpoint_config.tls.?;
    try testing.expectEqual(1, values.identities.len);
    try testing.expectEqual(.ecdsa_secp256r1_sha256, values.identities[0].key.scheme);
    try testing.expectEqualSlices(u8, testdata.leaf, values.identities[0].chain[0]);
    rotor.sync.close_now(test_server.listener);
    // RFC 9846 §4.3.2: the cookie key comes from the program's source.
    try testing.expectEqual(0, values.cookie_key[0]);
    try testing.expectEqual(1, values.cookie_key[1]);
}

test "decision 150 ruling 9: a server given no source draws from the system" {
    try test_server.init(null, .{ .identity = .{ .pem = .{ .chain = testdata.chain_pem, .key = testdata.key_pem } }, .cpu = support.cpu() });
    try testing.expect(test_server.config.random != null);
    const values = test_server.endpoint_config.tls.?;
    // Thirty-two octets from the system are not the counter's 0, 1, 2, ...
    try testing.expect(!(values.cookie_key[0] == 0 and values.cookie_key[1] == 1 and values.cookie_key[2] == 2));
    rotor.sync.close_now(test_server.listener);
}

test "decision 150: no identity serves cleartext, and a std.Io waits for Rotor's adapter" {
    var counter: support.Counter = .{};
    try test_server.init(null, .{ .cpu = support.cpu(), .random = counter.random() });
    try testing.expectEqual(null, test_server.endpoint_config.tls);
    rotor.sync.close_now(test_server.listener);
    var threaded: std.Io.Threaded = .init_single_threaded;
    try testing.expectError(error.IoUnavailable, test_server.init(threaded.io(), .{ .cpu = support.cpu(), .random = counter.random() }));
}

test "decision 150: a host that is no IP literal is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.HostInvalid, test_server.init(null, .{ .host = "localhost", .cpu = support.cpu(), .random = counter.random() }));
}

test {
    _ = @import("server_tcp_test.zig");
}
