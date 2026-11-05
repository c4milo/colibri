//! A server that binds one port and runs `server.Endpoint` on Rotor's loop (decision 150): h11 and
//! h2 over TCP, and h3 over QUIC on the UDP socket of the same port. A program places one, as it
//! places an endpoint, and keeps it in place while it runs.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const tls = @import("tls");
const identity_module = @import("identity.zig");
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

pub const InitError = identity_module.LoadError || error{
    /// A program passed a `std.Io`, which `colibri` takes once Rotor's adapter exists (decision 150
    /// ruling 6).
    IoUnavailable,
};

/// A server of the default capacity.
pub const Server = ServerOf(.{});

/// A server whose endpoint holds `capacity`'s connections.
pub fn ServerOf(comptime capacity: server.Capacity) type {
    return struct {
        const Self = @This();

        config: ServerConfig,
        identity: identity_module.Storage,
        endpoint_config: server.Config,
        endpoint: server.EndpointOf(capacity),

        /// Reads the identity and keeps the configuration. `io` must be null until Rotor's
        /// `std.Io` adapter exists, and the server then runs on Rotor's own loop.
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
}

test "decision 150: no identity serves cleartext, and a std.Io waits for Rotor's adapter" {
    var counter: support.Counter = .{};
    try test_server.init(null, .{ .cpu = support.cpu(), .random = counter.random() });
    try testing.expectEqual(null, test_server.endpoint_config.tls);
    var threaded: std.Io.Threaded = .init_single_threaded;
    try testing.expectError(error.IoUnavailable, test_server.init(threaded.io(), .{ .cpu = support.cpu(), .random = counter.random() }));
}
