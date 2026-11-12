//! The binds of a `.private` server's sockets (decision 150), split off `server_kinds.zig` so that
//! the retry of a port the system chose has tests over a fake host: a test cannot make the system
//! choose a port that another program holds.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const errors = @import("errors.zig");
const host_module = @import("host.zig");

const SocketId = host_module.SocketId;

/// Binds the listener on `text` and `port`, and when `h3` is set, the UDP socket on the
/// listener's port, where the server serves h3 (decision 150). With port 0 the system chooses the
/// TCP port, and another program may hold UDP on that number. So the server closes the listener
/// and asks for another port, `bind_tries_max` times at most. A fixed port gets one try, and any
/// other failure ends the binds at once.
pub fn bind(host: anytype, listener: SocketId, datagram: SocketId, text: []const u8, port: u16, h3: bool) errors.BindError!void {
    const tries: usize = if (port == 0 and h3) constants.limits.bind_tries_max else 1;
    for (0..tries) |index| {
        try host.listen(listener, text, port);
        if (!h3) return;
        assert(host.bound_port != 0);
        host.bind_datagram(datagram, text, host.bound_port) catch |failure| {
            host.close_open();
            if (failure == error.AddressInUse and index + 1 < tries) continue;
            return failure;
        };
        return;
    }
    unreachable;
}

const testing = std.testing;

/// A host whose system chooses `first_port`, then the port after it, and whose UDP binds fail
/// with `failure` for the first `held` tries. It halts when a listen finds the last listener
/// open. Test-only.
const FakeHost = struct {
    first_port: u16,
    held: usize,
    failure: errors.BindError = error.AddressInUse,
    bound_port: u16 = 0,
    listens: usize = 0,
    binds: usize = 0,
    closes: usize = 0,
    listening: bool = false,

    pub fn listen(fake: *FakeHost, _: SocketId, _: []const u8, port: u16) errors.BindError!void {
        // A try that failed closed its listener first, so no two listeners hold ports at once.
        assert(!fake.listening);
        fake.bound_port = if (port == 0) fake.first_port + @as(u16, @intCast(fake.listens)) else port;
        fake.listens += 1;
        fake.listening = true;
    }

    pub fn bind_datagram(fake: *FakeHost, _: SocketId, _: []const u8, port: u16) errors.BindError!void {
        assert(port == fake.bound_port);
        fake.binds += 1;
        if (fake.binds <= fake.held) return fake.failure;
    }

    pub fn close_open(fake: *FakeHost) void {
        fake.closes += 1;
        fake.listening = false;
    }
};

const test_listener: SocketId = @enumFromInt(0);
const test_datagram: SocketId = @enumFromInt(1);

test "decision 150: on port 0 the server asks for another port while UDP holds the one it got" {
    var fake: FakeHost = .{ .first_port = 40_001, .held = 2 };
    try bind(&fake, test_listener, test_datagram, "127.0.0.1", 0, true);
    // Two ports were held for UDP, so the third one serves both.
    try testing.expectEqual(40_003, fake.bound_port);
    try testing.expectEqual(3, fake.listens);
    try testing.expectEqual(2, fake.closes);
}

test "decision 150: on port 0 the binds end after bind_tries_max ports held for UDP" {
    var fake: FakeHost = .{ .first_port = 41_001, .held = constants.limits.bind_tries_max };
    try testing.expectError(error.AddressInUse, bind(&fake, test_listener, test_datagram, "127.0.0.1", 0, true));
    try testing.expectEqual(constants.limits.bind_tries_max, fake.listens);
    try testing.expectEqual(constants.limits.bind_tries_max, fake.closes);
}

test "decision 150: a fixed port, or another failure, gets one try" {
    var fixed: FakeHost = .{ .first_port = 42_001, .held = 1 };
    try testing.expectError(error.AddressInUse, bind(&fixed, test_listener, test_datagram, "127.0.0.1", 8443, true));
    try testing.expectEqual(1, fixed.listens);
    var other: FakeHost = .{ .first_port = 43_001, .held = 1, .failure = error.AddressFamilyUnsupported };
    try testing.expectError(error.AddressFamilyUnsupported, bind(&other, test_listener, test_datagram, "127.0.0.1", 0, true));
    try testing.expectEqual(1, other.listens);
    // A server with no h3 binds no UDP socket.
    var tcp_only: FakeHost = .{ .first_port = 44_001, .held = 1 };
    try bind(&tcp_only, test_listener, test_datagram, "127.0.0.1", 0, false);
    try testing.expectEqual(0, tcp_only.binds);
}
