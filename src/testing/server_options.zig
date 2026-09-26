//! The command line of the test-only server (`server.zig`), as `tools/h2spec.sh` and the interop
//! scripts pass it. Split off the server for length.
//!
//!     http-server [--port <port>] [--address <ipv4>] [--h11] [--echo] [--tls <identity-prefix>]
//!
//! `--h11` and `--echo` take no value. `--h11` makes a cleartext connection speak h11, or a TLS
//! server offer `http/1.1` alone. `--echo` answers every h11 request with what h11 read of it
//! (`h11/h11_echo.zig`), for the HTTP Garden, and needs `--h11` in cleartext.
const std = @import("std");
const constants = @import("constants.zig");
const session = @import("session.zig");

const Protocol = session.Protocol;

/// How many octets an IPv4 address has (RFC 791 §3.1).
pub const ipv4_octets: usize = 4;

/// The address the server listens on unless `--address` names another: the loopback, because it
/// serves tests alone. RFC 1122 §3.2.1.3 reserves 127.0.0.0/8 for the local host.
pub const loopback_octets = [ipv4_octets]u8{ loopback_first, 0, 0, 1 };
const loopback_first: u8 = 127;

const port_option = "--port";
const address_option = "--address";
const tls_option = "--tls";
const h11_option = "--h11";
const echo_option = "--echo";

/// What the command line asked for.
pub const Options = struct {
    port: u16 = constants.default_port,
    address: [ipv4_octets]u8 = loopback_octets,
    /// The prefix of the identity files `tools/h2_interop/tls_identity.go` wrote, which turns the
    /// TLS mode on.
    identity_prefix: ?[]const u8 = null,
    protocol: Protocol = .h2,
    echo: bool = false,
};

/// Reads the options from `arguments`, anything with a `next` that answers the next argument or
/// null, or returns null when one is unknown or unreadable, or when `--echo` is asked of anything
/// but h11 in cleartext.
pub fn read(arguments: anytype) ?Options {
    var options: Options = .{};
    for (0..constants.arguments_max) |_| {
        const argument = arguments.next() orelse break;
        if (std.mem.eql(u8, argument, h11_option)) {
            options.protocol = .h11;
            continue;
        }
        if (std.mem.eql(u8, argument, echo_option)) {
            options.echo = true;
            continue;
        }
        const value = arguments.next() orelse return null;
        read_setting(&options, argument, value) orelse return null;
    }
    // The echo is h11's, and the Garden reaches its origins in cleartext.
    const echo_ok = !options.echo or (options.protocol == .h11 and options.identity_prefix == null);
    return if (echo_ok) options else null;
}

/// Applies one option and its value, or returns null when it is not one or its value is
/// unreadable.
fn read_setting(options: *Options, option: []const u8, value: []const u8) ?void {
    const eql = std.mem.eql;
    if (eql(u8, option, port_option)) {
        options.port = std.fmt.parseInt(u16, value, constants.port_radix) catch return null;
    } else if (eql(u8, option, address_option)) {
        const address = std.Io.net.IpAddress.parseIp4(value, 0) catch return null;
        options.address = address.ip4.bytes;
    } else if (eql(u8, option, tls_option)) {
        options.identity_prefix = value;
    } else return null;
}

pub const usage = "usage: http-server [--port <port>] [--address <ipv4>] [--h11] [--echo] [--tls <identity-prefix>]\n";

const testing = std.testing;

/// The arguments a test hands `read`, one at a time. Test-only.
const TestArguments = struct {
    values: []const []const u8,
    index: usize = 0,

    fn next(arguments: *TestArguments) ?[]const u8 {
        if (arguments.index == arguments.values.len) return null;
        defer arguments.index += 1;
        return arguments.values[arguments.index];
    }
};

fn test_read(values: []const []const u8) ?Options {
    var arguments: TestArguments = .{ .values = values };
    return read(&arguments);
}

test "the options read into what the server runs, and unreadable ones are refused" {
    const echo = test_read(&.{ "--port", "8081", "--address", "0.0.0.0", "--h11", "--echo" }).?;
    try testing.expectEqual(8081, echo.port);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &echo.address);
    try testing.expect(echo.echo and echo.protocol == .h11 and echo.identity_prefix == null);
    const defaults = test_read(&.{}).?;
    try testing.expectEqualSlices(u8, &loopback_octets, &defaults.address);
    try testing.expectEqual(Protocol.h2, defaults.protocol);
    try testing.expectEqualStrings("id", test_read(&.{ "--tls", "id" }).?.identity_prefix.?);
    try testing.expectEqual(null, test_read(&.{ "--port", "port" }));
    try testing.expectEqual(null, test_read(&.{ "--address", "::1" }));
    try testing.expectEqual(null, test_read(&.{"--port"}));
    try testing.expectEqual(null, test_read(&.{ "--other", "1" }));
}

test "the echo is h11's, in cleartext" {
    try testing.expectEqual(null, test_read(&.{"--echo"}));
    try testing.expectEqual(null, test_read(&.{ "--h11", "--echo", "--tls", "id" }));
}
