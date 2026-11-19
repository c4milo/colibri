//! The command line of the test-only server (`../server.zig`), as `tools/h2spec.sh` and the interop
//! scripts pass it. Split off the server for length.
//!
//!     http-server [--port <port>] [--address <ipv4>] [--h11 | --h2] [--echo] [--coded]
//!         [--tls <identity-prefix> [--seconds <unix-seconds>]] [--h3-port <port>]
//!         [--routes github | kubernetes] [--body <octets>]
//!
//! A `--port` of 0 takes the port the kernel chooses, which the server's `listening on port` line
//! names (https://github.com/c4milo/colibri/issues/94). `--h11`, `--h2`, `--echo` and `--coded` take no
//! value. `--coded` codes each response in gzip or deflate when its request accepts one (decision
//! 101). `--h11` makes the server speak h11 alone and `--h2` h2 alone: a cleartext connection speaks
//! it from the start, and a TLS server offers it alone. With neither, a cleartext connection speaks
//! h2 when its first octets are h2's connection preface and h11 otherwise (decision 117), and a TLS
//! server offers both. `--echo` answers every h11 request with what h11 read of it
//! (`../h11/h11_echo.zig`), for the HTTP Garden, and needs `--h11` in cleartext. `--h3-port` names
//! the UDP port each TLS connection advertises h3 on (design §8 step 17b): an Alt-Svc line on each
//! final h11 response, and one ALTSVC frame per h2 connection. `--seconds` gives a TLS server
//! the Unix time it starts at: the server then draws a ticket key and issues session tickets
//! (RFC 9846 §4.7.1, decision 161). Without it the server issues none. `--routes` names the route
//! table that `server.Router` answers every request through: the GitHub API's 203 routes (design §8
//! step 13f), or 463 of the Kubernetes API's (design §8 step 13l). `--body` makes every answer
//! carry that many octets, from 1 to `constants.answer_body_len_max`, in place of its fixed body,
//! so the judge measures responses longer than the output (design §8 step 13n).
const std = @import("std");
const constants = @import("../constants.zig");
const alpn = @import("../alpn.zig");

const Protocol = alpn.Protocol;

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
const h2_option = "--h2";
const echo_option = "--echo";
const h3_port_option = "--h3-port";
const coded_option = "--coded";
const routes_option = "--routes";
const seconds_option = "--seconds";
const body_option = "--body";

/// The base the Unix seconds are written in on the command line.
const decimal: u8 = 10;
/// The route tables `--routes` names, or none.
pub const Routes = enum { none, github, kubernetes };

/// What the command line asked for.
pub const Options = struct {
    port: u16 = constants.default_port,
    address: [ipv4_octets]u8 = loopback_octets,
    /// The prefix of the identity files `tools/h2_interop/tls_identity.go` wrote, which turns the
    /// TLS mode on.
    identity_prefix: ?[]const u8 = null,
    /// The one version the server speaks, `.h11` with `--h11` and `.h2` with `--h2`, or null for
    /// both.
    alone: ?Protocol = null,
    echo: bool = false,
    /// Whether responses are coded in a coding their request accepts (decision 101).
    coded: bool = false,
    /// The UDP port each TLS connection advertises h3 on, or null for none.
    h3_port: ?u16 = null,
    /// The route table the server routes every request through with `server.Router`
    /// (`--routes`), or none.
    routes: Routes = .none,
    /// The Unix seconds the server starts at, which its session tickets carry, or null to issue
    /// none (decision 161).
    unix_seconds: ?u64 = null,
    /// The octets of content every answer carries (`--body`), or null for `response_body`.
    body_len: ?u32 = null,
};

/// Reads the options from `arguments`, anything with a `next` that answers the next argument or
/// null, or returns null when one is unknown or unreadable, or when `--echo` is asked of anything
/// but h11 in cleartext.
pub fn read(arguments: anytype) ?Options {
    var options: Options = .{};
    for (0..constants.arguments_max) |_| {
        const argument = arguments.next() orelse break;
        const flag = read_flag(&options, argument) orelse return null;
        if (flag == .taken) continue;
        const value = arguments.next() orelse return null;
        read_setting(&options, argument, value) orelse return null;
    }
    return if (modes_fit(&options)) options else null;
}

/// Whether the modes `options` asks for fit together.
fn modes_fit(options: *const Options) bool {
    // The echo is h11's, and the Garden reaches its origins in cleartext.
    const echo_ok = !options.echo or (options.alone == .h11 and options.identity_prefix == null);
    // The router answers every request itself, so no other mode answers too, and it codes no
    // response until design §8 step 25.6.
    const routes_ok = options.routes == .none or (!options.echo and !options.coded);
    // A ticket is a TLS message (RFC 9846 §4.7.1), so the time serves the TLS mode alone.
    const seconds_ok = options.unix_seconds == null or options.identity_prefix != null;
    // A body replaces the fixed answer, which the echo, the router and the coding replace too.
    const body_ok = options.body_len == null or (!options.echo and options.routes == .none and !options.coded);
    return echo_ok and routes_ok and seconds_ok and body_ok;
}

/// Whether `read_flag` took an argument as a flag, or left it for `read_setting`.
const Flag = enum { taken, not_a_flag };

/// Applies `argument` when it is a flag, an option that takes no value, or returns null when it
/// names a second version alone: `--h11` and `--h2` together name none.
fn read_flag(options: *Options, argument: []const u8) ?Flag {
    const eql = std.mem.eql;
    if (eql(u8, argument, h11_option) or eql(u8, argument, h2_option)) {
        const chosen: Protocol = if (eql(u8, argument, h11_option)) .h11 else .h2;
        if (options.alone != null and options.alone != chosen) return null;
        options.alone = chosen;
    } else if (eql(u8, argument, echo_option)) {
        options.echo = true;
    } else if (eql(u8, argument, coded_option)) {
        options.coded = true;
    } else return .not_a_flag;
    return .taken;
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
    } else if (eql(u8, option, h3_port_option)) {
        options.h3_port = std.fmt.parseInt(u16, value, constants.port_radix) catch return null;
    } else return read_mode(options, option, value);
}

/// Applies one option of a mode and its value, or returns null when it is not one or its value is
/// unreadable.
fn read_mode(options: *Options, option: []const u8, value: []const u8) ?void {
    const eql = std.mem.eql;
    if (eql(u8, option, routes_option)) {
        options.routes = parse_routes(value) orelse return null;
    } else if (eql(u8, option, seconds_option)) {
        options.unix_seconds = parse_seconds(value) orelse return null;
    } else if (eql(u8, option, body_option)) {
        options.body_len = parse_body_len(value) orelse return null;
    } else return null;
}

/// The route table `--routes` names, or null for a name that is no table's.
fn parse_routes(value: []const u8) ?Routes {
    const routes = std.meta.stringToEnum(Routes, value) orelse return null;
    return if (routes == .none) null else routes;
}

/// The Unix seconds of `--seconds`, or null for a value that is not a count, or for 0, which
/// chapulin reads as no clock and so as no ticket: the run omits the option instead.
fn parse_seconds(value: []const u8) ?u64 {
    const seconds = std.fmt.parseUnsigned(u64, value, decimal) catch return null;
    return if (seconds == 0) null else seconds;
}

/// The octets of `--body`, or null for a value that is not a count from 1 to
/// `constants.answer_body_len_max`.
fn parse_body_len(value: []const u8) ?u32 {
    const len = std.fmt.parseUnsigned(u32, value, decimal) catch return null;
    return if (len == 0 or len > constants.answer_body_len_max) null else len;
}

pub const usage = "usage: http-server [--port <port>] [--address <ipv4>] [--h11 | --h2] [--echo] [--coded] [--tls <identity-prefix> [--seconds <unix-seconds>]] [--h3-port <port>] [--routes github | kubernetes] [--body <octets>]\n";

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
    try testing.expect(echo.echo and echo.alone == .h11 and echo.identity_prefix == null);
    const defaults = test_read(&.{}).?;
    try testing.expectEqualSlices(u8, &loopback_octets, &defaults.address);
    try testing.expectEqual(null, defaults.alone);
    try testing.expectEqual(Protocol.h2, test_read(&.{"--h2"}).?.alone.?);
    try testing.expectEqual(null, test_read(&.{ "--h11", "--h2" }));
    try testing.expectEqualStrings("id", test_read(&.{ "--tls", "id" }).?.identity_prefix.?);
    try testing.expectEqual(8443, test_read(&.{ "--h3-port", "8443" }).?.h3_port.?);
    try testing.expectEqual(null, defaults.h3_port);
    try testing.expectEqual(null, test_read(&.{ "--h3-port", "65536" }));
    try testing.expectEqual(null, test_read(&.{ "--port", "port" }));
    try testing.expectEqual(null, test_read(&.{ "--address", "::1" }));
    try testing.expectEqual(null, test_read(&.{"--port"}));
    try testing.expectEqual(null, test_read(&.{ "--other", "1" }));
}

test "decision 161: --seconds takes Unix seconds above 0, over TLS alone" {
    try testing.expectEqual(1_790_000_000, test_read(&.{ "--tls", "id", "--seconds", "1790000000" }).?.unix_seconds.?);
    try testing.expectEqual(null, test_read(&.{ "--tls", "id" }).?.unix_seconds);
    try testing.expectEqual(null, test_read(&.{ "--seconds", "1790000000" }));
    try testing.expectEqual(null, test_read(&.{ "--tls", "id", "--seconds", "0" }));
    try testing.expectEqual(null, test_read(&.{ "--tls", "id", "--seconds", "soon" }));
    try testing.expectEqual(null, test_read(&.{ "--tls", "id", "--seconds" }));
}

test "the echo is h11's, in cleartext" {
    try testing.expectEqual(null, test_read(&.{"--echo"}));
    try testing.expectEqual(null, test_read(&.{ "--h11", "--echo", "--tls", "id" }));
}

test "design §8 step 13f: --routes takes github or kubernetes, and no other mode that answers or codes" {
    try testing.expectEqual(Routes.github, test_read(&.{ "--routes", "github" }).?.routes);
    try testing.expectEqual(Routes.github, test_read(&.{ "--h2", "--routes", "github" }).?.routes);
    try testing.expectEqual(Routes.kubernetes, test_read(&.{ "--routes", "kubernetes" }).?.routes);
    try testing.expectEqual(Routes.none, test_read(&.{}).?.routes);
    try testing.expectEqual(null, test_read(&.{ "--routes", "gitlab" }));
    try testing.expectEqual(null, test_read(&.{ "--routes", "none" }));
    try testing.expectEqual(null, test_read(&.{ "--coded", "--routes", "kubernetes" }));
    try testing.expectEqual(null, test_read(&.{"--routes"}));
    try testing.expectEqual(null, test_read(&.{ "--h11", "--echo", "--routes", "github" }));
    try testing.expectEqual(null, test_read(&.{ "--coded", "--routes", "github" }));
}

test "design §8 step 13n: --body takes from 1 octet to the most, and no mode with an answer of its own" {
    try testing.expectEqual(262_144, test_read(&.{ "--body", "262144" }).?.body_len.?);
    try testing.expectEqual(constants.answer_body_len_max, test_read(&.{ "--body", "1048576" }).?.body_len.?);
    try testing.expectEqual(null, test_read(&.{}).?.body_len);
    try testing.expectEqual(null, test_read(&.{ "--body", "0" }));
    try testing.expectEqual(null, test_read(&.{ "--body", "1048577" }));
    try testing.expectEqual(null, test_read(&.{ "--body", "large" }));
    try testing.expectEqual(null, test_read(&.{"--body"}));
    try testing.expectEqual(null, test_read(&.{ "--h11", "--echo", "--body", "8" }));
    try testing.expectEqual(null, test_read(&.{ "--routes", "github", "--body", "8" }));
    try testing.expectEqual(null, test_read(&.{ "--coded", "--body", "8" }));
    try testing.expectEqual(8, test_read(&.{ "--tls", "id", "--body", "8" }).?.body_len.?);
}
