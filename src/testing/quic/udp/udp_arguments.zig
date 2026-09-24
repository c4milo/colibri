//! The command line of `zig build quic-udp` (design §8 step 9e, piece 11):
//!
//!     quic-udp server <address> <port> <identity-prefix> <www> [once] [retry] [connections=<n>]
//!         [seconds=<unix-seconds>]
//!     quic-udp client <address> <port> <anchor-prefix> <hostname> <unix-seconds> <downloads>
//!         [keyupdate] [resumption] <path>...
//!
//! An address is IPv4 in dotted decimal or IPv6 in RFC 4291 §2.2's text form. The server binds
//! `<address>:<port>` and serves `<www>`:
//! - `once` makes it exit when its first connection ends.
//! - `retry` makes it answer every client's first Initial with a Retry, and serve only a client
//!   that returns the token (RFC 9000 §8.1.2).
//! - `connections=<n>` holds at most n connections at once, from 1 to `quic_connections_max`,
//!   which is also the count without it.
//! - `seconds=<unix-seconds>` gives the server the Unix time it started at, which its session
//!   tickets carry (RFC 9846 §4.6.1). Without it the server issues no ticket and accepts none.
//!
//! The client sends to `<address>:<port>` and fetches each path into `<downloads>`:
//! - `keyupdate` updates its keys once, as soon as RFC 9001 §6.1 permits.
//! - `resumption` fetches the first path on one connection, keeps the ticket the server issues,
//!   and fetches the rest on a second connection that presents it (RFC 9846 §2.2).
//!
//! The instant is a clock the command line cannot give, so it comes from Rotor (decision 63); the
//! Unix seconds are the certificate check's and the tickets', which the caller reads
//! (non-negotiable 3).
const std = @import("std");
const constants = @import("../../constants.zig");
const check_file = @import("../../tls/check_file.zig");
const hq = @import("../hq/hq.zig");
const udp = @import("../../udp.zig");

pub const Role = enum { server, client };

pub const Server = struct {
    /// Where the server binds: an IPv4 or IPv6 address, and the port.
    address: udp.Address,
    /// The prefix of the files `tools/h2_interop/tls_identity.go` wrote.
    identity_prefix: []const u8,
    www: []const u8,
    once: bool = false,
    /// Whether the server validates each client's address with a Retry (RFC 9000 §8.1.2).
    retry: bool = false,
    /// The connections the server holds at once.
    connections: usize = constants.quic_connections_max,
    /// The Unix seconds the server started at, or 0 for none.
    now_seconds: u64 = 0,

    /// The Unix seconds at `now_ns`: `now_seconds` and the seconds Rotor's instant has advanced
    /// since `started_ns`, the first tick's (decision 63). 0 for a server given no clock.
    pub fn seconds_at(server: *const Server, started_ns: u64, now_ns: u64) u64 {
        std.debug.assert(now_ns >= started_ns);
        if (server.now_seconds == 0) return 0;
        return server.now_seconds + (now_ns - started_ns) / constants.nanoseconds_per_second;
    }
};

pub const Client = struct {
    /// The server the client sends to: an IPv4 or IPv6 address, and the port.
    address: udp.Address,
    anchor_prefix: []const u8,
    hostname: []const u8,
    now_seconds: u64,
    downloads: []const u8,
    paths: []const []const u8,
    /// Whether the client starts one key update (RFC 9001 §6.1).
    key_update: bool = false,
    /// Whether the client fetches the rest of its paths on a second, resumed connection.
    resumption: bool = false,
};

pub const Arguments = union(Role) {
    server: Server,
    client: Client,
};

/// The radix every number on the command line is written in.
const decimal: u8 = 10;

var paths_storage: [constants.hq_paths_max][]const u8 = undefined;

pub fn parse(init: std.process.Init.Minimal) Arguments {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.next();
    const role = std.meta.stringToEnum(Role, arguments.next() orelse usage()) orelse usage();
    const address_text = arguments.next() orelse usage();
    const port = std.fmt.parseUnsigned(u16, arguments.next() orelse usage(), decimal) catch usage();
    const address = parse_address(address_text, port) orelse usage();
    return switch (role) {
        .server => .{ .server = parse_server(&arguments, address) },
        .client => .{ .client = parse_client(&arguments, address) },
    };
}

fn parse_server(arguments: *std.process.Args.Iterator, address: udp.Address) Server {
    var server: Server = .{
        .address = address,
        .identity_prefix = arguments.next() orelse usage(),
        .www = arguments.next() orelse usage(),
    };
    // Bounded by the options there are, each of which may appear once.
    for (0..server_options_count) |_| {
        const word = arguments.next() orelse return server;
        if (std.mem.eql(u8, word, "once")) {
            server.once = true;
        } else if (std.mem.eql(u8, word, "retry")) {
            server.retry = true;
        } else if (parse_seconds(word)) |seconds| {
            server.now_seconds = seconds;
        } else {
            server.connections = parse_connections(word) orelse usage();
        }
    }
    if (arguments.next() != null) usage();
    return server;
}

/// The client's words for one key update and for a second, resumed connection. Every path starts
/// with `/`, so neither is a path.
const key_update_word = "keyupdate";
const resumption_word = "resumption";
const client_options_count: usize = 2;

/// Paths a client with `resumption` needs: one for each of its two connections.
const resumption_paths_min: usize = 2;

/// `once`, `retry`, `connections=<n>` and `seconds=<unix-seconds>`.
const server_options_count: usize = 4;

const connections_prefix = "connections=";
const seconds_prefix = "seconds=";

/// The Unix seconds of `seconds=<unix-seconds>`, or null for any other word, or for 0, which
/// chapulin reads as no clock.
fn parse_seconds(word: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, word, seconds_prefix)) return null;
    const seconds = std.fmt.parseUnsigned(u64, word[seconds_prefix.len..], decimal) catch return null;
    if (seconds == 0) return null;
    return seconds;
}

/// The count of `connections=<n>`, or null for any other word, or for a count the table cannot
/// hold: from 1 to `quic_connections_max`.
fn parse_connections(word: []const u8) ?usize {
    if (!std.mem.startsWith(u8, word, connections_prefix)) return null;
    const count = std.fmt.parseUnsigned(usize, word[connections_prefix.len..], decimal) catch return null;
    if (count == 0 or count > constants.quic_connections_max) return null;
    return count;
}

fn parse_client(arguments: *std.process.Args.Iterator, address: udp.Address) Client {
    var client: Client = .{
        .address = address,
        .anchor_prefix = arguments.next() orelse usage(),
        .hostname = arguments.next() orelse usage(),
        .now_seconds = std.fmt.parseUnsigned(u64, arguments.next() orelse usage(), decimal) catch usage(),
        .downloads = arguments.next() orelse usage(),
        .paths = &.{},
    };
    const first_path = parse_client_options(arguments, &client);
    client.paths = parse_paths(arguments, first_path);
    // A resumed connection needs a path of its own, after the first connection's one.
    const paths_min = if (client.resumption) resumption_paths_min else 1;
    if (client.paths.len < paths_min) usage();
    return client;
}

/// Reads the client's option words into `client`, and returns the first word after them, which is
/// the first path.
fn parse_client_options(arguments: *std.process.Args.Iterator, client: *Client) []const u8 {
    var next = arguments.next() orelse usage();
    // Bounded by the options there are, each of which may appear once.
    for (0..client_options_count) |_| {
        if (std.mem.eql(u8, next, key_update_word)) {
            client.key_update = true;
        } else if (std.mem.eql(u8, next, resumption_word)) {
            client.resumption = true;
        } else break;
        next = arguments.next() orelse usage();
    }
    return next;
}

/// Reads the paths, `first` and every word after it.
fn parse_paths(arguments: *std.process.Args.Iterator, first: []const u8) []const []const u8 {
    var count: usize = 0;
    var word: ?[]const u8 = first;
    // Bounded by `hq_paths_max`.
    while (word) |path| : (word = arguments.next()) {
        if (count == paths_storage.len) usage();
        var line: [constants.hq_request_len_max]u8 = undefined;
        // Each path is checked once here, so the client never builds a request it must refuse.
        _ = hq.write_request(path, &line) catch usage();
        paths_storage[count] = path;
        count += 1;
    }
    return paths_storage[0..count];
}

/// An IPv4 address in dotted decimal or an IPv6 address in RFC 4291 §2.2's text form, and the
/// port, or null. The parser refuses an IPv6 address that names an interface, which the endpoint
/// never binds.
fn parse_address(text: []const u8, port: u16) ?udp.Address {
    const parsed = std.Io.net.IpAddress.parse(text, port) catch return null;
    return switch (parsed) {
        .ip4 => |ip4| udp.Address.ipv4(ip4.bytes, port),
        .ip6 => |ip6| udp.Address.ipv6(ip6.bytes, port, 0),
    };
}

pub fn usage() noreturn {
    std.debug.print(
        "usage: quic-udp server <address> <port> <identity-prefix> <www> [once] [retry] [connections=<n>] [seconds=<unix-seconds>]\n" ++
            "       quic-udp client <address> <port> <anchor-prefix> <hostname> <unix-seconds> <downloads> [keyupdate] [resumption] <path>...\n",
        .{},
    );
    std.process.exit(check_file.exit_usage);
}

const testing = std.testing;

test "an address is IPv4 in dotted decimal or IPv6 in RFC 4291 text, with its port" {
    const port: u16 = 443;
    const v4 = parse_address("127.0.0.1", port).?;
    try testing.expectEqual(udp.Address.Family.ipv4, v4.family);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, v4.bytes[0..udp.Address.ipv4_bytes]);
    try testing.expectEqual(port, v4.port);
    const v6 = parse_address("fd00:cafe:cafe:100::100", port).?;
    try testing.expectEqual(udp.Address.Family.ipv6, v6.family);
    const expected = [_]u8{ 0xfd, 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0x01, 0x00 };
    try testing.expectEqualSlices(u8, &expected, &v6.bytes);
    try testing.expectEqual(port, v6.port);
    const any = parse_address("::", port).?;
    try testing.expectEqual(udp.Address.Family.ipv6, any.family);
    try testing.expectEqual(null, parse_address("127.0.0", port));
    try testing.expectEqual(null, parse_address("256.0.0.1", port));
    try testing.expectEqual(null, parse_address("server4", port));
    try testing.expectEqual(null, parse_address("fe80::1%eth0", port));
}

test "a server holds from 1 to quic_connections_max connections, and names the count in one word" {
    try testing.expectEqual(1, parse_connections("connections=1").?);
    const most = std.fmt.comptimePrint("connections={d}", .{constants.quic_connections_max});
    const too_many = std.fmt.comptimePrint("connections={d}", .{constants.quic_connections_max + 1});
    try testing.expectEqual(constants.quic_connections_max, parse_connections(most).?);
    try testing.expectEqual(null, parse_connections(too_many));
    try testing.expectEqual(null, parse_connections("connections=0"));
    try testing.expectEqual(null, parse_connections("connections="));
    try testing.expectEqual(null, parse_connections("connection=4"));
    try testing.expectEqual(null, parse_connections("once"));
}

test "a server's Unix seconds advance with Rotor's instant, and 0 stays no clock" {
    const started_ns: u64 = 7 * constants.nanoseconds_per_second;
    var server: Server = .{ .address = undefined, .identity_prefix = "", .www = "", .now_seconds = 1_790_000_000 };
    try testing.expectEqual(1_790_000_000, server.seconds_at(started_ns, started_ns));
    const later_ns = started_ns + 90 * constants.nanoseconds_per_second - 1;
    try testing.expectEqual(1_790_000_089, server.seconds_at(started_ns, later_ns));
    server.now_seconds = 0;
    try testing.expectEqual(0, server.seconds_at(started_ns, later_ns));
}

test "a server's clock is one word of Unix seconds, and 0 is no clock" {
    const seconds: u64 = 1_790_000_000;
    try testing.expectEqual(seconds, parse_seconds("seconds=1790000000").?);
    try testing.expectEqual(null, parse_seconds("seconds=0"));
    try testing.expectEqual(null, parse_seconds("seconds="));
    try testing.expectEqual(null, parse_seconds("second=1790000000"));
    try testing.expectEqual(null, parse_seconds("connections=4"));
}
