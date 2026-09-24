//! The command line of `zig build quic-udp` (design §8 step 9e, piece 11):
//!
//!     quic-udp server <ipv4> <port> <identity-prefix> <www> [once] [connections=<n>]
//!     quic-udp client <ipv4> <port> <anchor-prefix> <hostname> <unix-seconds> <downloads> <path>...
//!
//! The server binds `<ipv4>:<port>` and serves `<www>`. With `once` it exits when its first
//! connection ends, and `connections=<n>` holds at most n connections at once, from 1 to
//! `quic_connections_max`, which is also the count without it. The client sends to
//! `<ipv4>:<port>` and fetches each path into `<downloads>`.
//! The instant is a clock the command line cannot give, so it comes from Rotor (decision 63); the
//! Unix seconds are the certificate check's, which the caller reads (non-negotiable 3).
const std = @import("std");
const constants = @import("../../constants.zig");
const check_file = @import("../../tls/check_file.zig");
const hq = @import("../hq/hq.zig");

pub const Role = enum { server, client };

pub const Server = struct {
    address: [ipv4_octets]u8,
    port: u16,
    /// The prefix of the files `tools/h2_interop/tls_identity.go` wrote.
    identity_prefix: []const u8,
    www: []const u8,
    once: bool = false,
    /// The connections the server holds at once.
    connections: usize = constants.quic_connections_max,
};

pub const Client = struct {
    address: [ipv4_octets]u8,
    port: u16,
    anchor_prefix: []const u8,
    hostname: []const u8,
    now_seconds: u64,
    downloads: []const u8,
    paths: []const []const u8,
};

pub const Arguments = union(Role) {
    server: Server,
    client: Client,
};

/// How many octets an IPv4 address has (RFC 791 §3.1).
pub const ipv4_octets: usize = 4;
/// The radix every number on the command line is written in.
const decimal: u8 = 10;

var paths_storage: [constants.hq_paths_max][]const u8 = undefined;

pub fn parse(init: std.process.Init.Minimal) Arguments {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.next();
    const role = std.meta.stringToEnum(Role, arguments.next() orelse usage()) orelse usage();
    const address = parse_ipv4(arguments.next() orelse usage()) orelse usage();
    const port = std.fmt.parseUnsigned(u16, arguments.next() orelse usage(), decimal) catch usage();
    return switch (role) {
        .server => .{ .server = parse_server(&arguments, address, port) },
        .client => .{ .client = parse_client(&arguments, address, port) },
    };
}

fn parse_server(arguments: *std.process.Args.Iterator, address: [ipv4_octets]u8, port: u16) Server {
    var server: Server = .{
        .address = address,
        .port = port,
        .identity_prefix = arguments.next() orelse usage(),
        .www = arguments.next() orelse usage(),
    };
    // Bounded by the options there are, each of which may appear once.
    for (0..server_options_count) |_| {
        const word = arguments.next() orelse return server;
        if (std.mem.eql(u8, word, "once")) {
            server.once = true;
        } else {
            server.connections = parse_connections(word) orelse usage();
        }
    }
    if (arguments.next() != null) usage();
    return server;
}

/// `once` and `connections=<n>`.
const server_options_count: usize = 2;

const connections_prefix = "connections=";

/// The count of `connections=<n>`, or null for any other word, or for a count the table cannot
/// hold: from 1 to `quic_connections_max`.
fn parse_connections(word: []const u8) ?usize {
    if (!std.mem.startsWith(u8, word, connections_prefix)) return null;
    const count = std.fmt.parseUnsigned(usize, word[connections_prefix.len..], decimal) catch return null;
    if (count == 0 or count > constants.quic_connections_max) return null;
    return count;
}

fn parse_client(arguments: *std.process.Args.Iterator, address: [ipv4_octets]u8, port: u16) Client {
    const anchor_prefix = arguments.next() orelse usage();
    const hostname = arguments.next() orelse usage();
    const now_seconds = std.fmt.parseUnsigned(u64, arguments.next() orelse usage(), decimal) catch usage();
    const downloads = arguments.next() orelse usage();
    var count: usize = 0;
    // Bounded by `hq_paths_max`.
    while (arguments.next()) |path| {
        if (count == paths_storage.len) usage();
        var line: [constants.hq_request_len_max]u8 = undefined;
        // Each path is checked once here, so the client never builds a request it must refuse.
        _ = hq.write_request(path, &line) catch usage();
        paths_storage[count] = path;
        count += 1;
    }
    if (count == 0) usage();
    return .{
        .address = address,
        .port = port,
        .anchor_prefix = anchor_prefix,
        .hostname = hostname,
        .now_seconds = now_seconds,
        .downloads = downloads,
        .paths = paths_storage[0..count],
    };
}

/// Four decimal octets separated by dots, or null.
fn parse_ipv4(text: []const u8) ?[ipv4_octets]u8 {
    var octets: [ipv4_octets]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&octets) |*octet| {
        octet.* = std.fmt.parseUnsigned(u8, parts.next() orelse return null, decimal) catch return null;
    }
    if (parts.next() != null) return null;
    return octets;
}

pub fn usage() noreturn {
    std.debug.print(
        "usage: quic-udp server <ipv4> <port> <identity-prefix> <www> [once] [connections=<n>]\n" ++
            "       quic-udp client <ipv4> <port> <anchor-prefix> <hostname> <unix-seconds> <downloads> <path>...\n",
        .{},
    );
    std.process.exit(check_file.exit_usage);
}

const testing = std.testing;

test "an IPv4 address is four decimal octets" {
    try testing.expectEqual([ipv4_octets]u8{ 127, 0, 0, 1 }, parse_ipv4("127.0.0.1").?);
    try testing.expectEqual(null, parse_ipv4("127.0.0"));
    try testing.expectEqual(null, parse_ipv4("127.0.0.1.1"));
    try testing.expectEqual(null, parse_ipv4("256.0.0.1"));
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
