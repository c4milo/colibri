//! The command line of the test-only client (`client_loop.zig`): where it connects, how many
//! connections it opens, each a `client.ConnectionPool`, how many TCP connections each pool holds, and the
//! plan of exchanges every one of them runs. Split off the loop for length.
const std = @import("std");
const client = @import("client");
const constants = @import("../constants.zig");
const client_exchange = @import("client_exchange.zig");
const alpn = @import("../alpn.zig");

const Plan = client_exchange.Plan;
const Protocol = alpn.Protocol;

/// What the command line asked for.
pub const Run = struct {
    address: [ipv4_octets]u8,
    port: u16,
    authority: []const u8,
    connections_count: u32,
    /// The TCP connections each pool holds at most: `--tcp-connections` (decision 125). An h11
    /// connection carries one exchange at a time, so a plan of several exchanges opens several.
    tcp_connections: u32,
    plans: [constants.requests_max]Plan,
    plans_count: u32,
    /// The prefix of the root's files, which turns the TLS mode on.
    anchor_prefix: ?[]const u8,
    /// Seconds since 1970-01-01T00:00:00Z, the instant chapulin judges the server's chain at. No
    /// file under `src/` reads a clock (non-negotiable 3), so the caller passes it.
    now_seconds: u32,
    /// The protocol every connection speaks in cleartext: h2 with prior knowledge unless `--h11`
    /// says h11. Over TLS, `--h11` offers `http/1.1` alone, and ALPN picks the protocol.
    protocol: Protocol,
    /// Whether `--pool` adds QUIC: the plan goes to one `client.ConnectionPool` (`pool_loop.zig`),
    /// which tries h3 over QUIC first and falls back to TCP, where every other run's pools hold
    /// TCP alone. It needs `--tls`, since h3 serves only "https" origins (RFC 9114 §3.1.2), and runs
    /// one pool, so no `--connections`.
    pool: bool,
    /// How long the pool's QUIC handshake runs before TCP opens beside it: `--fallback-ms`.
    fallback_delay_ns: u64,
    /// Whether the client offers gzip and deflate, and decodes a response coded in either:
    /// `--coded` (decision 101).
    coded: bool,
};

/// How many octets an IPv4 address has (RFC 791 §3.1).
pub const ipv4_octets: usize = 4;

/// The octets of every pool's memory in a run: a pool of one TCP connection for each socket the
/// run may hold. Each TCP connection of a pool adds the same octets, so a run whose sockets fit
/// fits this memory too.
pub const pool_memory_len: usize = constants.client_sockets_max * client.ConnectionPool.memory_bytes(.{});

/// The TCP connections each pool of `run` holds, which its `Config` names.
pub fn pool_tcp_connections(run: *const Run) u16 {
    return @intCast(run.tcp_connections);
}

/// The address a run connects to unless `--address` names another: the loopback, which RFC 1122
/// §3.2.1.3 reserves for the local host.
const loopback_octets = [ipv4_octets]u8{ loopback_first, 0, 0, 1 };
const loopback_first: u8 = 127;

pub const usage =
    \\usage: http-client [--address <ipv4>] [--port <port>] [--authority <name>]
    \\                 [--h11] [--coded] [--tls <anchor-prefix> --seconds <unix-seconds>]
    \\                 [--pool [--fallback-ms <milliseconds>]]
    \\                 [--connections <count>] [--tcp-connections <count>]
    \\                 (--get <path> | --post <path> <octets>)...
    \\
;

/// Reads the command line, or returns null when it names nothing to do or something unreadable.
/// `arguments` gives each word through `next`, as `std.process.Args.Iterator` does.
pub fn read_run(arguments: anytype) ?Run {
    var run: Run = .{
        .address = loopback_octets,
        .port = constants.default_port,
        .authority = "localhost",
        .connections_count = 1,
        .tcp_connections = 1,
        .plans = undefined,
        .plans_count = 0,
        .anchor_prefix = null,
        .now_seconds = 0,
        .protocol = .h2,
        .pool = false,
        .fallback_delay_ns = constants.pool_fallback_delay_ns,
        .coded = false,
    };
    for (0..constants.client_arguments_max) |_| {
        const option = arguments.next() orelse break;
        if (read_flag(&run, option)) continue;
        const value = arguments.next() orelse return null;
        read_option(&run, option, value, arguments) orelse return null;
    }
    return if (run_ok(&run)) run else null;
}

/// Whether the command line names something to do, and says all it needs.
fn run_ok(run: *const Run) bool {
    const connections_ok = run.connections_count > 0 and run.connections_count <= constants.client_connections_max;
    // A webpki chain is valid only at an instant, so the TLS mode needs one.
    const tls_ok = run.anchor_prefix == null or run.now_seconds > 0;
    const pool_ok = !run.pool or (run.anchor_prefix != null and run.connections_count == 1 and run.tcp_connections == 1);
    return run.plans_count > 0 and connections_ok and tls_ok and pool_ok and slots_ok(run);
}

/// Whether the run's pools fit the sockets a run holds.
fn slots_ok(run: *const Run) bool {
    if (run.tcp_connections == 0 or run.tcp_connections > constants.client_tcp_connections_max) return false;
    return run.connections_count * run.tcp_connections <= constants.client_sockets_max;
}

/// Applies an option that takes no value, or returns false when `option` is not one.
fn read_flag(run: *Run, option: []const u8) bool {
    if (std.mem.eql(u8, option, "--h11")) {
        run.protocol = .h11;
        return true;
    }
    if (std.mem.eql(u8, option, "--pool")) {
        run.pool = true;
        return true;
    }
    if (std.mem.eql(u8, option, "--coded")) {
        run.coded = true;
        return true;
    }
    return false;
}

/// Applies one option and its value, or returns null when the client does not know the option.
fn read_option(run: *Run, option: []const u8, value: []const u8, arguments: anytype) ?void {
    const eql = std.mem.eql;
    if (eql(u8, option, "--get")) return add_plan(run, .{ .method = "GET", .path = value, .content_len = 0 });
    if (eql(u8, option, "--post")) {
        const octets = arguments.next() orelse return null;
        const content_len = read_number(octets) orelse return null;
        if (content_len > constants.request_content_len_max) return null;
        return add_plan(run, .{ .method = "POST", .path = value, .content_len = content_len });
    }
    return read_setting(run, option, value);
}

/// Applies one option that sets how the run connects, or returns null when it is not one.
fn read_setting(run: *Run, option: []const u8, value: []const u8) ?void {
    const eql = std.mem.eql;
    if (eql(u8, option, "--connections") or eql(u8, option, "--tcp-connections")) return read_count(run, option, value);
    if (eql(u8, option, "--address")) {
        run.address = read_address(value) orelse return null;
    } else if (eql(u8, option, "--authority")) {
        run.authority = value;
    } else if (eql(u8, option, "--port")) {
        run.port = std.math.cast(u16, read_number(value) orelse return null) orelse return null;
    } else if (eql(u8, option, "--tls")) {
        run.anchor_prefix = value;
    } else if (eql(u8, option, "--seconds")) {
        run.now_seconds = read_number(value) orelse return null;
    } else if (eql(u8, option, "--fallback-ms")) {
        run.fallback_delay_ns = @as(u64, read_number(value) orelse return null) * constants.nanoseconds_per_millisecond;
    } else return null;
}

/// Applies `--connections` or `--tcp-connections`, or returns null when its value is not a
/// number.
fn read_count(run: *Run, option: []const u8, value: []const u8) ?void {
    const count = read_number(value) orelse return null;
    if (std.mem.eql(u8, option, "--connections")) {
        run.connections_count = count;
    } else {
        run.tcp_connections = count;
    }
}

/// An IPv4 address from the command line, or null when it is not one.
fn read_address(text: []const u8) ?[ipv4_octets]u8 {
    const address = std.Io.net.IpAddress.parseIp4(text, 0) catch return null;
    return address.ip4.bytes;
}

/// A decimal number from the command line, or null when it is not one.
fn read_number(text: []const u8) ?u32 {
    return std.fmt.parseInt(u32, text, constants.port_radix) catch null;
}

/// Appends one exchange to the plan, or returns null when the plan is full or the path is empty.
fn add_plan(run: *Run, plan: Plan) ?void {
    if (run.plans_count == constants.requests_max or plan.path.len == 0) return null;
    run.plans[run.plans_count] = plan;
    run.plans_count += 1;
}

const testing = std.testing;

/// A command line as a list of words, which `read_run` reads as it reads the process's. Test-only.
const TestArguments = struct {
    words: []const []const u8,
    index: usize = 0,

    fn next(arguments: *TestArguments) ?[]const u8 {
        if (arguments.index == arguments.words.len) return null;
        defer arguments.index += 1;
        return arguments.words[arguments.index];
    }
};

fn test_read(words: []const []const u8) ?Run {
    var arguments: TestArguments = .{ .words = words };
    return read_run(&arguments);
}

/// The options every pool run of the tests names. Test-only.
const test_tls = [_][]const u8{ "--tls", "prefix", "--seconds", "1", "--get", "/" };

test "--pool needs --tls and runs one pool" {
    try testing.expect(test_read(&[_][]const u8{ "--pool", "--get", "/" }) == null);
    try testing.expect(test_read(&([_][]const u8{ "--pool", "--connections", "2" } ++ test_tls)) == null);
    const run = test_read(&([_][]const u8{"--pool"} ++ test_tls)).?;
    try testing.expect(run.pool and run.connections_count == 1);
    try testing.expectEqual(constants.pool_fallback_delay_ns, run.fallback_delay_ns);
}

test "--fallback-ms sets how long QUIC's handshake runs before TCP opens" {
    const run = test_read(&([_][]const u8{ "--pool", "--fallback-ms", "40" } ++ test_tls)).?;
    try testing.expectEqual(40 * constants.nanoseconds_per_millisecond, run.fallback_delay_ns);
    try testing.expect(test_read(&([_][]const u8{ "--pool", "--fallback-ms", "soon" } ++ test_tls)) == null);
}

test "decision 125: --tcp-connections sets each pool's TCP slots, within the sockets of a run" {
    const one = test_read(&[_][]const u8{ "--get", "/" }).?;
    try testing.expectEqual(1, one.tcp_connections);
    const many = test_read(&[_][]const u8{ "--tcp-connections", "8", "--get", "/" }).?;
    try testing.expectEqual(8, pool_tcp_connections(&many));
    try testing.expect(test_read(&[_][]const u8{ "--tcp-connections", "0", "--get", "/" }) == null);
    try testing.expect(test_read(&[_][]const u8{ "--tcp-connections", "17", "--get", "/" }) == null);
    // 4 pools of 16 slots hold every socket a run holds, and 5 hold more.
    const full = test_read(&[_][]const u8{ "--connections", "4", "--tcp-connections", "16", "--get", "/" }).?;
    try testing.expect(full.connections_count * client.ConnectionPool.memory_bytes(.{ .tcp_connections = pool_tcp_connections(&full) }) <= pool_memory_len);
    try testing.expect(test_read(&[_][]const u8{ "--connections", "5", "--tcp-connections", "16", "--get", "/" }) == null);
    // `--pool` holds one TCP connection.
    try testing.expect(test_read(&([_][]const u8{ "--pool", "--tcp-connections", "2" } ++ test_tls)) == null);
}
