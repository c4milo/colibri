//! The command line of the test-only client (`client_loop.zig`): where it connects, how many
//! connections it opens, and the plan of exchanges every one of them runs. Split off the loop for
//! length.
const std = @import("std");
const constants = @import("../constants.zig");
const client_exchange = @import("client_exchange.zig");

const Plan = client_exchange.Plan;

/// What the command line asked for.
pub const Run = struct {
    address: [ipv4_octets]u8,
    port: u16,
    authority: []const u8,
    connections_count: u32,
    plans: [constants.exchanges_max]Plan,
    plans_count: u32,
    /// The prefix of the root's files, which turns the TLS mode on.
    anchor_prefix: ?[]const u8,
    /// Seconds since 1970-01-01T00:00:00Z, the instant chapulin judges the server's chain at. No
    /// file under `src/` reads a clock (non-negotiable 3), so the caller passes it.
    now_seconds: u32,
};

/// How many octets an IPv4 address has (RFC 791 §3.1).
pub const ipv4_octets: usize = 4;

/// The address a run connects to unless `--address` names another: the loopback, which RFC 1122
/// §3.2.1.3 reserves for the local host.
const loopback_octets = [ipv4_octets]u8{ loopback_first, 0, 0, 1 };
const loopback_first: u8 = 127;

pub const usage =
    \\usage: http-client [--address <ipv4>] [--port <port>] [--authority <name>]
    \\                 [--tls <anchor-prefix> --seconds <unix-seconds>]
    \\                 [--connections <count>] (--get <path> | --post <path> <octets>)...
    \\
;

/// Reads the command line, or returns null when it names nothing to do or something unreadable.
pub fn read_run(arguments: *std.process.Args.Iterator) ?Run {
    var run: Run = .{
        .address = loopback_octets,
        .port = constants.default_port,
        .authority = "localhost",
        .connections_count = 1,
        .plans = undefined,
        .plans_count = 0,
        .anchor_prefix = null,
        .now_seconds = 0,
    };
    for (0..constants.client_arguments_max) |_| {
        const option = arguments.next() orelse break;
        const value = arguments.next() orelse return null;
        read_option(&run, option, value, arguments) orelse return null;
    }
    const connections_ok = run.connections_count > 0 and run.connections_count <= constants.client_connections_max;
    // A webpki chain is valid only at an instant, so the TLS mode needs one.
    const tls_ok = run.anchor_prefix == null or run.now_seconds > 0;
    return if (run.plans_count > 0 and connections_ok and tls_ok) run else null;
}

/// Applies one option and its value, or returns null when the client does not know the option.
fn read_option(run: *Run, option: []const u8, value: []const u8, arguments: *std.process.Args.Iterator) ?void {
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
    if (eql(u8, option, "--address")) {
        run.address = read_address(value) orelse return null;
    } else if (eql(u8, option, "--authority")) {
        run.authority = value;
    } else if (eql(u8, option, "--port")) {
        run.port = std.math.cast(u16, read_number(value) orelse return null) orelse return null;
    } else if (eql(u8, option, "--connections")) {
        run.connections_count = read_number(value) orelse return null;
    } else if (eql(u8, option, "--tls")) {
        run.anchor_prefix = value;
    } else if (eql(u8, option, "--seconds")) {
        run.now_seconds = read_number(value) orelse return null;
    } else return null;
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
    if (run.plans_count == constants.exchanges_max or plan.path.len == 0) return null;
    run.plans[run.plans_count] = plan;
    run.plans_count += 1;
}
