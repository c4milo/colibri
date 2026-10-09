//! The UDP server's `h3` mode (design §8 step 17b): every connection runs on colibri's `server`
//! module, which a `server.Endpoint` holds, and `udp_h3_files.zig` answers each request.
//!
//! Each turn waits in Rotor's `tick` until a datagram arrives or a connection's next deadline
//! passes, then reads the instant that tick read (decision 63). It hands each datagram to the
//! endpoint, which routes it (RFC 9000 §5.2) or starts a connection from it, fires every deadline,
//! answers each event the endpoint reports, by its connection's slot, and sends what the endpoint
//! owes. A sent datagram's
//! octets belong to Rotor until its send's event (Rotor's rule 3), so each is built in a slot of
//! its own, and a datagram Rotor has no room for is one lost on the way, which RFC 9002 recovers.
//!
//! With `qlogdir`, each connection writes its qlog there: the endpoint asks its log provider for a
//! log as each connection starts, and hands it back once the connection is over (decision 102 as
//! amended). Each turn writes what every open log took.
const std = @import("std");
const quic = @import("quic");
const server = @import("server");
const constants = @import("../../constants.zig");
const udp = @import("../../udp.zig");
const entropy = @import("../../entropy.zig");
const check_file = @import("../../tls/check_file.zig");
const udp_peer = @import("udp_peer.zig");
const udp_arguments = @import("udp_arguments.zig");
const udp_identity = @import("udp_identity.zig");
const udp_h3_files = @import("udp_h3_files.zig");
const udp_qlog = @import("udp_qlog.zig");

const Endpoint = udp_h3_files.Endpoint;

var endpoint: Endpoint align(@alignOf(Endpoint)) = undefined;
var quic_config: server.QuicConfig align(@alignOf(server.QuicConfig)) = undefined;
var endpoint_config: server.EndpointConfig align(@alignOf(server.EndpointConfig)) = undefined;
/// The files each connection serves, at its slot in the endpoint.
var files: [constants.quic_connections_max]udp_h3_files.Files align(@alignOf(udp_h3_files.Files)) = undefined;
var events: [constants.udp_operations_max]udp.Event align(@alignOf(udp.Event)) = undefined;
var slots: [constants.udp_send_slots][constants.quic_datagram_len_max]u8 = undefined;
var slot_busy: [constants.udp_send_slots]bool = @splat(false);
/// Where each slot's datagram goes, which its send reads until its event (Rotor's rule 3).
var slot_outbound: [constants.udp_send_slots]udp.Outbound align(@alignOf(udp.Outbound)) = undefined;
/// Connections that failed, which fail the run unless the server was asked to expect them
/// (`errors`), files the ended connections served, and the connections that ended.
var connection_errors: u64 = 0;
var served: u64 = 0;
var ended: u64 = 0;
/// The logs the endpoint's provider gives out, whether each is in use, and the directory their
/// files go in, null for a run that logs nothing.
var qlogs: [constants.quic_connections_max]udp_qlog.Qlog align(@alignOf(udp_qlog.Qlog)) = undefined;
var qlog_in_use: [constants.quic_connections_max]bool = @splat(false);
var qlog_directory: ?[]const u8 = null;
var log_context: u8 = 0;
const log_vtable: server.LogProvider.VTable = .{ .open = open_log, .close = close_log };

/// Serves until the run is over: with `once`, the first connection's end; without it, the ticks
/// running out.
pub fn serve(asked: udp_arguments.Server, socket: *udp.Endpoint, started_ns: u64) void {
    quic_config = .{
        .tls = udp_identity.server_tls(),
        .ecn = asked.ecn,
        .idle_timeout_ms = constants.quic_idle_timeout_ms,
        .switch_to = asked.switch_to,
    };
    qlog_directory = asked.qlogdir;
    endpoint_config = .{
        .quic = &quic_config,
        .retry = if (asked.retry) udp_identity.retry_config() else null,
        .logs = if (asked.qlogdir != null) .{ .context = &log_context, .vtable = &log_vtable } else null,
    };
    endpoint.init(&endpoint_config, entropy.random(), asked.now_seconds, started_ns) catch |failure| fail("the endpoint did not start: {t}", .{failure});
    for (&files) |*held| held.init(asked.www);
    for (0..constants.quic_run_ticks_max) |_| {
        const ready = socket.tick(&events, wait_ns(socket)) catch |failure| fail("the tick failed: {t}", .{failure});
        const now_ns = socket.now_ns();
        const ended_before = ended;
        for (ready) |event| on_event(asked, socket, event, now_ns);
        endpoint.on_instant(now_ns);
        take(asked, .none, now_ns);
        flush(socket, now_ns);
        write_logs();
        if (asked.once and ended > ended_before) break;
    }
    close_logs();
    socket.close() catch |failure| fail("the socket did not close: {t}", .{failure});
    std.debug.print("quic-udp: served {d} files, {d} connection errors\n", .{ served, connection_errors });
}

/// How long the next tick may wait: until the endpoint's next deadline, and never longer than
/// `quic_tick_wait_ns_max`.
fn wait_ns(socket: *const udp.Endpoint) u64 {
    const deadline_ns = endpoint.deadline_ns() orelse return constants.quic_tick_wait_ns_max;
    return @min(constants.quic_tick_wait_ns_max, deadline_ns -| socket.now_ns());
}

fn on_event(asked: udp_arguments.Server, socket: *udp.Endpoint, event: udp.Event, now_ns: u64) void {
    if (event.user_data != udp.receive_user_data) {
        // A send's event gives its slot back.
        slot_busy[@intCast(event.user_data)] = false;
        return;
    }
    if (event.flags.buffer) {
        const delivery = socket.delivery(event);
        const ecn = udp_peer.received_ecn(&delivery.from);
        take(asked, .{ .datagram = .{ .octets = delivery.bytes, .ecn = ecn, .from = udp_peer.peer_address(delivery.from.peer) } }, now_ns);
    }
    socket.finish_receive(event);
}

/// Passes `input` to the endpoint, then answers every event it reports until it reports none.
fn take(asked: udp_arguments.Server, input: server.Input, now_ns: u64) void {
    var rest = input;
    for (0..constants.h3_endpoint_events_max) |_| {
        const reported = endpoint.receive(rest, now_ns).event orelse return;
        rest = .none;
        switch (reported) {
            .ended => |over| end(asked, over),
            // A QUIC connection owes no `send` or `close`, and the run never shuts the endpoint
            // down.
            .send, .close, .closed => unreachable,
            inline else => |carried| files[carried.id.connection.slot].on_event(&endpoint, reported),
        }
    }
}

/// Counts what a connection that is over served, and empties its slot's table for a later client.
/// A connection that failed ends the run unless the server was asked to expect it: a suite such as
/// h3spec breaks a rule on purpose on every connection it opens.
fn end(asked: udp_arguments.Server, over: server.Ended) void {
    const held = &files[over.connection.slot];
    served += held.served;
    held.reset();
    ended += 1;
    if (!over.failed) return;
    connection_errors += 1;
    if (!asked.errors) fail("a connection ended on a connection error", .{});
}

/// Sends every datagram the endpoint owes now, each from a free slot.
fn flush(socket: *udp.Endpoint, now_ns: u64) void {
    for (&slots, 0..) |*slot, index| {
        if (slot_busy[index]) continue;
        const sent = endpoint.send_datagram(slot, now_ns) orelse return;
        slot_outbound[index] = outbound(sent);
        if (socket.send(index, sent.octets, &slot_outbound[index])) slot_busy[index] = true;
    }
}

/// Where a datagram goes, asking Rotor to set the codepoint colibri named (decision 68).
fn outbound(sent: server.Sent) udp.Outbound {
    const ecn = udp_peer.sent_ecn(sent.ecn);
    return .{
        .peer = udp_peer.udp_address(sent.to),
        .local = undefined,
        .segment_bytes = 0,
        .ecn = ecn,
        .flags = .{ .peer = true, .ecn = ecn != .not_ect },
    };
}

/// The endpoint's log provider: a free log, whose file is named for the connection (main schema
/// §12.1), or null when every log is in use or the file cannot be created.
fn open_log(context: *anyopaque, original_destination: []const u8, now_ns: u64) ?*quic.qlog.Log {
    _ = context;
    for (&qlogs, &qlog_in_use) |*qlog, *in_use| {
        if (in_use.*) continue;
        const log = qlog.open(qlog_directory, .server, original_destination, now_ns) orelse return null;
        in_use.* = true;
        return log;
    }
    return null;
}

/// Writes the rest of a connection's log and closes its file, once the endpoint hands it back.
fn close_log(context: *anyopaque, log: *quic.qlog.Log) void {
    _ = context;
    for (&qlogs, &qlog_in_use) |*qlog, *in_use| {
        if (!in_use.* or &qlog.log != log) continue;
        qlog.close();
        in_use.* = false;
        return;
    }
    unreachable;
}

/// Writes what each open log took this turn (decision 102).
fn write_logs() void {
    for (&qlogs, qlog_in_use) |*qlog, in_use| {
        if (in_use) qlog.write();
    }
}

/// Closes every log still open, when the run ends or fails, so a failed run leaves its qlogs.
fn close_logs() void {
    for (&qlogs, &qlog_in_use) |*qlog, *in_use| {
        if (!in_use.*) continue;
        qlog.close();
        in_use.* = false;
    }
}

fn fail(comptime format: []const u8, values: anytype) noreturn {
    close_logs();
    std.debug.print("quic-udp: " ++ format ++ "\n", values);
    std.process.exit(check_file.exit_failed);
}
