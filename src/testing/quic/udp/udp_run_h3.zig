//! The UDP server's `h3` mode (design §8 step 17b): every connection runs on colibri's `server`
//! module, which a `server.Engine` holds, and `udp_h3_files.zig` answers each request.
//!
//! Each turn waits in Rotor's `tick` until a datagram arrives or a connection's next deadline
//! passes, then reads the instant that tick read (decision 63). It hands each datagram to the
//! engine, which routes it (RFC 9000 §5.2) or starts a connection from it, fires every deadline,
//! answers each event the engine reports, by its connection's slot, and sends what the engine
//! owes. A sent datagram's
//! octets belong to Rotor until its send's event (Rotor's rule 3), so each goes into a batch of its
//! peer's, which holds it until then, and a datagram Rotor has no room for is one lost on the way,
//! which RFC 9002 recovers.
//!
//! On Linux the socket asks the kernel to coalesce datagrams (UDP_GRO), and each batch goes out as
//! one segmented send (UDP_SEGMENT, `udp_batch.zig`, design §8 step 13f.6). Rotor splits what the
//! kernel coalesced, so each delivery holds one datagram (Rotor's decision 15 as amended).
//!
//! With `qlogdir`, each connection writes its qlog there: the engine asks its log provider for a
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
const udp_batch = @import("udp_batch.zig");
const server_routes = @import("../../server/server_routes.zig");

const Engine = udp_h3_files.Engine;

var engine: Engine align(@alignOf(Engine)) = undefined;
var engine_config: server.Config align(@alignOf(server.Config)) = undefined;
/// The files each connection serves, at its slot in the engine.
var files: [constants.quic_connections_max]udp_h3_files.Files align(@alignOf(udp_h3_files.Files)) = undefined;
/// The files every connection's table keeps mapped for the run.
var mapped: udp_h3_files.Mapped align(@alignOf(udp_h3_files.Mapped)) = .{};
var events: [constants.udp_operations_max]udp.Event align(@alignOf(udp.Event)) = undefined;
/// The datagram the engine writes, before it joins its peer's batch.
var datagram: [constants.quic_datagram_len_max]u8 = undefined;
var batches: udp_batch.Batches align(@alignOf(udp_batch.Batches)) = .{};
/// Where each batch goes, which its send reads until its event (Rotor's rule 3).
var batch_outbound: [constants.udp_batches]udp.Outbound align(@alignOf(udp.Outbound)) = undefined;
/// Connections that failed, which fail the run unless the server was asked to expect them
/// (`errors`), files the ended connections served, and the connections that ended.
var connection_errors: u64 = 0;
var served: u64 = 0;
var ended: u64 = 0;
/// The logs the engine's provider gives out, whether each is in use, and the directory their
/// files go in, null for a run that logs nothing.
var qlogs: [constants.quic_connections_max]udp_qlog.Qlog align(@alignOf(udp_qlog.Qlog)) = undefined;
var qlog_in_use: [constants.quic_connections_max]bool = @splat(false);
var qlog_directory: ?[]const u8 = null;
var log_context: u8 = 0;
/// The router of `routes=github`, which answers every request in place of `files` (design §8 step
/// 13f).
var route_pool: server_routes.Pool align(@alignOf(server_routes.Pool)) = undefined;
const log_vtable: server.LogProvider.VTable = .{ .open = open_log, .close = close_log };

/// Serves until the run is over: with `once`, the first connection's end; without it, the ticks
/// running out.
pub fn serve(asked: udp_arguments.Server, socket: *udp.Endpoint, started_ns: u64) void {
    start(asked, started_ns);
    for (0..constants.quic_run_ticks_max) |_| {
        const ready = socket.tick(&events, wait_ns(socket)) catch |failure| fail("the tick failed: {t}", .{failure});
        const now_ns = socket.now_ns();
        const ended_before = ended;
        for (ready) |event| on_event(asked, socket, event, now_ns);
        engine.on_instant(now_ns);
        take(asked, .none, now_ns);
        flush(socket, now_ns);
        write_logs();
        if (asked.once and ended > ended_before) break;
    }
    close_logs();
    socket.close() catch |failure| fail("the socket did not close: {t}", .{failure});
    // The controller the engine gave its connections, which tools/quic_udp.sh checks (decision 136).
    std.debug.print("quic-udp: served {d} files, {d} connection errors, controller {t}\n", .{ served, connection_errors, engine_config.congestion_controller });
}

/// Starts the engine, the files of `<www>`, with `routes=github` the router's pool, and the
/// batches, which hold one datagram each with `no-gso`.
fn start(asked: udp_arguments.Server, started_ns: u64) void {
    qlog_directory = asked.qlogdir;
    engine_config = .{
        .tls = udp_identity.server_identity(),
        .ecn = asked.ecn,
        .idle_timeout_ms = constants.quic_idle_timeout_ms,
        .switch_to = asked.switch_to,
        .congestion_controller = if (asked.bbr) .bbr else if (asked.newreno) .newreno else .cubic,
        .retry = if (asked.retry) udp_identity.retry_config() else null,
        .logs = if (asked.qlogdir != null) .{ .context = &log_context, .vtable = &log_vtable } else null,
    };
    engine.init(&engine_config, entropy.random(), .{ .ns = started_ns, .unix_seconds = asked.now_seconds }) catch |failure| fail("the engine did not start: {t}", .{failure});
    for (&files) |*held| held.init(asked.www, &mapped);
    if (asked.routes) route_pool = .{};
    batches = .of(asked.segments);
}

/// How long the next tick may wait: until the engine's next deadline, and never longer than
/// `quic_tick_wait_ns_max`.
fn wait_ns(socket: *const udp.Endpoint) u64 {
    const deadline_ns = engine.deadline_ns() orelse return constants.quic_tick_wait_ns_max;
    return @min(constants.quic_tick_wait_ns_max, deadline_ns -| socket.now_ns());
}

fn on_event(asked: udp_arguments.Server, socket: *udp.Endpoint, event: udp.Event, now_ns: u64) void {
    if (event.user_data != udp.receive_user_data) {
        // A send's event gives its batch back.
        batches.release(@intCast(event.user_data));
        return;
    }
    if (event.flags.buffer) take_delivery(asked, socket.delivery(event), now_ns);
    socket.finish_receive(event);
}

/// Hands the engine the datagram of a delivery, which holds one (Rotor's decision 15 as
/// amended). A delivery cut short is dropped, as a lost datagram is.
fn take_delivery(asked: udp_arguments.Server, delivery: udp.Delivery, now_ns: u64) void {
    std.debug.assert(delivery.from.segment_bytes == 0);
    if (delivery.from.flags.truncated) return;
    const ecn = udp_peer.received_ecn(&delivery.from);
    const from = udp_peer.peer_address(delivery.from.peer);
    take(asked, .{ .datagram = .{ .bytes = delivery.bytes, .ecn = ecn, .from = from } }, now_ns);
}

/// Passes `input` to the engine, then answers every event it reports until it reports none.
fn take(asked: udp_arguments.Server, input: server.Input, now_ns: u64) void {
    var rest = input;
    for (0..constants.h3_endpoint_events_max) |_| {
        const reported = engine.receive(rest, now_ns).event orelse return;
        rest = .none;
        switch (reported) {
            .ended => |over| end(asked, over),
            // A QUIC connection owes no `send` or `close`, and the run never shuts the engine
            // down.
            .send, .close, .closed => unreachable,
            inline else => |carried| if (asked.routes) {
                var context: void = {};
                const handled = route_pool.handle(&context, &engine, reported);
                std.debug.assert(handled == .taken);
            } else files[carried.id.connection.slot].on_event(&engine, reported),
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

/// Sends every datagram the engine owes now, while a batch is free to take it, in one send for
/// each batch.
fn flush(socket: *udp.Endpoint, now_ns: u64) void {
    // Bounded: each pass adds one datagram, and the batches hold at most this many.
    for (0..constants.udp_batches * constants.udp_segments_max) |_| {
        if (!batches.has_free()) break;
        const sent = engine.send_datagram(&datagram, now_ns) orelse break;
        batches.add(sent);
    }
    for (&batches.batches, 0..) |*batch, index| {
        if (batch.state != .open) continue;
        batch_outbound[index] = outbound(batch);
        // A batch Rotor has no room for is freed, and its datagrams are lost on the way.
        batch.state = if (socket.send(index, batch.bytes[0..batch.len], &batch_outbound[index])) .sending else .free;
    }
}

/// Where a batch goes, asking Rotor to set the codepoint colibri named (decision 68), and to cut
/// it into segments of its first datagram's length.
fn outbound(batch: *const udp_batch.Batch) udp.Outbound {
    const ecn = udp_peer.sent_ecn(batch.ecn);
    return .{
        .peer = udp_peer.udp_address(batch.to),
        .local = undefined,
        .segment_bytes = batch.segment_bytes(),
        .ecn = ecn,
        .flags = .{ .peer = true, .ecn = ecn != .not_ect },
    };
}

/// The engine's log provider: a free log, whose file is named for the connection (main schema
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

/// Writes the rest of a connection's log and closes its file, once the engine hands it back.
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
