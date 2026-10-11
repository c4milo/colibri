//! The socket around `server/server_session.zig`: the server of design §9, which `tools/h2spec.sh`
//! runs the pinned h2spec against and h2load measures. Each connection is a connection of colibri's
//! `server` module (design §8 step 17a). `zig build http-server -- --port <port>` runs it in
//! cleartext, where a connection speaks h2 when its first octets are h2's preface and h11 otherwise
//! (decision 117), or one alone with `--h11` or `--h2`. With `--tls <identity-prefix>` it serves
//! TLS instead, through `tls.record.Server`: it offers `h2` and `http/1.1` through ALPN, or one
//! alone with `--h11` or `--h2`, and each connection speaks what its handshake selected (decision
//! 88).
//!
//! One worker per core, sharing nothing. Each worker has its own Rotor loop and its own listening
//! socket on the same port, bound with SO_REUSEPORT, so the kernel hands each new connection to
//! one worker and no worker reads another's memory: no lock, no atomic and no queue between cores
//! (CLAUDE.md, Performance). A worker holds its connections in a fixed array.
//!
//! No call here waits but the loop's `tick`, one system call per turn (decisions 46 and 58). A
//! worker keeps one accept in flight while it has a free slot, and each connection at most one
//! receive, one send and, at its end, one close. A peer that stops reading holds up only its own
//! connection: its octets wait in that connection's buffer.
//!
//! Each connection runs on the instant the loop read at its last tick, which reads no clock of
//! its own (decision 63), and a tick waits no longer than the soonest deadline of a connection
//! (decision 110), which then gets the instant through `on_instant`.
//!
//! A receive writes into `received`, and its octets are appended to `input` when its event
//! arrives. The session consumes `input` from the front, which moves what is left, and Rotor owns
//! a receive's buffer until its final event (its rule 3), so a receive never targets `input`.
//! A send reads `output[output_sent..output_len]`, and the session only appends after that.
//!
//! The socket side holds no protocol rule: it reads octets into a buffer, hands them to a session,
//! writes back what the session produced, and closes when the session says it is done (RFC 9113
//! §5.4.1). Nothing here allocates: every worker, connection and buffer is in static storage
//! sized by `constants.zig`, and each loop runs on memory its worker holds.
//!
//! This file reads the command line and starts the workers. Its pieces are in `server/`:
//! `server_options.zig` reads the command line, `server_mode.zig` holds what it asked for,
//! `server_worker.zig` is one worker and its loop, `server_socket.zig` one connection's socket and
//! buffers, and `server_session.zig` one connection with no socket in it.
//!
//! The TLS mode runs one worker. chapulin's generator is one process-wide state with no lock
//! (its `drbg.h`), so two threads must not run handshakes at once.
const std = @import("std");
const entropy = @import("entropy.zig");
const cpu = @import("cpu.zig");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const alpn = @import("alpn.zig");
const server_mode = @import("server/server_mode.zig");
const server_options = @import("server/server_options.zig");
const server_worker = @import("server/server_worker.zig");
const server_identity = @import("tls/server_identity.zig");
const server = @import("server");

const Protocol = alpn.Protocol;

/// Runs one worker per core until the process is stopped, every one listening on one port:
/// `port`, or the port the kernel chose when `port` is 0.
pub fn listen_and_serve(port: u16) !void {
    const cores = std.Thread.getCpuCount() catch 1;
    // One worker in the TLS mode: see the header.
    const count = if (server_mode.tls_shared != null) 1 else @max(1, @min(cores, constants.workers_max));
    const bound = try server_worker.bind_listeners(port, count);
    // A script reads the port from this line, and connects once it is out: every listener is bound.
    std.debug.print("http-server: listening on port {d}, rotor backend {t}\n", .{ bound, rotor.backend() });
    var threads: [constants.workers_max]?std.Thread = @splat(null);
    for (1..count) |index| {
        threads[index] = std.Thread.spawn(.{}, server_worker.run, .{index}) catch null;
        // A listener with no worker would keep the connections the kernel hands it.
        if (threads[index] == null) rotor.sync.close_now(server_worker.workers[index].listener);
    }
    // The main thread is a worker too, so a one-core host spawns nothing.
    try server_worker.run(0);
    for (threads[1..count]) |thread| {
        if (thread) |handle| handle.join();
    }
}

/// Runs the server: `zig build http-server -- [options]` (`server/server_options.zig`).
pub fn main(init: std.process.Init.Minimal) !void {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.skip();
    const options = server_options.read(&arguments) orelse {
        std.debug.print(server_options.usage, .{});
        std.process.exit(exit_usage);
    };
    server_mode.versions = versions_of(options.alone);
    server_mode.listen_address = options.address;
    server_mode.echo_mode = options.echo;
    server_mode.coded_mode = options.coded;
    if (options.h3_port) |port| server_mode.h3_alternative = .{ .port = port };
    if (options.identity_prefix) |prefix| try load_tls(prefix, options.alone);
    try listen_and_serve(options.port);
}

/// The versions the server speaks: `alone` by itself, or h11 and h2 when it is null (decision 117).
fn versions_of(alone: ?Protocol) server.Versions {
    const protocol = alone orelse return .{};
    return switch (protocol) {
        .h11 => .{ .h2 = false },
        .h2 => .{ .h11 = false },
    };
}

/// Loads the identity, converts what every TLS connection borrows, and runs chapulin's check on
/// the identity once. With `--h11` the server offers `http/1.1` alone, and with `--h2` `h2` alone.
fn load_tls(prefix: []const u8, alone: ?Protocol) !void {
    server_identity.seed(&server_mode.tls_identity);
    const protocols: []const []const u8 = if (alone) |protocol| switch (protocol) {
        .h11 => &alpn.alpn_h11,
        .h2 => &alpn.alpn_h2,
    } else &alpn.alpn_both;
    try server_mode.tls_config.init(try server_identity.load(prefix, &server_mode.tls_identity, protocols));
    try server_mode.tls_config.check(entropy.random());
    server_mode.tls_shared = &server_mode.tls_config;
    // A log names what the sessions were told of the CPU, which decides the suites they hold.
    cpu.print("http-server");
}

/// The exit status of a run asked for something this build cannot do.
const exit_usage: u8 = 2;
