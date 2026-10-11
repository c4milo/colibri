//! The server of design §9, which `tools/h2spec.sh` runs the pinned h2spec against and h2load
//! measures. Every connection is served by colibri's `server` module, through one
//! `server.Endpoint` for each worker (design §8 step 21b.6, decision 119). `zig build http-server
//! -- --port <port>` runs it in cleartext, where a connection speaks h2 when its first octets are
//! h2's preface and h11 otherwise (decision 117), or one alone with `--h11` or `--h2`. With `--tls
//! <identity-prefix>` it serves TLS instead: the endpoint offers `h2` and `http/1.1` through ALPN,
//! or one alone with `--h11` or `--h2`, and each connection speaks what its handshake selected
//! (decision 88).
//!
//! One worker per core, sharing nothing. Each worker has its own Rotor loop, its own listening
//! socket on the same port, bound with SO_REUSEPORT, and its own endpoint, so the kernel hands
//! each new connection to one worker and no worker reads another's memory: no lock, no atomic and
//! no queue between cores (CLAUDE.md, Performance). A worker holds its sockets in a fixed array.
//!
//! No call here waits but the loop's `tick`, one system call per turn (decisions 46 and 58). A
//! worker keeps one accept in flight while it has a free socket, and each socket at most one
//! receive, one send and, at its end, one close. A peer that stops reading holds up only its own
//! connection: its octets wait in that socket's buffer.
//!
//! Each connection runs on the instant the loop read at its last tick, which reads no clock of
//! its own (decision 63), and a tick waits no longer than the endpoint's soonest deadline
//! (decision 110), which the endpoint then gets through `on_instant`.
//!
//! The socket side holds no protocol rule: it reads octets into a buffer, hands them to the
//! worker's session, writes back what the session produced, and closes a socket when the endpoint
//! says so (RFC 9113 §5.4.1) or its peer left. Nothing here allocates: every worker, socket and
//! buffer is in static storage sized by `constants.zig`, and each loop runs on memory its worker
//! holds.
//!
//! This file reads the command line and starts the workers. Its pieces are in `server/`:
//! `server_options.zig` reads the command line, `server_mode.zig` holds what it asked for,
//! `server_worker.zig` is one worker and its loop, `server_socket.zig` one socket and its buffers,
//! `server_session.zig` the worker's endpoint and the connections it serves, with no socket in
//! them, and `server_session_answer.zig` the responses one connection owes.
//!
//! The TLS mode runs one worker. chapulin's generator is one process-wide state with no lock
//! (its `drbg.h`), so two threads must not run handshakes at once.
const std = @import("std");
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
    const count = if (server_mode.identity != null) 1 else @max(1, @min(cores, constants.workers_max));
    // Each endpoint builds its TLS configuration and checks that the identity's key signs. A
    // refused identity ends the run here, before the line a script waits for.
    for (0..count) |index| try server_worker.start(index);
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
    if (options.identity_prefix) |prefix| try load_tls(prefix);
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

/// Loads the identity every worker's endpoint serves TLS with. It names no protocol: an endpoint
/// offers what its versions allow, so `--h11` offers `http/1.1` alone and `--h2` `h2` alone.
fn load_tls(prefix: []const u8) !void {
    server_identity.seed(&server_mode.identity_storage);
    server_mode.identity = try server_identity.load(prefix, &server_mode.identity_storage, &.{});
    // A log names what the sessions were told of the CPU, which decides the suites they hold.
    cpu.print("http-server");
}

/// The exit status of a run asked for something this build cannot do.
const exit_usage: u8 = 2;
