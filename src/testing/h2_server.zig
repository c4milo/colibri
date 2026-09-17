//! The socket around `h2_session.zig`: the cleartext prior-knowledge h2 server of design §9, which
//! `tools/h2spec.sh` runs the pinned h2spec against and h2load measures. `zig build h2-server --
//! --port <port>` runs it.
//!
//! This is the only file in the tree that opens a socket, and it holds no protocol rule: it reads
//! octets into a buffer, hands them to a session, writes back what the session produced, and
//! closes when the session says it is done (RFC 9113 §5.4.1). Connections are served one at a
//! time, which is all h2spec asks for: every case it runs is one connection.
//!
//! The library it drives allocates nothing, and neither does this: both buffers and the session
//! are static, and the `Io` implementation is given a failing allocator, because nothing here
//! starts an asynchronous task.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const constants = @import("constants.zig");
const h2_session = @import("h2_session.zig");

const Io = std.Io;
const Session = h2_session.Session;

/// The one connection's session, its buffers and the octets read but not yet consumed.
const Serving = struct {
    session: Session,
    input: [constants.read_buffer_len]u8,
    /// Octets of `input` read from the socket and not yet consumed.
    input_len: usize,
    output: [constants.write_buffer_len]u8,
};

/// One slot per connection served at once, outside any stack frame: each is large, and the count
/// is fixed, so the server allocates nothing however many peers arrive.
var slots: [constants.connections_max]Serving = undefined;

/// Whether each slot is in use. The accept loop claims a slot and the thread serving it frees it.
var slot_taken: [constants.connections_max]std.atomic.Value(bool) = @splat(.init(false));

/// Serves connections until the process is stopped. `port` is where it listens on the loopback.
/// Each connection gets a slot and a thread, because a peer that holds one connection open must
/// not keep the next peer waiting: h2spec opens a connection per case and leaves them to the
/// operating system to close.
pub fn listen_and_serve(io: Io, port: u16) !void {
    const address = try Io.net.IpAddress.parseIp4(loopback_address, port);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    while (true) {
        const stream = try server.accept(io);
        const slot = claim_slot() orelse {
            stream.close(io);
            continue;
        };
        const thread = std.Thread.spawn(.{}, serve_slot, .{ io, stream, slot }) catch {
            release_slot(slot);
            stream.close(io);
            continue;
        };
        thread.detach();
    }
}

/// The index of a free slot, or null when every one is serving a connection.
fn claim_slot() ?usize {
    for (&slot_taken, 0..) |*taken, index| {
        if (taken.cmpxchgStrong(false, true, .acquire, .monotonic) == null) return index;
    }
    return null;
}

/// Frees the slot a connection was served in.
fn release_slot(slot: usize) void {
    assert(slot_taken[slot].load(.monotonic));
    slot_taken[slot].store(false, .release);
}

/// Serves one connection in `slot`, then closes it and frees the slot. A connection that broke is
/// the peer's business, not the server's: the suites drop connections on purpose.
fn serve_slot(io: Io, stream: Io.net.Stream, slot: usize) void {
    defer {
        stream.close(io);
        release_slot(slot);
    }
    serve(io, stream, &slots[slot]) catch {};
}

/// Serves one connection: read, step, write, until the peer closes or the session is done.
fn serve(io: Io, stream: Io.net.Stream, serving: *Serving) !void {
    serving.session.init();
    serving.input_len = 0;
    var read_buffer: [constants.read_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var write_buffer: [constants.write_buffer_len]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    while (true) {
        if (try run_steps(&writer, serving)) return;
        const room = serving.input[serving.input_len..];
        if (room.len == 0) return;
        // One read of whatever the socket has: a reader that waited for a full buffer would wait
        // for octets the peer has no reason to send.
        var into = [_][]u8{room};
        const read = reader.interface.readVec(&into) catch return;
        // A read of no octets is the peer closing its side, which ends this connection.
        if (read == 0) return;
        serving.input_len += read;
    }
}

/// Steps the session until it stops moving, writing everything it produces. True when the session
/// is done and the connection is to be closed.
fn run_steps(writer: *Io.net.Stream.Writer, serving: *Serving) !bool {
    for (0..constants.steps_per_read_max) |_| {
        const step = serving.session.step(serving.input[0..serving.input_len], &serving.output);
        if (step.written > 0) {
            try writer.interface.writeAll(serving.output[0..step.written]);
            try writer.interface.flush();
        }
        consume(serving, step.consumed);
        if (step.done) return true;
        if (step.consumed == 0 and step.written == 0) return false;
    }
    // A step that consumes nothing and writes nothing ends the loop, so it always ends.
    unreachable;
}

/// Drops the `consumed` octets the session took, moving what is left to the front.
fn consume(serving: *Serving, consumed: usize) void {
    assert(consumed <= serving.input_len);
    if (consumed == 0) return;
    const rest = serving.input_len - consumed;
    for (0..rest) |index| serving.input[index] = serving.input[consumed + index];
    serving.input_len = rest;
}

/// The address the server listens on: the loopback, because it serves tests alone.
const loopback_address = "127.0.0.1";

/// The command-line option that names the port, as `tools/h2spec.sh` passes it.
const port_option = "--port";

/// Runs the server: `zig build h2-server -- --port <port>`, or `default_port` when none is given.
/// The `Io` implementation is given a failing allocator, because nothing here runs asynchronously.
pub fn main(init: std.process.Init.Minimal) !void {
    var arguments = std.process.Args.Iterator.init(init.args);
    _ = arguments.skip();
    const port = read_port(&arguments);
    var threaded: std.Io.Threaded = .init(std.mem.Allocator.failing, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try listen_and_serve(io, port);
}

/// The port `--port` names, or `default_port`.
fn read_port(arguments: *std.process.Args.Iterator) u16 {
    var wanted = false;
    for (0..constants.arguments_max) |_| {
        const argument = arguments.next() orelse break;
        if (wanted) return std.fmt.parseInt(u16, argument, constants.port_radix) catch constants.default_port;
        wanted = std.mem.eql(u8, argument, port_option);
    }
    return constants.default_port;
}
