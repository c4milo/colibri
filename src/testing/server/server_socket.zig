//! One connection's socket in the test-only server (`../server.zig`): the session, the octets read
//! but not consumed, the octets the session produced that the socket has not taken yet, and the
//! Rotor operations in flight. `server_worker.zig` holds a worker's connections and hands each
//! event to the one it names.
//!
//! A receive writes into `received`, and its octets are appended to `input` when its event
//! arrives. The session consumes `input` from the front, which moves what is left, and Rotor owns
//! a receive's buffer until its final event (its rule 3), so a receive never targets `input`.
//! A send reads `output[output_sent..output_len]`, and the session only appends after that.
//! Split off `../server.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");
const server_session = @import("server_session.zig");

const Session = server_session.Session;

/// What an operation a connection has in flight does. It rides in the operation's user data,
/// below the connection's slot.
pub const Kind = enum(u8) { receive, send, close };
pub const kind_bits = @bitSizeOf(Kind);

/// The operations a loop holds in flight for each connection: a receive, a send and a close.
pub const operations_per_connection: u32 = @typeInfo(Kind).@"enum".fields.len;

/// The user data of the operation of `kind` the connection in `slot` has in flight.
pub fn user_data(slot: usize, kind: Kind) u64 {
    return (@as(u64, slot) << kind_bits) | @intFromEnum(kind);
}

/// One connection a worker serves: the session, the octets read but not consumed, and the octets
/// the session produced that the socket has not taken yet. Over TLS, both hold records.
pub const Connection = struct {
    descriptor: rotor.Descriptor,
    session: Session,
    /// Where the receive in flight writes (see the header).
    received: [constants.wire_read_len]u8,
    input: [constants.wire_read_len]u8,
    input_len: usize,
    output: [constants.write_buffer_len]u8,
    /// Octets of `output` the session has produced.
    output_len: usize,
    /// Octets of `output` the socket has taken, which are always the first ones.
    output_sent: usize,
    /// The operations in flight. A slot is free again once it is closed and none is.
    receiving: bool,
    sending: bool,
    close_submitted: bool,
    closed: bool,
    /// Whether this slot holds a connection.
    live: bool,
    /// Whether the session is done, so the octets left are the last the peer gets.
    closing: bool,
    /// Whether the connection ends now, with nothing more sent: the peer left or a call failed.
    failed: bool,

    /// Takes the socket `descriptor` names, with nothing read, written or in flight. The caller
    /// starts the session.
    pub fn open(connection: *Connection, descriptor: rotor.Descriptor) void {
        connection.descriptor = descriptor;
        connection.input_len = 0;
        connection.output_len = 0;
        connection.output_sent = 0;
        connection.receiving = false;
        connection.sending = false;
        connection.close_submitted = false;
        connection.closed = false;
        connection.closing = false;
        connection.failed = false;
        connection.live = true;
    }

    /// Appends what a receive read to the input and steps the session over it. A receive of no
    /// octets is the peer closing its side, which ends the connection.
    pub fn on_received(connection: *Connection, event: rotor.Event, now_ns: u64) void {
        connection.receiving = false;
        const read = event.outcome() catch 0;
        if (read == 0) {
            connection.failed = true;
            return;
        }
        assert(read <= connection.input.len - connection.input_len);
        @memcpy(connection.input[connection.input_len..][0..read], connection.received[0..read]);
        connection.input_len += read;
        connection.step(now_ns);
    }

    /// Counts what a send took, and steps the session: the room the send freed may be what it
    /// waited for.
    pub fn on_sent(connection: *Connection, event: rotor.Event, now_ns: u64) void {
        connection.sending = false;
        const sent = event.outcome() catch {
            connection.failed = true;
            return;
        };
        connection.output_sent += sent;
        assert(connection.output_sent <= connection.output_len);
        // Every octet is gone and no send is in flight, so the buffer starts again at its front.
        if (connection.output_sent == connection.output_len) {
            connection.output_len = 0;
            connection.output_sent = 0;
        }
        connection.step(now_ns);
    }

    /// Submits what the connection needs next: its close once it is failed or finished and
    /// drained, otherwise a send of what is owed and a receive while there is room for more.
    /// `slot` is where its worker holds it, which each operation's user data names.
    pub fn arm(connection: *Connection, loop: *rotor.Loop, slot: usize) void {
        if (connection.close_submitted) return;
        const drained = connection.output_sent == connection.output_len;
        if (connection.failed or (connection.closing and drained)) return connection.submit(loop, slot, .close);
        if (!connection.sending and !drained) connection.submit(loop, slot, .send);
        const room = connection.input.len - connection.input_len;
        if (!connection.receiving and !connection.closing and room > 0) connection.submit(loop, slot, .receive);
    }

    /// Submits one operation. The loop holds one of each kind for every connection, so it always
    /// has room.
    fn submit(connection: *Connection, loop: *rotor.Loop, slot: usize, kind: Kind) void {
        const operation = switch (kind) {
            .receive => blk: {
                const room = connection.input.len - connection.input_len;
                connection.receiving = true;
                break :blk rotor.Operation.receive(user_data(slot, kind), connection.descriptor, connection.received[0..@min(room, connection.received.len)]);
            },
            .send => blk: {
                connection.sending = true;
                break :blk rotor.Operation.send(user_data(slot, kind), connection.descriptor, connection.output[connection.output_sent..connection.output_len]);
            },
            // Rotor's close cancels the connection's receive and send first.
            .close => blk: {
                connection.close_submitted = true;
                break :blk rotor.Operation.close(user_data(slot, kind), connection.descriptor);
            },
        };
        const taken = loop.submit(&.{operation}, &.{});
        assert(taken == 1);
    }

    /// Steps the session at `now_ns` until it stops moving, appending what it writes to the
    /// output buffer.
    pub fn step(connection: *Connection, now_ns: u64) void {
        if (connection.failed or connection.close_submitted) return;
        for (0..constants.steps_per_read_max) |_| {
            const room = connection.output[connection.output_len..];
            if (room.len == 0) return;
            const stepped = connection.session.step(connection.input[0..connection.input_len], room, now_ns);
            connection.output_len += stepped.written;
            connection.consume(stepped.consumed);
            if (stepped.done) {
                connection.closing = true;
                return;
            }
            if (stepped.consumed == 0 and stepped.written == 0) return;
        }
    }

    /// Drops the `consumed` octets the session took, moving what is left to the front.
    fn consume(connection: *Connection, consumed: usize) void {
        assert(consumed <= connection.input_len);
        if (consumed == 0) return;
        std.mem.copyForwards(u8, &connection.input, connection.input[consumed..connection.input_len]);
        connection.input_len -= consumed;
    }
};
