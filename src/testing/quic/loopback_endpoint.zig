//! One endpoint of the QUIC loopback check (design §8 step 9e): a `quic.Connection` over a
//! chapulin session, and the part of a caller a real endpoint plays around them.
//!
//! It is `src/sim/quic_endpoint.zig` with chapulin in place of the null provider and suite, so the
//! caller's four duties are the same (decisions 48, 57, 60 and 61):
//! - It derives the Initial keys from the client's first Destination Connection ID (RFC 9001
//!   §5.2).
//! - It gives the provider this endpoint's transport parameters before the handshake (§8.2).
//! - It marks each later level installed when chapulin reports it ready (§4.1.4).
//! - It supplies the octets of the stream it sends, and places the pool the octets it receives
//!   wait in.
//! The order of the first two differs from the simulator's: chapulin starts its session when it
//! is given the parameters, and derives no Initial key before that.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../constants.zig");
const chapulin_quic = @import("chapulin_quic.zig");

const Connection = quic.Connection;
const Level = quic.core.Level;
const Role = quic.crypto.Role;
const Direction = quic.crypto.Direction;
const Parameters = quic.transport_parameters.Parameters;
const Session = chapulin_quic.Session;

pub const Error = quic.connection_datagram.Error || quic.connection_send.Error || quic.connection_recovery.Error ||
    quic.connection_stream_send.Error || quic.stream.stream_table.OpenError || quic.connection_stream_read.Error ||
    error{
        /// chapulin refused to start or to take its Initial keys.
        SessionRefused,
        /// The server read an octet of the client's stream other than the one the client sent.
        TransferOctetWrong,
    };

/// The connection IDs of the run, fixed so a run reads the same in a capture each time.
const id_len: usize = 8;
const client_octet: u8 = 0xc1;
const server_octet: u8 = 0x5e;
const original_octet: u8 = 0x0d;
const client_id: [id_len]u8 = @splat(client_octet);
const server_id: [id_len]u8 = @splat(server_octet);
const original_id: [id_len]u8 = @splat(original_octet);

/// What each endpoint grants its peer (RFC 9000 §18.2): room for the one stream the client sends.
const stream_window: u64 = 65_536;
const connection_window: u64 = 131_072;
const streams_granted: u64 = 1;
const idle_timeout_ms: u64 = 30_000;

/// The octets of the one stream the client sends, and how the octet at each offset is chosen. A
/// mebibyte takes the 1-RTT packet numbers past 256, where a one-octet Packet Number field no
/// longer decodes without the largest number received (RFC 9000 Appendix A.3), and makes the
/// server grant credit many times over (RFC 9000 §4.1).
pub const transfer_len: u64 = 1_048_576;
const octet_stride: u64 = 7;
const octet_seed: u64 = 0x2b;

/// The client's first bidirectional stream, which is the one it sends (RFC 9000 §2.1).
const transfer_stream: quic.stream.StreamId = .{ .value = 0 };

pub const Endpoint = struct {
    connection: Connection,
    session: Session,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    /// The datagram being received, copied: the suite opens it in place.
    received: [constants.quic_datagram_len_max]u8,
    /// The datagram being sent.
    output: [constants.quic_datagram_len_max]u8,
    pool: quic.stream.stream_incoming.DefaultPool,
    read_buffer: [constants.quic_datagram_len_max]u8,
    transfer_started: bool,
    /// Whether the peer acknowledged every octet of the client's stream, FIN included.
    transfer_done: bool,
    transfer_read_len: u64,
    transfer_read: bool,

    /// Starts the connection and its session. `options` is the session's.
    pub fn init(endpoint: *Endpoint, options: chapulin_quic.Options, now_ns: u64) Error!void {
        const role = options.role;
        const local_source: []const u8 = if (role == .client) &client_id else &server_id;
        endpoint.connection.init(.{
            .role = role,
            .local_parameters = parameters(),
            .now_ns = now_ns,
            .identity = .{ .local_initial_source = local_source, .original_destination = &original_id },
            .receive = endpoint.pool.storage(),
        });
        endpoint.session.init(options);
        endpoint.send_scratch = .{};
        endpoint.transfer_started = false;
        endpoint.transfer_done = false;
        endpoint.transfer_read_len = 0;
        endpoint.transfer_read = false;
        // RFC 9001 §8.2: the parameters travel in the handshake. `Connection.init` wrote the
        // connection IDs into them (RFC 9000 §7.3).
        var body: [constants.quic_peer_params_len_max]u8 = undefined;
        var writer = quic.core.Writer.init(&body);
        quic.transport_parameters.write(&writer, &endpoint.connection.local_parameters, role) catch
            return error.SessionRefused;
        endpoint.session.provider().set_transport_params(writer.written()) catch return error.SessionRefused;
        // RFC 9001 §5.2: both endpoints derive the Initial keys from the Destination Connection ID
        // of the client's first Initial packet.
        const suite = endpoint.session.suite();
        suite.vtable.install_initial_keys(suite.context, role, &original_id) catch return error.SessionRefused;
        quic.connection_keys.on_keys_installed(&endpoint.connection, .initial, .read);
        quic.connection_keys.on_keys_installed(&endpoint.connection, .initial, .write);
        _ = endpoint.session.take_ready();
    }

    /// Takes one datagram the peer sent.
    pub fn receive(endpoint: *Endpoint, octets: []const u8, now_ns: u64) Error!void {
        assert(octets.len <= endpoint.received.len);
        @memcpy(endpoint.received[0..octets.len], octets);
        const received = try quic.connection_datagram.receive(
            &endpoint.connection,
            endpoint.session.suite(),
            endpoint.session.provider(),
            .{ .octets = endpoint.received[0..octets.len], .now_ns = now_ns, .ecn = .not_ect },
            &endpoint.scratch,
        );
        if (received.completed_streams > 0) endpoint.transfer_done = true;
        endpoint.install_ready();
        if (endpoint.connection.role == .server) try endpoint.read_transfer();
    }

    /// Builds the next datagram into `output`, or answers null when nothing is owed.
    pub fn send(endpoint: *Endpoint, now_ns: u64) Error!?[]const u8 {
        try endpoint.start_transfer();
        const sent = try quic.connection_send.send(
            &endpoint.connection,
            endpoint.session.suite(),
            endpoint.session.provider(),
            endpoint.stream_provider(),
            &endpoint.send_scratch,
            &endpoint.output,
            now_ns,
        ) orelse return null;
        endpoint.install_ready();
        return endpoint.output[0..sent.len];
    }

    /// The instant this endpoint next wants to be called at (design §4.2).
    pub fn next_deadline_ns(endpoint: *Endpoint) ?u64 {
        const deadline = quic.connection_timer.next(&endpoint.connection) orelse return null;
        return deadline.at_ns;
    }

    /// Fires whichever deadlines `now_ns` has reached.
    pub fn on_instant(endpoint: *Endpoint, now_ns: u64) Error!void {
        const at_ns = endpoint.next_deadline_ns() orelse return;
        if (now_ns < at_ns) return;
        _ = try quic.connection_timer.on_instant(&endpoint.connection, endpoint.session.suite(), &endpoint.scratch.recovery, now_ns);
    }

    /// RFC 9001 §4.1.4: marks installed each level chapulin reported ready. A level colibri has
    /// discarded stays discarded (§4.9).
    fn install_ready(endpoint: *Endpoint) void {
        const ready = endpoint.session.take_ready();
        // Bounded by the levels and the two directions.
        for (0..quic.core.levels_count) |level_index| {
            const level: Level = @enumFromInt(level_index);
            for ([_]Direction{ .read, .write }) |direction| {
                if (!Session.is_ready(ready, level, direction)) continue;
                if (endpoint.connection.keys.at(level, direction) != .none) continue;
                quic.connection_keys.on_keys_installed(&endpoint.connection, level, direction);
            }
        }
    }

    /// The server reads what has arrived of the client's stream, and checks each octet.
    fn read_transfer(endpoint: *Endpoint) Error!void {
        if (endpoint.transfer_read) return;
        // Bounded: each read takes at least one octet, and the stream holds `transfer_len`.
        for (0..transfer_len + 1) |_| {
            const read = quic.connection_stream_read.read(&endpoint.connection, transfer_stream, &endpoint.read_buffer) catch |failure| switch (failure) {
                // The stream's first octets have not arrived, so the server has not opened it.
                error.NotReadable => return,
                else => return failure,
            };
            if (!octets_match(endpoint.transfer_read_len, endpoint.read_buffer[0..read.len])) return error.TransferOctetWrong;
            endpoint.transfer_read_len += read.len;
            if (read.fin) endpoint.transfer_read = true;
            if (read.len == 0 or read.fin) return;
        }
    }

    /// The client opens its one stream and hands colibri all of it once the handshake completes.
    fn start_transfer(endpoint: *Endpoint) Error!void {
        if (endpoint.connection.role != .client or endpoint.transfer_started) return;
        if (!endpoint.connection.handshake_complete) return;
        const id = try quic.connection_stream_send.open(&endpoint.connection, .bidirectional);
        assert(id.value == transfer_stream.value);
        try quic.connection_stream_send.supply(&endpoint.connection, id, transfer_len, true);
        endpoint.transfer_started = true;
    }

    fn stream_provider(endpoint: *Endpoint) quic.stream.stream_provider.StreamProvider {
        return .{ .context = endpoint, .vtable = &stream_vtable };
    }
};

/// What each endpoint advertises (RFC 9000 §18.2).
fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = connection_window;
    held.initial_max_stream_data_bidi_local = stream_window;
    held.initial_max_stream_data_bidi_remote = stream_window;
    held.initial_max_streams_bidi = streams_granted;
    held.max_idle_timeout_ms = idle_timeout_ms;
    return held;
}

const stream_vtable: quic.stream.stream_provider.VTable = .{ .read = supply_transfer };

/// The client's stream, read back by offset. Every call at one offset answers the same octets,
/// which RFC 9000 §2.2 asks of a retransmission.
fn supply_transfer(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    if (offset >= transfer_len) return 0;
    const len: usize = @intCast(@min(output.len, transfer_len - offset));
    for (output[0..len], 0..) |*octet, index| octet.* = octet_at(offset + index);
    return len;
}

fn octet_at(offset: u64) u8 {
    return @truncate(offset *% octet_stride +% octet_seed);
}

/// Whether `octets`, read from offset `from` of the client's stream, are the ones it sent.
fn octets_match(from: u64, octets: []const u8) bool {
    // Bounded by what one read took.
    for (octets, 0..) |octet, index| {
        if (octet != octet_at(from + index)) return false;
    }
    return true;
}

test "the server's check refuses an octet the client did not send at that offset" {
    var octets: [id_len]u8 = undefined;
    const from: u64 = transfer_len / 2;
    for (&octets, 0..) |*octet, index| octet.* = octet_at(from + index);
    try std.testing.expect(octets_match(from, &octets));
    // The same octets read from the next offset are the wrong ones there.
    try std.testing.expect(!octets_match(from + 1, &octets));
    octets[octets.len - 1] ^= 1;
    try std.testing.expect(!octets_match(from, &octets));
}
