//! One endpoint of the QUIC connection check (design §8 step 9e): a `quic.Connection` with the
//! null QUIC provider and the null suite, and the part of a caller a real endpoint plays around
//! them.
//!
//! colibri holds no key and drives no TLS stack (decisions 8 and 48), so the caller does four
//! things colibri cannot:
//! - It derives the Initial keys from the client's first Destination Connection ID (RFC 9001 §5.2).
//! - It gives the provider this endpoint's transport parameters before the handshake (§8.2).
//! - It moves each later level's keys from the provider to the suite when the handshake reaches
//!   that level (§4.1.4), which the null provider does through its `suite` field. colibri reads
//!   them from the suite on its own (decision 62).
//! - It keeps the octets of the stream it sends (decision 57), and places the pool the octets it
//!   receives wait in (decision 61).
//! Everything else is one colibri call per datagram each way (decisions 59 and 60) and one per
//! instant. It reads no clock and draws no random number (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");

const Connection = quic.Connection;
const Role = quic.connection.Role;
const Parameters = quic.transport_parameters.Parameters;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

/// Why an endpoint stopped: a connection error, which two colibri endpoints never give each other,
/// or a send colibri refused.
pub const Error = quic.connection_datagram.Error || quic.connection_send.Error || quic.connection_recovery.Error ||
    quic.connection_stream_send.Error || quic.stream.stream_table.OpenError || quic.connection_stream_read.Error ||
    error{
        /// The server read an octet of the client's stream other than the one the client sent.
        TransferOctetWrong,
    };

/// The connection IDs of the run: the client's, the server's, and the one the client addresses its
/// first Initial to, which both derive the Initial keys from (RFC 9001 §5.2). Fixed octets, so a
/// seed replays (invariant 5).
const id_len: usize = 8;
const client_octet: u8 = 0xc1;
const server_octet: u8 = 0x5e;
const original_octet: u8 = 0x0d;
const client_id: [id_len]u8 = @splat(client_octet);
const server_id: [id_len]u8 = @splat(server_octet);
const original_id: [id_len]u8 = @splat(original_octet);

/// What each endpoint grants its peer (RFC 9000 §18.2): room for the one stream the client sends,
/// and an idle timeout long enough that only a dead path reaches it.
pub const stream_window: u64 = 65_536;
const connection_window: u64 = 131_072;
const streams_granted: u64 = 1;
const idle_timeout_ms: u64 = 60_000;

/// The octets of the one stream the client sends, and how the octet at each offset is chosen.
/// A run may send fewer (`Endpoint.transfer_len`).
pub const transfer_len_default: u64 = 16_384;
/// A request that fits one packet, as an hq-interop or h3 request line does.
pub const request_len: u64 = 64;
const octet_stride: u64 = 7;
const octet_seed: u64 = 0x2b;

pub const Endpoint = struct {
    connection: Connection,
    provider: sim.NullQuicProvider,
    suite: sim.NullSuite,
    send_scratch: quic.connection_send.DefaultScratch,
    scratch: quic.connection_datagram.Scratch,
    /// The datagram being received, copied out of the network: the suite opens it in place.
    received: [sim.constants.network_datagram_len_max]u8,
    /// The datagram being sent.
    output: [sim.constants.network_datagram_len_max]u8,
    /// Whether the client has opened its stream, which it does once the handshake completes.
    transfer_started: bool,
    /// Whether the peer acknowledged every octet of it, FIN included (RFC 9000 §3.1).
    transfer_done: bool,
    /// The pool the peer's stream octets wait in (decision 61), and what the server has read of
    /// the client's stream.
    pool: quic.stream.stream_incoming.DefaultPool,
    read_buffer: [sim.constants.network_datagram_len_max]u8,
    transfer_read_len: u64,
    transfer_read: bool,
    /// The octets of the client's stream, which both endpoints hold: the client supplies that
    /// many and the server checks them.
    transfer_len: u64,
    /// Makes the client supply its stream's first octet changed, which a fault test uses to show
    /// the server's check fires (`quic_connection_check.Fault`).
    supplies_wrong_octet: bool,

    pub fn init(endpoint: *Endpoint, role: Role, now_ns: u64) void {
        const local_source: []const u8 = if (role == .client) &client_id else &server_id;
        endpoint.connection.init(.{
            .role = role,
            .local_parameters = parameters(),
            .now_ns = now_ns,
            .identity = .{ .local_initial_source = local_source, .original_destination = &original_id },
            .receive = endpoint.pool.storage(),
            // Decision 68: the network carries each datagram's codepoint both ways.
            .ecn_reads = true,
            .ecn_marks = true,
        });
        endpoint.provider = .{ .role = role, .suite = &endpoint.suite };
        endpoint.suite = .{};
        endpoint.send_scratch = .{};
        endpoint.transfer_started = false;
        endpoint.transfer_done = false;
        endpoint.transfer_read_len = 0;
        endpoint.transfer_read = false;
        endpoint.transfer_len = transfer_len_default;
        endpoint.supplies_wrong_octet = false;
        // RFC 9001 §5.2: both endpoints derive the Initial keys from the Destination Connection ID
        // of the client's first Initial packet.
        const suite = endpoint.suite.suite();
        suite.vtable.install_initial_keys(suite.context, role, &original_id) catch unreachable;
        // RFC 9001 §8.2: the parameters travel in the handshake, so the provider holds them before
        // it starts. `Connection.init` wrote the connection IDs into them (RFC 9000 §7.3).
        var body: [sim.constants.null_quic_params_len_max]u8 = undefined;
        var writer = quic.core.Writer.init(&body);
        quic.transport_parameters.write(&writer, &endpoint.connection.local_parameters, role) catch unreachable;
        endpoint.provider.provider().set_transport_params(writer.written()) catch unreachable;
    }

    /// Takes one datagram the network delivered.
    pub fn receive(endpoint: *Endpoint, octets: []const u8, ecn: sim.network.Ecn, now_ns: u64) Error!void {
        assert(octets.len <= endpoint.received.len);
        @memcpy(endpoint.received[0..octets.len], octets);
        const received = try quic.connection_datagram.receive(
            &endpoint.connection,
            endpoint.suite.suite(),
            endpoint.provider.provider(),
            .{ .octets = endpoint.received[0..octets.len], .now_ns = now_ns, .ecn = space_ecn(ecn) },
            &endpoint.scratch,
        );
        if (received.completed_streams > 0) endpoint.transfer_done = true;
        if (endpoint.connection.role == .server) try endpoint.read_transfer();
    }

    /// The server reads what has arrived of the client's stream, and checks each octet against
    /// the one the client sent at that offset (decision 61).
    fn read_transfer(endpoint: *Endpoint) Error!void {
        if (endpoint.transfer_read) return;
        // Bounded: each read takes at least one octet, and the stream holds `transfer_len`.
        for (0..endpoint.transfer_len + 1) |_| {
            const read = quic.connection_stream_read.read(&endpoint.connection, transfer_stream, &endpoint.read_buffer) catch |failure| switch (failure) {
                // The stream's first octets have not arrived, so the server has not opened it.
                error.NotReadable => return,
                else => return failure,
            };
            try endpoint.check_octets(endpoint.read_buffer[0..read.len]);
            endpoint.transfer_read_len += read.len;
            if (read.fin) endpoint.transfer_read = true;
            if (read.len == 0 or read.fin) return;
        }
    }

    /// Builds the next datagram into `output`, or answers null when nothing is owed.
    pub fn send(endpoint: *Endpoint, now_ns: u64) Error!?quic.connection_send.Sent {
        try endpoint.start_transfer();
        const suite = endpoint.suite.suite();
        const provider = endpoint.provider.provider();
        const sent = try quic.connection_send.send(
            &endpoint.connection,
            suite,
            provider,
            endpoint.stream_provider(),
            &endpoint.send_scratch,
            &endpoint.output,
            now_ns,
        ) orelse return null;
        return sent;
    }

    /// Each octet read against the one the client sent at that offset.
    fn check_octets(endpoint: *const Endpoint, octets: []const u8) Error!void {
        // Bounded by what one read took.
        for (octets, 0..) |octet, index| {
            if (octet != octet_at(endpoint.transfer_read_len + index)) return error.TransferOctetWrong;
        }
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
        _ = try quic.connection_timer.on_instant(&endpoint.connection, endpoint.suite.suite(), &endpoint.scratch.recovery, now_ns);
    }

    /// The client opens its one stream and hands colibri all of it once the handshake completes.
    fn start_transfer(endpoint: *Endpoint) Error!void {
        if (endpoint.connection.role != .client or endpoint.transfer_started) return;
        if (!endpoint.connection.handshake_complete) return;
        const id = try quic.connection_stream_send.open(&endpoint.connection, .bidirectional);
        try quic.connection_stream_send.supply(&endpoint.connection, id, endpoint.transfer_len, true);
        endpoint.transfer_started = true;
    }

    fn stream_provider(endpoint: *Endpoint) StreamProvider {
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
    const endpoint: *const Endpoint = @ptrCast(@alignCast(context));
    _ = stream_id;
    if (offset >= endpoint.transfer_len) return 0;
    const len: usize = @intCast(@min(output.len, endpoint.transfer_len - offset));
    for (output[0..len], 0..) |*octet, index| octet.* = octet_at(offset + index);
    if (endpoint.supplies_wrong_octet and offset == 0) output[0] ^= 1;
    return len;
}

/// The octet of the client's stream at `offset`.
fn octet_at(offset: u64) u8 {
    return @truncate(offset *% octet_stride +% octet_seed);
}

/// The client's first bidirectional stream, which is the one it sends (RFC 9000 §2.1).
const transfer_stream: quic.stream.StreamId = .{ .value = 0 };

/// The codepoint `connection_send` names for a datagram, as the network carries it (RFC 9000
/// §13.4).
pub fn network_ecn(ecn: quic.connection_send.Ecn) sim.network.Ecn {
    return switch (ecn) {
        .not_ect => .not_ect,
        .ect_0 => .ect_0,
        .ect_1 => .ect_1,
        .ecn_ce => .ecn_ce,
    };
}

/// The network's ECN codepoint as the receive path names it (RFC 9000 §13.4).
fn space_ecn(ecn: sim.network.Ecn) quic.connection_receive.Datagram.Ecn {
    return switch (ecn) {
        .not_ect => .not_ect,
        .ect_0 => .ect_0,
        .ect_1 => .ect_1,
        .ecn_ce => .ecn_ce,
    };
}
