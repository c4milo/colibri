//! One endpoint of the QUIC connection check (design §8 step 9e): a `quic.Connection` with the
//! null QUIC provider and the null suite, and the part of a caller a real endpoint plays around
//! them.
//!
//! colibri holds no key and drives no TLS stack (decisions 8 and 48), so the caller does four
//! things colibri cannot:
//! - It derives the Initial keys from the client's first Destination Connection ID (RFC 9001 §5.2).
//! - It gives the provider this endpoint's transport parameters before the handshake (§8.2).
//! - It installs each later level's keys when the handshake reaches that level (§4.1.4).
//! - It keeps the octets of the stream it sends (decision 57).
//! Everything else is one colibri call per datagram each way (decisions 59 and 60) and one per
//! instant. It reads no clock and draws no random number (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");

const Connection = quic.Connection;
const Level = quic.core.Level;
const Role = quic.connection.Role;
const Parameters = quic.transport_parameters.Parameters;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

/// Why an endpoint stopped: a connection error, which two colibri endpoints never give each other,
/// or a send colibri refused.
pub const Error = quic.connection_datagram.Error || quic.connection_send.Error || quic.connection_recovery.Error ||
    quic.connection_stream_send.Error || quic.stream.stream_table.OpenError;

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

/// The null provider's script (`null_quic_provider.zig`, RFC 9001 §4.1.5's Figure 5) reaches the
/// Handshake level at its second step, once the ServerHello has been written or read, and the
/// application level at its fourth, once the server's Finished has. Those are the moments a TLS
/// stack hands over each level's secrets (§4.1.4).
const handshake_keys_step: u8 = 2;
const application_keys_step: u8 = 4;

/// What each endpoint grants its peer (RFC 9000 §18.2): room for the one stream the client sends,
/// and an idle timeout long enough that only a dead path reaches it.
pub const stream_window: u64 = 65_536;
const connection_window: u64 = 131_072;
const streams_granted: u64 = 1;
const idle_timeout_ms: u64 = 60_000;

/// The octets of the one stream the client sends, and how the octet at each offset is chosen.
pub const transfer_len: u64 = 16_384;
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

    pub fn init(endpoint: *Endpoint, role: Role, now_ns: u64) void {
        const local_source: []const u8 = if (role == .client) &client_id else &server_id;
        endpoint.connection.init(.{
            .role = role,
            .local_parameters = parameters(),
            .now_ns = now_ns,
            .identity = .{ .local_initial_source = local_source, .original_destination = &original_id },
        });
        endpoint.provider = .{ .role = role };
        endpoint.suite = .{};
        endpoint.send_scratch = .{};
        endpoint.transfer_started = false;
        endpoint.transfer_done = false;
        // RFC 9001 §5.2: both endpoints derive the Initial keys from the Destination Connection ID
        // of the client's first Initial packet.
        const suite = endpoint.suite.suite();
        suite.vtable.install_initial_keys(suite.context, role, &original_id) catch unreachable;
        quic.connection_keys.on_keys_installed(&endpoint.connection, .initial, .read);
        quic.connection_keys.on_keys_installed(&endpoint.connection, .initial, .write);
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
        endpoint.install_keys();
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
        // RFC 9001 §4.1.1: the handshake is complete when the TLS stack says so, and a client's
        // stack says so once its own Finished is written, which happens inside `send`.
        _ = try quic.connection_handshake.complete(&endpoint.connection, provider, suite);
        endpoint.install_keys();
        return sent;
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

    /// RFC 9001 §4.1.4: installs each level's keys once the handshake has reached it.
    fn install_keys(endpoint: *Endpoint) void {
        endpoint.install_at(.handshake, handshake_keys_step);
        endpoint.install_at(.application, application_keys_step);
    }

    fn install_at(endpoint: *Endpoint, level: Level, step: u8) void {
        if (endpoint.provider.step < step) return;
        // Once: a level colibri discarded stays discarded (RFC 9001 §4.9).
        if (endpoint.suite.state_of(level, .read) != .none) return;
        endpoint.suite.install(level);
        quic.connection_keys.on_keys_installed(&endpoint.connection, level, .read);
        quic.connection_keys.on_keys_installed(&endpoint.connection, level, .write);
    }

    /// The client opens its one stream and hands colibri all of it once the handshake completes.
    fn start_transfer(endpoint: *Endpoint) Error!void {
        if (endpoint.connection.role != .client or endpoint.transfer_started) return;
        if (!endpoint.connection.handshake_complete) return;
        const id = try quic.connection_stream_send.open(&endpoint.connection, .bidirectional);
        try quic.connection_stream_send.supply(&endpoint.connection, id, transfer_len, true);
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

const stream_vtable: quic.stream.stream_provider.VTable = .{ .read = read_transfer };

/// The client's stream, read back by offset. Every call at one offset answers the same octets,
/// which RFC 9000 §2.2 asks of a retransmission.
fn read_transfer(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    if (offset >= transfer_len) return 0;
    const len: usize = @intCast(@min(output.len, transfer_len - offset));
    for (output[0..len], 0..) |*octet, index| octet.* = @truncate((offset + index) *% octet_stride +% octet_seed);
    return len;
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
