//! The qlog a connection writes when its caller gave it a log (decision 102, design §8 step 18b):
//! the QUIC events of quic-events §3 that colibri fills from its own state. Every function here
//! returns at once when the connection holds no log, so a connection without one pays one branch
//! at each place it would log.
//!
//! **A log reads the connection and never changes it.** The same seed sends the same datagrams
//! with a log and without one (decision 102). The frames of a packet are read a second time, from
//! the plaintext it was sealed from or opened into, and what they did is not asked again.
//!
//! **Some events say what changed.** Quic-events §4.6 logs a state when the connection enters it,
//! and §7.2 logs a recovery metric when its value changes. `log_changes` runs as `send`,
//! `receive` and `on_instant` return, compares the connection with what the last events said,
//! and logs the difference.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const qlog = @import("qlog");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const frame_module = @import("../frame/frame.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const receive_module = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");

const Level = core.Level;
const Reader = core.Reader;
const TextWriter = qlog.TextWriter;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const quic_event = qlog.quic_event;
const quic_frame = qlog.quic_frame;

pub const Log = qlog.Log;

/// QUIC version 1 as the octets a QuicVersion hexstring shows (quic-events §8.1), in the network
/// byte order RFC 9000 §17.2 writes it in.
const version_octets = octets: {
    var octets: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &octets, constants.version_1, .big);
    break :octets octets;
};

/// A connection's log, and what its last events said.
pub const State = struct {
    /// The caller's log, whose header the caller wrote (main schema §5), or null.
    log: ?*Log,
    /// The state the last `connection_state_updated` named, or null before the first.
    connection_state: ?quic_event.ConnectionState,
    /// Whether the peer's parameters, the chosen protocol and the close were logged.
    peer_parameters_logged: bool,
    alpn_logged: bool,
    closed_logged: bool,
    /// The values the last `recovery_metrics_updated` carried, or their starting values.
    metrics: Metrics,
};

/// The recovery metrics of quic-events §7.2 that colibri keeps.
const Metrics = struct {
    min_rtt_ns: u64 = 0,
    smoothed_rtt_ns: u64 = 0,
    latest_rtt_ns: u64 = 0,
    rtt_variance_ns: u64 = 0,
    pto_count: u16 = 0,
    congestion_window: u64 = 0,
    bytes_in_flight: u64 = 0,
    /// RFC 9002 Appendix B.3 starts `ssthresh` at infinity, which colibri holds as the largest
    /// `u64`, so it is logged only once a congestion event lowers it.
    ssthresh: u64 = std.math.maxInt(u64),
};

/// Takes the caller's log and writes what the connection starts with: the version it speaks
/// (quic-events §5.1) and its own transport parameters (§5.3).
pub fn init(connection: *Connection, log: ?*Log, now_ns: u64) void {
    connection.qlog = .{
        .log = log,
        .connection_state = null,
        .peer_parameters_logged = false,
        .alpn_logged = false,
        .closed_logged = false,
        .metrics = .{},
    };
    const held = log orelse return;
    // Main schema §5: the header comes first, and each event's time counts from its instant.
    assert(held.started and held.start_ns <= now_ns);
    held.event(quic_event.name.version_information, now_ns, quic_event.VersionInformation{
        .vantage_point = switch (connection.role) {
            .client => .client,
            .server => .server,
        },
        .version = .{ .octets = &version_octets },
    });
    held.event(quic_event.name.parameters_set, now_ns, parameters_event(.local, &connection.local_parameters));
}

/// Quic-events §5.5 for one packet `send` sealed. `payload` is the plaintext it was sealed from,
/// PADDING included, and `packet_len` the octets it occupies in the datagram.
pub fn on_packet_sent(connection: *const Connection, level: Level, packet_number: u64, packet_len: usize, payload: []const u8, now_ns: u64) void {
    const log = connection.qlog.log orelse return;
    log.event(quic_event.name.packet_sent, now_ns, Packet{
        .header = .{ .packet_type = packet_type_of(level), .packet_number = packet_number },
        .raw = .{ .length = packet_len, .payload_length = payload.len },
        .payload = payload,
        // RFC 9000 §19.3: the ACK Delay is scaled by the exponent of the endpoint that sent it.
        .ack_delay_exponent = connection.local_parameters.ack_delay_exponent,
    });
}

/// Quic-events §5.6 for a packet of a datagram that opened, or §5.7 for one that was dropped.
/// `packet_len` is the octets the walk stepped over for it.
pub fn on_packet_read(connection: *const Connection, outcome: receive_module.Outcome, packet_len: usize, now_ns: u64) void {
    const log = connection.qlog.log orelse return;
    switch (outcome) {
        .opened => |opened| log.event(quic_event.name.packet_received, now_ns, Packet{
            .header = .{ .packet_type = packet_type_of(opened.level), .packet_number = opened.packet_number },
            .raw = .{ .length = packet_len, .payload_length = opened.payload.len },
            .payload = opened.payload,
            .ack_delay_exponent = peer_ack_delay_exponent(connection),
        }),
        .discarded => |why| log.event(quic_event.name.packet_dropped, now_ns, quic_event.PacketDropped{
            .raw = .{ .length = packet_len },
            .trigger = dropped_trigger(why),
        }),
    }
}

/// Quic-events §7.4 for each packet of `level`'s space that recovery declared lost. `trigger` is
/// the cause, or null when more than one could have declared the packet.
pub fn on_packets_lost(
    connection: *const Connection,
    level: Level,
    lost: []const recovery_sent.Record,
    trigger: ?quic_event.LossTrigger,
    now_ns: u64,
) void {
    const log = connection.qlog.log orelse return;
    // Bounded by the caller's list, which holds at most one table of sent packets.
    for (lost) |record| log.event(quic_event.name.packet_lost, now_ns, quic_event.PacketLost{
        .header = .{ .packet_type = packet_type_of(level), .packet_number = record.number },
        .trigger = trigger,
    });
}

/// Quic-events §4.3 for the peer's CONNECTION_CLOSE, which is what names its error. A close the
/// connection sends, or a silent one, is `log_changes`'s to log.
pub fn on_close_received(connection: *Connection, close: ?frames.Close, now_ns: u64) void {
    const log = connection.qlog.log orelse return;
    const held = close orelse return;
    if (connection.qlog.closed_logged) return;
    connection.qlog.closed_logged = true;
    log.event(quic_event.name.connection_closed, now_ns, close_event(.remote, held.layer, held.error_code));
}

/// Logs what changed since the last events: the peer's transport parameters (quic-events §5.3)
/// and the protocol the handshake chose (§5.2) once they are known, how the connection closed
/// (§4.3), the state it entered (§4.6), and the recovery metrics (§7.2). `provider` is null
/// where the caller passes none, which is only where no handshake advances.
pub fn log_changes(connection: *Connection, provider: ?tls_provider.QuicProvider, now_ns: u64) void {
    const log = connection.qlog.log orelse return;
    log_peer_parameters(connection, log, now_ns);
    if (provider) |held| log_alpn(connection, log, held, now_ns);
    log_state(connection, log, now_ns);
    log_metrics(connection, log, now_ns);
}

fn log_peer_parameters(connection: *Connection, log: *Log, now_ns: u64) void {
    if (connection.qlog.peer_parameters_logged) return;
    // By pointer, because the event's connection IDs point into the parameters.
    const peer = if (connection.peer_parameters) |*held| held else return;
    connection.qlog.peer_parameters_logged = true;
    log.event(quic_event.name.parameters_set, now_ns, parameters_event(.remote, peer));
}

/// RFC 9001 §8.1: the protocol arrives in the handshake with the peer's transport parameters, so
/// it is asked for from then on until the provider names one.
fn log_alpn(connection: *Connection, log: *Log, provider: tls_provider.QuicProvider, now_ns: u64) void {
    if (connection.qlog.alpn_logged or connection.peer_parameters == null) return;
    const alpn = provider.negotiated_alpn() orelse return;
    connection.qlog.alpn_logged = true;
    log.event(quic_event.name.alpn_information, now_ns, quic_event.AlpnInformation{
        .chosen_alpn = .{ .byte_value = .{ .octets = alpn } },
    });
}

/// Quic-events §4.6, and §4.3 the first time the connection leaves the active state.
fn log_state(connection: *Connection, log: *Log, now_ns: u64) void {
    const state = state_of(connection) orelse return;
    const old = connection.qlog.connection_state;
    if (old == state) return;
    connection.qlog.connection_state = state;
    if (connection.termination.state != .active and !connection.qlog.closed_logged) {
        connection.qlog.closed_logged = true;
        log.event(quic_event.name.connection_closed, now_ns, closed_event(connection));
    }
    log.event(quic_event.name.connection_state_updated, now_ns, quic_event.ConnectionStateUpdated{ .old = old, .new = state });
}

/// Quic-events §4.6's state of the connection, or null before an Initial was sent or received.
fn state_of(connection: *const Connection) ?quic_event.ConnectionState {
    return switch (connection.termination.state) {
        .closing => .closing,
        .draining => .draining,
        .closed => .closed,
        .active => handshake_state_of(connection),
    };
}

fn handshake_state_of(connection: *const Connection) ?quic_event.ConnectionState {
    // RFC 9001 §4.1.2 confirms a handshake after it completes, so the later state is asked first.
    if (connection.handshake_confirmed) return .handshake_confirmed;
    if (connection.handshake_complete) return .handshake_complete;
    // Quic-events §4.6: "handshake_started" is a Handshake packet sent or received, and
    // "attempted" an Initial packet.
    if (used(connection, .handshake)) return .handshake_started;
    if (used(connection, .initial)) return .attempted;
    return null;
}

/// Whether a packet was sent or received at `level`.
fn used(connection: *const Connection, level: Level) bool {
    const space = &connection.spaces[@intFromEnum(level)];
    return space.next_packet_number > 0 or space.received.largest() != null;
}

/// Quic-events §4.3 for a connection that stopped being active, from the reason it stopped.
fn closed_event(connection: *const Connection) quic_event.ConnectionClosed {
    // `Termination` sets a reason whenever it leaves the active state.
    return switch (connection.termination.reason.?) {
        .idle => .{ .initiator = .local, .trigger = .idle_timeout },
        .closed_locally => sent_close_event(connection),
        .closed_by_peer => .{ .initiator = .remote, .trigger = .unspecified },
        .abandoned => .{ .initiator = .local, .trigger = .version_mismatch },
        .path_failed, .packet_numbers_exhausted => .{ .initiator = .local, .trigger = .@"error" },
    };
}

/// The close this endpoint sent, which `pending_close` keeps for as long as it is closing.
fn sent_close_event(connection: *const Connection) quic_event.ConnectionClosed {
    const close = connection.pending_close orelse return .{ .initiator = .local, .trigger = .unspecified };
    return close_event(.local, close.layer, close.error_code);
}

fn close_event(initiator: quic_event.Initiator, layer: frame_module.CloseLayer, error_code: u64) quic_event.ConnectionClosed {
    return switch (layer) {
        .transport => .{ .initiator = initiator, .error_space = .transport, .error_code = error_code, .trigger = .@"error" },
        .application => .{ .initiator = initiator, .error_space = .application, .error_code = error_code, .trigger = .application },
    };
}

/// Quic-events §7.2: each metric whose value changed since the last event, in one event.
fn log_metrics(connection: *Connection, log: *Log, now_ns: u64) void {
    const current = metrics_of(connection);
    const last = connection.qlog.metrics;
    if (std.meta.eql(current, last)) return;
    connection.qlog.metrics = current;
    log.event(quic_event.name.recovery_metrics_updated, now_ns, quic_event.RecoveryMetricsUpdated{
        .min_rtt = changed_duration(current.min_rtt_ns, last.min_rtt_ns),
        .smoothed_rtt = changed_duration(current.smoothed_rtt_ns, last.smoothed_rtt_ns),
        .latest_rtt = changed_duration(current.latest_rtt_ns, last.latest_rtt_ns),
        .rtt_variance = changed_duration(current.rtt_variance_ns, last.rtt_variance_ns),
        .pto_count = changed(u16, current.pto_count, last.pto_count),
        .congestion_window = changed(u64, current.congestion_window, last.congestion_window),
        .bytes_in_flight = changed(u64, current.bytes_in_flight, last.bytes_in_flight),
        .ssthresh = changed(u64, current.ssthresh, last.ssthresh),
    });
}

fn metrics_of(connection: *const Connection) Metrics {
    const recovery = &connection.recovery;
    return .{
        .min_rtt_ns = recovery.rtt.min_ns,
        .smoothed_rtt_ns = recovery.rtt.smoothed_ns,
        .latest_rtt_ns = recovery.rtt.latest_ns,
        .rtt_variance_ns = recovery.rtt.variation_ns,
        .pto_count = recovery.timer.pto_count,
        .congestion_window = recovery.congestion.window,
        .bytes_in_flight = recovery.in_flight_len(),
        .ssthresh = recovery.congestion.slow_start_threshold,
    };
}

fn changed(comptime T: type, current: T, last: T) ?T {
    return if (current == last) null else current;
}

fn changed_duration(current_ns: u64, last_ns: u64) ?quic_event.Duration {
    return if (current_ns == last_ns) null else .{ .ns = current_ns };
}

/// Quic-events §5.3 for one endpoint's transport parameters (RFC 9000 §18.2).
fn parameters_event(initiator: quic_event.Initiator, parameters: *const Parameters) quic_event.ParametersSet {
    return .{
        .initiator = initiator,
        .original_destination_connection_id = hex_of(&parameters.original_destination_connection_id),
        .initial_source_connection_id = hex_of(&parameters.initial_source_connection_id),
        .retry_source_connection_id = hex_of(&parameters.retry_source_connection_id),
        .disable_active_migration = parameters.disable_active_migration,
        .max_idle_timeout = parameters.max_idle_timeout_ms,
        .max_udp_payload_size = parameters.max_udp_payload_size,
        .ack_delay_exponent = parameters.ack_delay_exponent,
        .max_ack_delay = parameters.max_ack_delay_ms,
        .active_connection_id_limit = parameters.active_connection_id_limit,
        .initial_max_data = parameters.initial_max_data,
        .initial_max_stream_data_bidi_local = parameters.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote = parameters.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni = parameters.initial_max_stream_data_uni,
        .initial_max_streams_bidi = parameters.initial_max_streams_bidi,
        .initial_max_streams_uni = parameters.initial_max_streams_uni,
    };
}

/// A connection ID of `parameters` as a hexstring. By pointer, so the octets stay the
/// parameters' own until the event is written.
fn hex_of(connection_id: *const ?transport_parameters.ConnectionId) ?quic_event.Hex {
    const held = if (connection_id.*) |*id| id else return null;
    return .{ .octets = held.slice() };
}

/// A `packet_sent` or `packet_received` event: the header, the lengths, and each frame of the
/// payload (quic-events §5.5, §5.6).
const Packet = struct {
    header: quic_event.PacketHeader,
    raw: quic_event.Raw,
    payload: []const u8,
    /// The exponent an ACK frame's ACK Delay is scaled by (RFC 9000 §19.3), which is the sender's.
    ack_delay_exponent: u64,

    pub fn write(packet: Packet, text: *TextWriter) qlog.Error!void {
        try quic_event.field(text, "header", packet.header);
        try quic_event.field(text, "raw", packet.raw);
        try quic_event.begin_frames(text);
        try write_frames(text, packet.payload, packet.ack_delay_exponent);
        try quic_event.end_frames(text);
    }
};

/// Each frame of `payload`, in order. A frame that does not parse ends the list: the packet is
/// logged as far as a reader can follow it, which is where `connection_frames` stopped too.
fn write_frames(text: *TextWriter, payload: []const u8, ack_delay_exponent: u64) qlog.Error!void {
    var reader = Reader.init(payload);
    // Bounded by the frames one packet can hold, as `connection_frames.process` is.
    for (0..constants.frames_per_packet_max) |_| {
        if (reader.remaining_len() == 0) return;
        const frame = frame_module.read(&reader) catch return;
        try write_frame(text, frame, ack_delay_exponent);
    }
}

fn write_frame(text: *TextWriter, frame: frame_module.Frame, ack_delay_exponent: u64) qlog.Error!void {
    switch (frame) {
        .padding => |padding| try quic_frame.padding(text, padding.len),
        .ping => try quic_frame.ping(text),
        .ack => |ack| try write_ack(text, ack, ack_delay_exponent),
        .reset_stream => |reset| try quic_frame.reset_stream(text, reset.stream_id, reset.error_code, reset.final_size),
        .stop_sending => |stop| try quic_frame.stop_sending(text, stop.stream_id, stop.error_code),
        .crypto => |crypto| try quic_frame.crypto(text, crypto.offset, crypto.data.len),
        .new_token => |token| try quic_frame.new_token(text, token.token.len),
        .stream => |stream| try quic_frame.stream(text, stream.stream_id, stream.offset, stream.data.len, stream.fin),
        .max_data => |limit| try quic_frame.max_data(text, limit.maximum),
        .max_stream_data => |limit| try quic_frame.max_stream_data(text, limit.stream_id, limit.maximum),
        .max_streams => |limit| try quic_frame.max_streams(text, directionality_of(limit.directionality), limit.maximum),
        .data_blocked => |blocked| try quic_frame.data_blocked(text, blocked.limit),
        .stream_data_blocked => |blocked| try quic_frame.stream_data_blocked(text, blocked.stream_id, blocked.limit),
        .streams_blocked => |blocked| try quic_frame.streams_blocked(text, directionality_of(blocked.directionality), blocked.limit),
        .new_connection_id => |issued| try quic_frame.new_connection_id(text, issued.sequence_number, issued.retire_prior_to, issued.connection_id),
        .retire_connection_id => |retired| try quic_frame.retire_connection_id(text, retired.sequence_number),
        .path_challenge => |challenge| try quic_frame.path_challenge(text, challenge.data),
        .path_response => |response| try quic_frame.path_response(text, response.data),
        .connection_close => |close| try write_close(text, close),
        .handshake_done => try quic_frame.handshake_done(text),
    }
}

fn write_ack(text: *TextWriter, ack: frame_module.Ack, ack_delay_exponent: u64) qlog.Error!void {
    // RFC 9000 §19.3: microseconds, scaled by 2 to the power of the exponent.
    const delay_ns = (ack.delay <<| @as(u6, @intCast(ack_delay_exponent))) *| constants.nanoseconds_per_microsecond;
    try quic_frame.ack_begin(text, delay_ns);
    var walk = ack.ranges.iterator();
    // Bounded by the frame's own count of ranges, which `frame_ack.read` walked once already.
    while (walk.next()) |range| try quic_frame.ack_range(text, range.smallest, range.largest);
    const ecn = ack.ecn orelse return quic_frame.ack_end(text, null);
    try quic_frame.ack_end(text, .{ .ect0 = ecn.ect_0, .ect1 = ecn.ect_1, .ce = ecn.ecn_ce });
}

fn write_close(text: *TextWriter, close: frame_module.frame_control.ConnectionClose) qlog.Error!void {
    const space: quic_frame.ErrorSpace = switch (close.layer) {
        .transport => .transport,
        .application => .application,
    };
    try quic_frame.connection_close(text, space, close.error_code, close.frame_type, close.reason);
}

fn directionality_of(directionality: frame_module.Directionality) quic_frame.Directionality {
    return switch (directionality) {
        .bidirectional => .bidirectional,
        .unidirectional => .unidirectional,
    };
}

/// Quic-events §8.6's name for the packets of `level`. colibri sends and opens no 0-RTT packet
/// (decision 20), so the application level is 1-RTT.
fn packet_type_of(level: Level) quic_event.PacketType {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .@"1RTT",
    };
}

/// RFC 9000 §18.2: the peer's exponent, or 3 until its parameters arrive.
fn peer_ack_delay_exponent(connection: *const Connection) u64 {
    const peer = connection.peer_parameters orelse return transport_parameters.default_ack_delay_exponent;
    return peer.ack_delay_exponent;
}

/// Quic-events §5.7's trigger for each reason `connection_receive` drops a packet.
fn dropped_trigger(why: receive_module.Discarded) @FieldType(quic_event.PacketDropped, "trigger") {
    return switch (why) {
        .unreadable_header => .invalid,
        .other_connection, .other_source => .connection_unknown,
        .no_keys => .key_unavailable,
        .would_not_open => .decryption_failure,
        .already_processed => .duplicate,
        .not_for_this_walk => .unsupported,
    };
}

test {
    _ = @import("connection_qlog_test.zig");
}
