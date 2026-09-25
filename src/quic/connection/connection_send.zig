//! One UDP datagram, assembled out of the packets RFC 9000 §12.2 lets a sender coalesce.
//!
//! **Every packet is planned before any is sealed.** §14.1 makes a client expand a datagram
//! carrying an Initial to 1,200 octets, and [decision 54](../../../docs/decisions.md) puts that
//! expansion on the datagram's last packet. The AEAD covers the payload, so PADDING cannot be
//! appended after `seal` — the assembler plans each level, learns which packet is last, pads
//! that one and seals them all.
//!
//! **What bounds a datagram, in the order it is asked.** The caller's buffer, then the maximum
//! datagram size (RFC 9000 §14.2), then §8's anti-amplification limit, which is the server's
//! alone (§8.1, invariant 18). The last is checked before the datagram is returned and
//! not after, because `Path.on_datagram_sent` asserts it and an assertion is not a check.
//!
//! **It records what it sends, and the congestion window bounds it.** Decision 59 has the
//! connection drive RFC 9002's loss recovery, so each packet that counts in flight goes into
//! `connection.recovery` here, at the instant the caller passed. RFC 9002 §7 keeps the bytes in
//! flight within the congestion window, and a level the window holds back sends only what adds
//! nothing in flight: ACK frames (§2). colibri waits until the window holds the rest of the
//! datagram rather than cut a packet short, so §14.1's padding fits in it too.
//!
//! **Two more rules expand a datagram.** RFC 9000 §8.2.1 and §8.2.2 ask for 1,200 octets around a
//! PATH_CHALLENGE and a PATH_RESPONSE, and both except the anti-amplification limit — which
//! `datagram_ceiling` has already bounded the datagram by, so the padding stops there on its own
//! and §8.2.3's second validation is what the short datagram leaves owed.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const tls = @import("tls");
const constants = @import("../constants.zig");
const frame_module = @import("../frame/frame.zig");
const connection_module = @import("connection.zig");
const packet_build = @import("packet_build/packet_build.zig");
const connection_close = @import("connection_close.zig");
const transport_parameters = @import("../transport_parameters.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const keys_module = @import("connection_keys.zig");
const connection_crypto = @import("connection_crypto.zig");
const connection_handshake = @import("connection_handshake.zig");
const space_module = @import("../space/space.zig");
const connection_expand = @import("connection_expand.zig");
const migration = @import("connection_migration.zig");
const path_module = @import("../path.zig");
const PeerAddress = @import("../peer_address.zig").PeerAddress;
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
/// The ECN codepoint of a datagram's IP header (RFC 9000 §13.4), which the caller writes.
pub const Ecn = recovery_sent.Ecn;

pub const Error = packet_build.Error || error{
    /// RFC 9001 §8.2: the handshake completed while this datagram was framed, and the peer's
    /// transport parameters never arrived.
    ParametersMissing,
};

/// The code a CONNECTION_CLOSE carries for `failure`, or null when none goes out.
pub fn connection_error_code(failure: Error) ?u64 {
    // RFC 9001 §8.2: a missing extension is a TRANSPORT_PARAMETER_ERROR (RFC 9000 §7.4).
    if (failure == error.ParametersMissing) return connection_crypto.connection_error_code(error.ParametersMissing);
    return packet_build.connection_error_code(@errorCast(failure));
}

/// Where a datagram's packets are framed before any is sealed. One payload buffer per encryption
/// level, because §12.2 coalesces one packet of each and all three are planned before the first
/// is protected. The caller places it (decision 35).
pub fn Scratch(comptime capacity: usize) type {
    return struct {
        header: [constants.packet_header_len_max]u8 = undefined,
        payloads: [core.levels_count][capacity]u8 = undefined,

        pub const payload_len_max: usize = capacity;
    };
}

/// The scratch a caller gets by asking for no size in particular: RFC 9000 §14.1's smallest
/// allowed maximum datagram size, which decision 54 makes the default.
pub const DefaultScratch = Scratch(constants.datagram_len_min);

/// One packet of the datagram, as the caller reports it to RFC 9002's recovery.
pub const Packet = struct {
    level: Level,
    packet_number: u64,
    /// Octets it occupies, which §8 counts and RFC 9002 §7.2 measures the congestion window in.
    len: usize,
    ack_eliciting: bool,
    in_flight: bool,
    /// RFC 9000 §13.3: the CRYPTO or STREAM octets this packet carried, which the caller keeps in
    /// its `recovery_sent.Record` so a loss can say which octets to send again.
    carries: recovery_sent.Carries = .none,
    data_offset: u64 = 0,
    data_len: u16 = 0,
    stream_id: u64 = 0,
};

/// What was assembled.
pub const Sent = struct {
    /// Octets of `output` the datagram occupies.
    len: usize,
    packets: [core.levels_count]Packet,
    count: usize,
    /// The ECN codepoint the caller sets in the datagram's IP header (RFC 9000 §13.4, decision
    /// 68). Not-ECT unless the connection was opened with `ecn_marks`.
    ecn: Ecn = .not_ect,
    /// The address the caller sends the datagram to (decision 72): the active path's, or the
    /// previous path's for the PATH_CHALLENGE RFC 9000 §9.3.3 sends there.
    to: PeerAddress = .{},

    pub fn written(sent: *const Sent) []const Packet {
        return sent.packets[0..sent.count];
    }
};

/// Owes `count` probe packets at `level`, which RFC 9002's PTO asks for (`Recovery.Action.probe`,
/// Appendix A.9). §6.2.4: "When a PTO timer expires, a sender MUST send at least one
/// ack-eliciting packet in the packet number space as a probe", and "All probe packets sent on a
/// PTO MUST be ack-eliciting". Each ack-eliciting packet `send` builds at `level` counts off one;
/// one that would elicit nothing carries a PING, which §6.2.4 asks for "When there is no data to
/// send". A probe never repeats a range still in flight (invariant 29).
pub fn owe_probes(connection: *Connection, level: Level, count: u8) void {
    assert(count > 0 and count <= constants.probe_packets);
    const owed = &connection.probes_owed[@intFromEnum(level)];
    owed.* = @max(owed.*, count);
}

/// Assembles one datagram into the front of `output`. Null when there is nothing to send, which
/// is the ordinary answer whenever the connection is idle.
pub fn send(
    connection: *Connection,
    suite: crypto.Suite,
    provider: tls.QuicProvider,
    stream_provider: StreamProvider,
    scratch: anytype,
    output: []u8,
    now_ns: u64,
) Error!?Sent {
    // RFC 9000 §10.2.2: "an endpoint in the draining state MUST NOT send any packets", and the
    // same answer covers a connection whose closing period has ended (§10.2).
    if (connection.termination.permission() == .send_nothing) return null;
    // Decision 62: a level whose keys the caller's code gave the suite since the last call can
    // carry a packet in this datagram.
    keys_module.take_available(connection, suite);
    keys_module.take_lost(connection, suite);
    if (migration.owes_previous_probe(connection)) {
        if (try send_previous_probe(connection, suite, provider, stream_provider, scratch, output, now_ns)) |sent| return sent;
    }
    // A ceiling too small for a level's packet is `plan`'s to find (`error.NoSpaceLeft`): a
    // 1-RTT packet's header is far shorter than an Initial's, and RFC 9000 §8.2.1 still wants a
    // PATH_CHALLENGE sent on a new path whose §8 limit is a few dozen octets.
    const ceiling = @min(output.len, datagram_ceiling(connection));
    var plans: [core.levels_count]packet_build.Planned = undefined;
    var count: usize = 0;
    var planned_len: usize = 0;
    const window = window_of(connection, ceiling, now_ns);
    // RFC 9000 §12.2: "Coalescing packets in order of increasing encryption levels ... makes it
    // more likely that the receiver will be able to process all the packets in a single pass",
    // and a short header carries no Length so §12.2 makes it the last packet anyway.
    for (0..core.levels_count) |index| {
        const level: Level = @enumFromInt(index);
        const room = room_on_path(connection, level, window.len -| planned_len, ceiling - planned_len) orelse continue;
        const payload = &scratch.payloads[index];
        const planned = packet_build.plan(connection, provider, stream_provider, level, payload, room, now_ns) catch |failure| switch (failure) {
            // A level that cannot fit a packet in what is left ends the datagram rather than
            // failing it: §12.2 coalesces what fits and the rest goes in the next one.
            error.NoSpaceLeft => break,
            else => return failure,
        } orelse continue;
        plans[count] = planned;
        count += 1;
        planned_len += packet_len_of(connection, planned);
    }
    if (count == 0) return null;
    connection_expand.expand_last(connection, plans[0..count], planned_len, ceiling);
    var sent = try seal_all(connection, suite, scratch, plans[0..count], output);
    sent.ecn = codepoint_of(connection, now_ns);
    sent.to = connection.path.address;
    const recorded = record_all(connection, plans[0..count], &sent, now_ns);
    if (window.past_window and recorded) connection.recovery.congestion.past_window_allowed = false;
    // After the records, because discarding the Initial keys discards the Initial space's records
    // too (RFC 9002 §6.4), and an Initial packet coalesced ahead of this one is among them.
    note_handshake_sent(connection, suite, plans[0..count]);
    note_close_sent(connection, plans[0..count], now_ns);
    note_ack_eliciting_sent(connection, &sent, now_ns);
    note_challenge_sent(connection, plans[0..count], sent.len, now_ns);
    try note_handshake_complete(connection, provider, suite);
    return sent;
}

/// RFC 9000 §9.3.3's PATH_CHALLENGE to the previously active path, in a datagram of its own that
/// carries probing frames alone (§9.1), because §9.3 sends every other frame to the new address.
/// The paths are swapped while it is built, so the path frames, §8's limit and §8.2.1's
/// expansion all read the previous one. Loss recovery keeps no record of it: §9.4 says "Packets
/// sent on the old path MUST NOT contribute to congestion control or RTT estimation for the new
/// path", and §8.2.4's timer is what notices its loss.
fn send_previous_probe(
    connection: *Connection,
    suite: crypto.Suite,
    provider: tls.QuicProvider,
    stream_provider: StreamProvider,
    scratch: anytype,
    output: []u8,
    now_ns: u64,
) Error!?Sent {
    const previous = &connection.migration.previous.?;
    std.mem.swap(path_module.Path, &connection.path, previous);
    defer std.mem.swap(path_module.Path, &connection.path, previous);
    const ceiling = @min(output.len, datagram_ceiling(connection));
    const payload = &scratch.payloads[@intFromEnum(Level.application)];
    // RFC 9000 §12.5: a PATH_CHALLENGE goes only in a 1-RTT packet, which `plan` refuses to build
    // without its keys.
    const room: packet_build.Room = .{ .len = ceiling, .probing_only = true };
    const planned = try packet_build.plan(connection, provider, stream_provider, .application, payload, room, now_ns) orelse return null;
    var plans = [_]packet_build.Planned{planned};
    connection_expand.expand_last(connection, &plans, packet_len_of(connection, planned), ceiling);
    var sent = try seal_all(connection, suite, scratch, &plans, output);
    sent.to = connection.path.address;
    note_challenge_sent(connection, &plans, sent.len, now_ns);
    return sent;
}

/// RFC 9001 §4.1.1: "the TLS handshake is considered complete when the TLS stack has reported
/// that the handshake is complete". A client's stack reports it once its Finished is written,
/// which happens while a datagram is framed, so `send` asks as `connection_datagram.receive` does
/// (decision 60).
fn note_handshake_complete(connection: *Connection, provider: tls.QuicProvider, suite: crypto.Suite) Error!void {
    _ = connection_handshake.complete(connection, provider, suite) catch |failure| switch (failure) {
        error.ParametersMissing => return Error.ParametersMissing,
        // `complete` refuses nothing else: it reads the provider and changes no flow.
        else => unreachable,
    };
}

/// What RFC 9002 §7's congestion window leaves this datagram.
const Window = struct {
    /// Octets the packets of the datagram may add to the bytes in flight.
    len: u64,
    /// Whether that is §7.3.2's one datagram past the window, which sending it spends.
    past_window: bool,
};

fn window_of(connection: *Connection, ceiling: usize, now_ns: u64) Window {
    const recovery = &connection.recovery;
    const datagram_len = @min(ceiling, recovery.congestion.max_datagram_len);
    const window_len = recovery.congestion.available_len(recovery.in_flight_len());
    // RFC 9002 §7.7: "A sender SHOULD pace sending of all in-flight packets based on input from
    // the congestion controller." The pacer's credit is brought up to this instant first.
    recovery.pacer.refill(now_ns, recovery.rate());
    const available_len = recovery.available_len();
    const congestion_limited = window_len < datagram_len;
    connection.pacing_limited = !congestion_limited and available_len < datagram_len;
    // RFC 9002 §7.8: the window is underused only when "sending is not pacing limited", so a
    // sender the pacer holds is using its window as fully as one the window holds.
    connection.window_limited = congestion_limited or connection.pacing_limited;
    // RFC 9002 §7.3.2: on entering recovery "a single packet can be sent prior to reduction".
    const past_window = congestion_limited and recovery.congestion.past_window_allowed;
    return .{ .len = if (past_window) datagram_len else available_len, .past_window = past_window };
}

/// The instant the pacer will let the next datagram out (RFC 9002 §7.7), or null when the last
/// `send` was not held back by it. The caller calls `send` again then.
pub fn pacing_deadline_ns(connection: *const Connection) ?u64 {
    if (!connection.pacing_limited) return null;
    const recovery = &connection.recovery;
    return recovery.pacer.next_send_at_ns(recovery.congestion.max_datagram_len, recovery.rate());
}

/// `room_at`, on a path that may be waiting for validation. Decision 72: until a path the peer
/// moved to is validated, §8 limits what may go there to three times what arrived, and the
/// PATH_CHALLENGE frames §13.3 sends until one is answered need those octets more than data.
fn room_on_path(connection: *const Connection, level: Level, window_len: u64, room: usize) ?packet_build.Room {
    if (!connection.migration.awaiting_validation or level != .application) return room_at(connection, level, window_len, room);
    // RFC 9000 §9.4: "Packets sent on the old path MUST NOT contribute to congestion control or
    // RTT estimation for the new path", and "A sender can make exceptions for probe packets". So
    // the octets still in flight to the old address hold back nothing here: the packet carries ACK
    // and path frames alone, and §8's limit is what bounds it.
    return .{ .len = room, .withholding_data = true };
}

/// What `level`'s packet may hold, given the octets `window_len` the congestion window leaves and
/// the octets `room` the datagram leaves. Null when the level sends nothing in this datagram.
fn room_at(connection: *const Connection, level: Level, window_len: u64, room: usize) ?packet_build.Room {
    // RFC 9000 §10.2.1: a closing endpoint "retains only enough information to generate a packet
    // containing a CONNECTION_CLOSE frame", so no recovery state bounds it, and §10.2.1's own
    // limit on how often it answers is the caller's to keep.
    if (connection_close.owes(connection)) return .{ .len = room };
    const kind: space_module.Kind = @enumFromInt(@intFromEnum(level));
    // `constants.sent_packets_max`: a space whose table is full waits for an acknowledgment, and
    // RFC 9002 Appendix A.1 tracks every ack-eliciting packet, so none goes until one arrives.
    if (connection.recovery.tables[@intFromEnum(kind)].is_full()) return null;
    if (in_flight_len_allowed(connection, level, window_len, room)) |len| return .{ .len = len };
    // RFC 9000 §14.1: "A client MUST expand the payload of all UDP datagrams carrying Initial
    // packets", and RFC 9002 §2 counts that PADDING in flight, so a client the window holds back
    // sends no Initial at all.
    if (connection.role == .client and level == .initial) return null;
    return .{ .len = room, .in_flight_allowed = false };
}

/// The octets `level`'s packet may add to the bytes in flight, or null when the congestion window
/// allows it none.
fn in_flight_len_allowed(connection: *const Connection, level: Level, window_len: u64, room: usize) ?usize {
    // RFC 9002 §7: the window binds every packet "unless the packet is sent on a PTO timer
    // expiration".
    if (connection.probes_owed[@intFromEnum(level)] > 0) return room;
    // RFC 9002 §7: "An endpoint MUST NOT send a packet if it would cause bytes_in_flight ... to be
    // larger than the congestion window." colibri waits for a whole datagram's worth of window.
    if (window_len < @min(room, connection.recovery.congestion.max_datagram_len)) return null;
    return @intCast(@min(room, window_len));
}

/// RFC 9000 §10.1: "An endpoint also restarts its idle timer when sending an ack-eliciting packet
/// if no other ack-eliciting packets have been sent since last receiving and processing a packet."
/// `Termination.on_ack_eliciting_sent` answers the second half.
fn note_ack_eliciting_sent(connection: *Connection, sent: *const Sent, now_ns: u64) void {
    // Bounded by the levels: a datagram coalesces at most one packet of each (§12.2).
    for (sent.written()) |packet| {
        if (packet.ack_eliciting) connection.termination.on_ack_eliciting_sent(now_ns);
    }
}

/// RFC 9001 §4.9.1: "a client MUST discard Initial keys when it first sends a Handshake packet".
/// `connection_keys` answers for the role and for a level already discarded.
fn note_handshake_sent(connection: *Connection, suite: crypto.Suite, plans: []const packet_build.Planned) void {
    // Bounded by the levels: a datagram coalesces at most one packet of each (§12.2).
    for (plans) |planned| {
        if (planned.level == .handshake) keys_module.on_handshake_packet_sent(connection, suite);
    }
}

/// RFC 9002 Appendix A.5's `OnPacketSent` for each packet of the datagram that counts in flight.
/// A.1: "a QUIC sender tracks every ack-eliciting packet until the packet is acknowledged or
/// lost". A packet of ACK frames alone is not tracked: nothing in it is sent again (RFC 9000
/// §13.3), and a peer need not acknowledge it (§13.2.1), so its record would hold a slot of the
/// table until loss detection gave it up. Its ECN codepoint is still counted, because the peer
/// counts it (RFC 9000 §13.4.1).
/// True when any packet was recorded, which is what spends §7.3.2's datagram past the window.
fn record_all(connection: *Connection, plans: []const packet_build.Planned, sent: *const Sent, now_ns: u64) bool {
    var recorded = false;
    // Bounded by the levels: a datagram coalesces at most one packet of each (§12.2).
    for (plans, sent.written()) |planned, packet| {
        const kind: space_module.Kind = @enumFromInt(@intFromEnum(packet.level));
        // RFC 9000 §10.2.1: a closing endpoint keeps nothing a CONNECTION_CLOSE does not need.
        if (!packet.in_flight or planned.carries_close) {
            connection.recovery.on_packet_sent_unrecorded(kind, sent.ecn, now_ns);
            continue;
        }
        // `room_at` framed nothing at a level whose table was full, so the record fits.
        connection.recovery.on_packet_sent(kind, record_of(packet, sent.ecn, now_ns), now_ns) catch unreachable;
        recorded = true;
    }
    return recorded;
}

/// The codepoint the next datagram carries (decision 68). RFC 9000 §13.4.2: "The endpoint sets
/// an ECT(0) codepoint in the IP header of early outgoing packets sent on a new path", and the
/// path's test decides after that (decision 69). A caller that sets no codepoint gets Not-ECT,
/// which is what it sends.
fn codepoint_of(connection: *Connection, now_ns: u64) Ecn {
    if (!connection.ecn_marks) return .not_ect;
    return connection.recovery.ecn_codepoint(now_ns);
}

/// The record RFC 9002 Appendix A.1.1 keeps of `packet`, which went out in a datagram marked
/// `ecn`. RFC 9000 §13.4.2.1 judges the peer's counts against these marks.
fn record_of(packet: Packet, ecn: Ecn, now_ns: u64) recovery_sent.Record {
    return .{
        .number = packet.packet_number,
        .sent_at_ns = now_ns,
        .sent_len = @intCast(packet.len),
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .carries = packet.carries,
        .data_offset = packet.data_offset,
        .data_len = packet.data_len,
        .stream_id = packet.stream_id,
        .ecn = ecn,
    };
}

/// RFC 9000 §8.2.1: the datagram exists now, so its length is what says whether the path MTU is
/// being validated along with the address, and §8.2.4's timer starts from here.
fn note_challenge_sent(connection: *Connection, plans: []const packet_build.Planned, len: usize, now_ns: u64) void {
    for (plans) |planned| {
        const data = planned.path_challenge orelse continue;
        connection.path.on_challenge_sent(data, len, now_ns, challenge_timeout_ns(connection));
        return;
    }
}

/// RFC 9000 §8.2.4: "A value of three times the larger of the current PTO or the PTO for the new
/// path (using kInitialRtt, as defined in [QUIC-RECOVERY]) is RECOMMENDED", because "the new path
/// could have a longer round-trip time than the original".
fn challenge_timeout_ns(connection: *const Connection) u64 {
    const rtt = &connection.recovery.rtt;
    const larger_ns = @max(rtt.probe_timeout_ns(true), rtt.new_path_probe_timeout_ns());
    return constants.path_probe_timeouts *| larger_ns;
}

/// RFC 9000 §10.2: "After sending a CONNECTION_CLOSE frame, an endpoint immediately enters the
/// closing state." The datagram exists by the time this runs, so the state follows the packet
/// rather than the intention to send one.
fn note_close_sent(connection: *Connection, plans: []const packet_build.Planned, now_ns: u64) void {
    var carried = false;
    for (plans) |planned| carried = carried or planned.carries_close;
    if (!carried) return;
    // §10.2: the closing period is three times the Probe Timeout, which `take_close` sizes the
    // draining period with too. The `true` asks for the one that includes the peer's
    // max_ack_delay: §10.2 asks for "at least" three PTOs, so the longer answer is the safe one
    // when a close goes out before the application level is in use.
    const probe_timeout_ns = connection.recovery.rtt.probe_timeout_ns(true);
    connection.termination.on_close_sent(now_ns, probe_timeout_ns);
}

/// Octets a planned packet will occupy once sealed: its header with any widening of its packet
/// number, its payload and the tag.
fn packet_len_of(connection: *Connection, planned: packet_build.Planned) usize {
    _ = connection;
    const header_len = planned.shape.header_len + packet_build.widening_len(planned);
    return header_len + planned.payload_len + planned.padding_len + constants.aead_tag_len;
}

/// What bounds a datagram besides the caller's buffer, in the order the file header names them.
///
/// The maximum datagram size is the one RFC 9002's congestion controller counts in, which
/// `Connection.init` sets to §14.1's smallest allowed maximum datagram size. colibri runs neither
/// PMTUD nor DPLPMTUD, and §14.2 says "In the absence of these mechanisms, QUIC endpoints SHOULD
/// NOT send datagrams larger than the smallest allowed maximum datagram size."
///
/// The peer's `max_udp_payload_size` (§18.2) never binds below that size, because §18.2 makes
/// "Values below 1200" invalid and `transport_parameters` refuses them. A discovery that raised
/// the maximum would have to bound it by the peer's value, which is what the assertion guards.
///
/// §8.1's anti-amplification limit bounds it too, and it is a bound and not an assertion: a
/// server that has received nothing may send nothing, which is the ordinary state of every server
/// at the start of a connection rather than a defect in colibri.
fn datagram_ceiling(connection: *const Connection) usize {
    // RFC 9000 §14.2: no datagram above the maximum datagram size, which no discovery has raised.
    const maximum = connection.recovery.congestion.max_datagram_len;
    assert(maximum == constants.datagram_len_min);
    // §21.1.1.1 exempts a client, whose allowance `Path` answers as unlimited (invariant 18).
    return @intCast(@min(maximum, connection.path.send_allowance()));
}

/// Seals every planned packet into `output`, in the order they were planned (RFC 9000 §12.2).
fn seal_all(
    connection: *Connection,
    suite: crypto.Suite,
    scratch: anytype,
    plans: []const packet_build.Planned,
    output: []u8,
) Error!Sent {
    var sent: Sent = .{ .len = 0, .packets = undefined, .count = 0 };
    for (plans) |planned| {
        const payload = &scratch.payloads[@intFromEnum(planned.level)];
        // RFC 9000 §19.1: PADDING is octets of 0x00, and a run of them is one frame to a reader.
        @memset(payload[planned.payload_len..][0..planned.padding_len], 0);
        const built = try packet_build.seal_planned(
            connection,
            suite,
            planned,
            &scratch.header,
            payload,
            output[sent.len..],
        );
        sent.packets[sent.count] = .{
            .level = built.level,
            .packet_number = built.packet_number,
            .len = built.len,
            .ack_eliciting = built.ack_eliciting,
            .in_flight = built.in_flight,
            .carries = built.carries,
            .data_offset = built.data_offset,
            .data_len = built.data_len,
            .stream_id = built.stream_id,
        };
        sent.count += 1;
        sent.len += built.len;
    }
    // RFC 9000 §8, invariant 18: the limit counts whole datagrams and is checked before one is
    // returned, never after. `Path.on_datagram_sent` asserts the same thing, and an assertion is
    // colibri's own defect rather than a check on what it may send.
    assert(!connection.path.is_amplification_limited(sent.len));
    connection.path.on_datagram_sent(sent.len);
    return sent;
}

test {
    _ = @import("connection_send_test.zig");
    _ = @import("connection_send_window_test.zig");
    _ = @import("connection_ecn_test.zig");
}
