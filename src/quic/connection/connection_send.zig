//! One UDP datagram, assembled out of the packets RFC 9000 §12.2 lets a sender coalesce.
//!
//! **Every packet is planned before any is sealed.** §14.1 makes a client expand a datagram
//! carrying an Initial to 1,200 octets, and [decision 54](../../../docs/decisions.md) puts that
//! expansion on the datagram's last packet. The AEAD covers the payload, so PADDING cannot be
//! appended after `seal` — the assembler plans each level, learns which packet is last, pads
//! that one and seals them all.
//!
//! **What bounds a datagram, in the order it is asked.** The caller's buffer, then the peer's
//! `max_udp_payload_size` (RFC 9000 §18.2), then §8's anti-amplification limit, which is the
//! server's alone (§8.1, invariant 18). The last is checked before the datagram is returned and
//! not after, because `Path.on_datagram_sent` asserts it and an assertion is not a check.
//!
//! **It tells recovery nothing on its own.** RFC 9002's loss recovery is the caller's to drive,
//! so `Sent` reports every packet and the caller records them. That keeps the instant a
//! parameter and leaves the timers to the piece design §8 step 9e still owes.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const tls = @import("tls");
const constants = @import("../constants.zig");
const frame_module = @import("../frame/frame.zig");
const connection_module = @import("connection.zig");
const packet_build = @import("packet_build.zig");
const transport_parameters = @import("../transport_parameters.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;

pub const Error = packet_build.Error;

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
};

/// What was assembled.
pub const Sent = struct {
    /// Octets of `output` the datagram occupies.
    len: usize,
    packets: [core.levels_count]Packet,
    count: usize,

    pub fn written(sent: *const Sent) []const Packet {
        return sent.packets[0..sent.count];
    }
};

/// Assembles one datagram into the front of `output`. Null when there is nothing to send, which
/// is the ordinary answer whenever the connection is idle.
pub fn send(
    connection: *Connection,
    suite: crypto.Suite,
    provider: tls.QuicProvider,
    scratch: anytype,
    output: []u8,
    now_ns: u64,
) Error!?Sent {
    const ceiling = @min(output.len, datagram_ceiling(connection));
    if (ceiling < constants.packet_header_len_max) return null;
    var plans: [core.levels_count]packet_build.Planned = undefined;
    var count: usize = 0;
    var planned_len: usize = 0;
    // RFC 9000 §12.2: "Coalescing packets in order of increasing encryption levels ... makes it
    // more likely that the receiver will be able to process all the packets in a single pass",
    // and a short header carries no Length so §12.2 makes it the last packet anyway.
    for (0..core.levels_count) |index| {
        const level: Level = @enumFromInt(index);
        const room = ceiling - planned_len;
        const payload = &scratch.payloads[index];
        const planned = packet_build.plan(connection, provider, level, payload, room, now_ns) catch |failure| switch (failure) {
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
    expand_last(connection, plans[0..count], planned_len, ceiling);
    return try seal_all(connection, suite, scratch, plans[0..count], output);
}

/// Octets a planned packet will occupy once sealed: its header, its payload and the tag.
fn packet_len_of(connection: *Connection, planned: packet_build.Planned) usize {
    _ = connection;
    return planned.shape.header_len + planned.payload_len + planned.padding_len + constants.aead_tag_len;
}

/// RFC 9000 §18.2's `max_udp_payload_size`, which is what the peer said it can receive. Before
/// the handshake carries it, §14.1's smallest allowed maximum datagram is all colibri may assume.
fn datagram_ceiling(connection: *const Connection) usize {
    const peer = connection.peer_parameters orelse return constants.datagram_len_min;
    return @intCast(@min(peer.max_udp_payload_size, constants.datagram_len_max));
}

/// RFC 9000 §14.1's expansion, put on the datagram's last packet by decision 54.
fn expand_last(connection: *Connection, plans: []packet_build.Planned, planned_len: usize, ceiling: usize) void {
    if (!owes_expansion(connection, plans)) return;
    if (planned_len >= constants.datagram_len_min) return;
    const wanted = constants.datagram_len_min - planned_len;
    const last = &plans[plans.len - 1];
    // The padding goes in the last packet's payload, so it is bounded by what that payload's
    // buffer still holds as well as by what the datagram needs.
    last.padding_len = @min(wanted, room_for_padding(last, ceiling, planned_len));
}

/// How many octets of PADDING the last packet can still take.
fn room_for_padding(last: *const packet_build.Planned, ceiling: usize, planned_len: usize) usize {
    const spare_in_datagram = ceiling - planned_len;
    const spare_in_packet = last.shape.room - last.payload_len;
    return @min(spare_in_datagram, spare_in_packet);
}

/// Whether RFC 9000 §14.1 requires this datagram to reach 1,200 octets. "A client MUST expand the
/// payload of all UDP datagrams carrying Initial packets ... Similarly, a server MUST expand the
/// payload of all UDP datagrams carrying ack-eliciting Initial packets."
fn owes_expansion(connection: *const Connection, plans: []const packet_build.Planned) bool {
    for (plans) |planned| {
        if (planned.level != .initial) continue;
        if (connection.role == .client) return true;
        // §14.1 asks a server only for the ack-eliciting ones, so an Initial carrying nothing but
        // an acknowledgment costs a server no padding.
        return planned.ack_eliciting;
    }
    return false;
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
}
