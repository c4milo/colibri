//! One UDP datagram, walked into the packets RFC 9000 §12.2 coalesced into it.
//!
//! The caller read the octets and owns them. This file separates the datagram into packets,
//! decides which encryption level each belongs to, and hands each one to the caller's
//! `crypto.Suite` to open. What a packet's frames mean is `connection_frames.zig`'s.
//!
//! **Almost everything here is a discard rather than an error.** Until the AEAD tag matches,
//! nothing in a packet is the peer's word for anything: §12.2 says that when a packet fails to
//! open the receiver "MUST attempt to process the remaining packets", and RFC 9001 §5.5 makes an
//! undecryptable packet something to drop rather than close on. So the walk carries on past a
//! packet it could not read, and only a packet that opened can produce a connection error.
//!
//! **A datagram is not a packet.** §12.2's Length field is what ends a long-header packet, and a
//! short header, a Retry and a Version Negotiation packet carry no Length, so each of those is
//! the last thing in its datagram. The walk ends on them rather than guessing where the next
//! packet would start.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const header = @import("../packet/packet_header.zig");
const connection_module = @import("connection.zig");
const keys_module = @import("connection_keys.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Suite = crypto.Suite;

/// What arrived, which is the caller's to describe because colibri owns no socket.
pub const Datagram = struct {
    /// The octets, which `crypto.Suite.open` unprotects in place, so they are writable.
    octets: []u8,
    /// The instant it arrived (non-negotiable 3).
    now_ns: u64,
    /// The ECN codepoint of its IP header (RFC 9000 §13.4), which the caller reads.
    ecn: Ecn,

    pub const Ecn = @import("../space/space.zig").Space.Ecn;
};

/// Why a packet was not processed. None of these closes the connection: RFC 9000 §12.2 and
/// RFC 9001 §5.5 both make an unreadable packet a discard, because nothing in it is authentic.
pub const Discarded = enum {
    /// The header did not parse, so where the packet ends is unknown and the walk must stop.
    unreadable_header,
    /// RFC 9000 §12.2: "Receivers SHOULD ignore any subsequent packets with a different
    /// Destination Connection ID than the first packet in the datagram."
    other_connection,
    /// RFC 9001 §4.9, §5.7: the level's keys are absent, discarded, or not yet permitted.
    no_keys,
    /// RFC 9001 §5.5: the AEAD tag did not match.
    would_not_open,
    /// RFC 9000 §12.3: this number was processed before, or is below what the space remembers.
    already_processed,
    /// A Retry, a Version Negotiation or a packet of another version. Each is handled elsewhere
    /// and none may be followed by another packet (§12.2).
    not_for_this_walk,
};

/// What one packet of the datagram turned into.
pub const Outcome = union(enum) {
    /// It opened and its payload is ready for the frame layer, at `level`.
    opened: Opened,
    /// It was dropped, for a reason that is never the peer's fault to close on.
    discarded: Discarded,
};

pub const Opened = struct {
    level: Level,
    packet_number: u64,
    /// The frames, which `crypto.Suite.open` left in place inside the datagram.
    payload: []const u8,
};

/// Where the walk has got to in one datagram. The caller drives it, because the frame layer sits
/// between two packets and this file does not own it.
pub const Walk = struct {
    datagram: Datagram,
    /// Octets of `datagram.octets` already walked past.
    consumed: usize,
    /// The Destination Connection ID of the first packet, which §12.2 makes every later packet
    /// of the datagram match.
    first_destination: ?[]const u8,
    /// How many packets this walk has separated, which bounds it (non-negotiable 4).
    packets: usize,

    pub fn init(walk: *Walk, datagram: Datagram) void {
        assert(datagram.octets.len <= constants.datagram_len_max);
        walk.* = .{
            .datagram = datagram,
            .consumed = 0,
            .first_destination = null,
            .packets = 0,
        };
    }

    /// Whether any octets are left to walk.
    pub fn finished(walk: *const Walk) bool {
        return walk.consumed >= walk.datagram.octets.len or
            walk.packets >= constants.coalesced_packets_max;
    }
};

/// Separates and opens the next packet of `walk`. Null when the datagram is spent.
///
/// Every return advances `walk` past the packet it describes, or ends the walk, so a caller that
/// loops until null terminates: RFC 9000 §12.2's Length is what says where a long-header packet
/// ends, and every other form is the last in its datagram.
pub fn next(walk: *Walk, connection: *Connection, suite: Suite) ?Outcome {
    if (walk.finished()) return null;
    walk.packets += 1;
    const rest = walk.datagram.octets[walk.consumed..];
    const parsed = header.read(rest, connection.identity.local_len()) catch {
        // The header did not parse, so nothing says where this packet ends. RFC 9000 §12.2 asks
        // a receiver to process the remaining packets, and there is no way to find them.
        walk.consumed = walk.datagram.octets.len;
        return .{ .discarded = .unreadable_header };
    };
    return switch (parsed) {
        .long => |long| open_long(walk, connection, suite, long, rest),
        .short => |short| open_short(walk, connection, suite, short, rest),
        // §12.2: a Retry, a Version Negotiation and a packet of another version carry no Length
        // and cannot be followed by another packet, so the walk ends whatever the caller does
        // with them.
        else => end_walk(walk),
    };
}

fn end_walk(walk: *Walk) Outcome {
    walk.consumed = walk.datagram.octets.len;
    return .{ .discarded = .not_for_this_walk };
}

/// An Initial or Handshake packet, which RFC 9001 Table 1 pairs with its encryption level.
fn open_long(walk: *Walk, connection: *Connection, suite: Suite, long: header.Long, rest: []u8) Outcome {
    const level: Level = switch (long.type) {
        .initial => .initial,
        .handshake => .handshake,
        // Decision 20 refuses 0-RTT, so colibri installs no keys for it and never opens one.
        // RFC 9001 §5.7 makes an unopenable packet a discard, which is what this is.
        .zero_rtt => return advance(walk, long.packet_len, .no_keys),
        // `header.read` answers `.retry` for a Retry, so this arm cannot be reached.
        .retry => unreachable,
    };
    if (!matches_first_destination(walk, long.dcid)) {
        return advance(walk, long.packet_len, .other_connection);
    }
    const packet = rest[0..long.packet_len];
    return open_at(walk, connection, suite, level, packet, long.packet_number_offset, long.packet_len);
}

/// A 1-RTT packet, which RFC 9000 §17.3 makes the last of its datagram: a short header carries no
/// Length, so `packet_len` is the whole remainder.
fn open_short(walk: *Walk, connection: *Connection, suite: Suite, short: header.Short, rest: []u8) Outcome {
    if (!matches_first_destination(walk, short.dcid)) {
        return advance(walk, short.packet_len, .other_connection);
    }
    const packet = rest[0..short.packet_len];
    return open_at(walk, connection, suite, .application, packet, short.packet_number_offset, short.packet_len);
}

/// Asks the suite to open one packet, having first asked whether the level may be read at all.
fn open_at(
    walk: *Walk,
    connection: *Connection,
    suite: Suite,
    level: Level,
    packet: []u8,
    packet_number_offset: usize,
    packet_len: usize,
) Outcome {
    // RFC 9001 §4.9 and §5.7: a level colibri never installed, already discarded, or may not read
    // yet is not one to call `open` at. Invariant 21 is this check.
    if (!keys_module.can_open(connection, level, connection.handshake_complete)) {
        return advance(walk, packet_len, .no_keys);
    }
    const space = connection.space_at(level);
    const opened = suite.open(.{
        .level = level,
        .packet = packet,
        .packet_number_offset = packet_number_offset,
        // RFC 9000 Appendix A.3: the truncated number is recovered against the largest already
        // received in this space, and in no other.
        .largest_packet_number = space.received.largest(),
        // RFC 9001 §6.5: at the application level a delayed packet of the previous key phase
        // carries the same Key Phase bit as the first of the next, and this is what tells them
        // apart. It is null at the handshake levels, which have no key update.
        .current_phase_lowest = if (level == .application) connection.current_phase_lowest else null,
    }) catch {
        // RFC 9001 §5.5: "an endpoint MUST NOT fail the connection" over a packet that did not
        // authenticate, so it is dropped and the walk goes on to the next.
        return advance(walk, packet_len, .would_not_open);
    };
    // RFC 9000 §12.3: the duplicate check happens after protection is removed and before the
    // frames are processed, which is why the space is asked rather than told here.
    if (space.duplicate_verdict(opened.packet_number) != .new) {
        return advance(walk, packet_len, .already_processed);
    }
    walk.consumed += packet_len;
    const payload_start = packet_number_offset + opened.packet_number_len;
    return .{ .opened = .{
        .level = level,
        .packet_number = opened.packet_number,
        .payload = packet[payload_start..][0..opened.payload_len],
    } };
}

/// Steps past a packet that will not be processed, so §12.2's remaining packets still are.
fn advance(walk: *Walk, packet_len: usize, why: Discarded) Outcome {
    assert(packet_len > 0);
    walk.consumed += packet_len;
    return .{ .discarded = why };
}

/// RFC 9000 §12.2: "Receivers SHOULD ignore any subsequent packets with a different Destination
/// Connection ID than the first packet in the datagram." The first packet's is what the rest are
/// held to, and it is remembered here rather than compared against what colibri issued, because
/// §12.2 is about one datagram being one connection's.
fn matches_first_destination(walk: *Walk, dcid: []const u8) bool {
    const first = walk.first_destination orelse {
        walk.first_destination = dcid;
        return true;
    };
    return std.mem.eql(u8, first, dcid);
}

test {
    _ = @import("connection_receive_test.zig");
}
