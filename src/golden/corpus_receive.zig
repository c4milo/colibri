//! Decodes a `quic_receive` corpus case: one datagram walked by the version 1 receive path
//! (`connection_receive.zig`) at a client in a state the case names. Split off `corpus.zig`, which
//! reads formats a decoder takes whole; this one needs a connection and a suite around it.
//!
//! The verdict is what the walk says of the first packet it does not hand on: a discard, named as
//! an error after `connection_receive.Discarded`, or the connection error the walk returns. A case
//! whose every packet opens is accepted. Each packet that opens is recorded in its space as the
//! caller records it (RFC 9000 §13.1), so a repeat inside one datagram is a duplicate (§12.3).
//!
//! The suite is the corpus's own, because the golden module is given `quic` and not `sim`. It
//! protects nothing: a packet's number is its one octet after the header, and the last octet of
//! its 16-octet tag names the keys that open it. That models what a real suite learns by trying
//! its keys (RFC 9001 §5.5, §6.3), so every verdict a key state produces is a matter of octets a
//! mutation can edit.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("constants.zig");
const cases = @import("corpus_cases.zig");

const crypto = quic.crypto;
const Level = quic.core.Level;
const Connection = quic.Connection;
const receive = quic.connection_receive;
const ReceiveState = cases.ReceiveState;

/// A discard, as the error a case's verdict names (`connection_receive.Discarded`).
pub const DiscardError = error{
    UnreadableHeader,
    OtherConnection,
    OtherSource,
    NoKeys,
    WouldNotOpen,
    AlreadyProcessed,
    NotForThisWalk,
};

pub const Error = DiscardError || receive.Error;

const tag_len = crypto.constants.aead_tag_len;
const marker_current = cases.marker_current;
const marker_next = cases.marker_next;
const marker_previous = cases.marker_previous;

/// The client's connection ID, which every case's packets are addressed to, and the one it first
/// addressed the server by (RFC 9000 §7.2).
const client_id = cases.receive_client_id;
const original_octet: u8 = 0x05;
const original_id: [client_id.len]u8 = @splat(original_octet);
/// The current phase's lowest packet number in `current_phase_from_4` (RFC 9001 §6.5).
pub const current_phase_lowest: u64 = 4;
const test_now_ns: u64 = 1_000_000;

/// The connection, the suite and the octets one case runs over, outside any stack frame and reset
/// per case (decision 35).
var connection: Connection = undefined;
var suite_state: GoldenSuite = .{};
var octets_held: [constants.case_len_max]u8 = undefined;

pub fn decode(state: ReceiveState, octets: []const u8) Error!void {
    assert(octets.len <= octets_held.len);
    open_client(state);
    @memcpy(octets_held[0..octets.len], octets);
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = octets_held[0..octets.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const suite = suite_state.suite();
    // Bounded: every outcome advances the walk or ends it, and a datagram holds at most
    // `coalesced_packets_max` packets.
    for (0..quic.constants.coalesced_packets_max + 1) |_| {
        const outcome = try receive.next(&walk, &connection, suite) orelse return;
        const opened = switch (outcome) {
            .opened => |held| held,
            .discarded => |reason| return discard_error(reason),
        };
        // RFC 9000 §13.1: the packet is recorded once processed, which here is once opened.
        _ = connection.space_at(opened.level).receive(opened.packet_number, test_now_ns, false, .not_ect);
    }
    unreachable;
}

fn discard_error(reason: receive.Discarded) DiscardError {
    return switch (reason) {
        .unreadable_header => error.UnreadableHeader,
        .other_connection => error.OtherConnection,
        .other_source => error.OtherSource,
        .no_keys => error.NoKeys,
        .would_not_open => error.WouldNotOpen,
        .already_processed => error.AlreadyProcessed,
        .not_for_this_walk => error.NotForThisWalk,
    };
}

/// A client in `state`.
fn open_client(state: ReceiveState) void {
    suite_state = .{
        .previous_held = state == .current_phase_from_4,
        .integrity_exhausted = state == .integrity_exhausted,
    };
    connection.init(.{
        .role = .client,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &client_id, .original_destination = &original_id },
    });
    const levels: []const Level = if (state == .initial_only) &.{.initial} else &.{ .initial, .handshake, .application };
    // Bounded by the three levels of RFC 9001 §4.1.4.
    for (levels) |level| quic.connection_keys.on_keys_installed(&connection, level, .read);
    connection.handshake_complete = state != .handshake_pending and state != .initial_only;
    switch (state) {
        .complete, .handshake_pending, .initial_only, .integrity_exhausted => {},
        // RFC 9001 §6.2: an update answered and not yet acknowledged under the new keys.
        .update_unacknowledged => connection.key_phase.pending_ack = true,
        // RFC 9001 §6.5: the previous phase's keys held, and the current one begun at 4.
        .current_phase_from_4 => {
            connection.key_phase.current_lowest = current_phase_lowest;
            connection.key_phase.previous_held = true;
        },
    }
}

/// What the client grants: any window at all, which `Connection.init` requires.
fn parameters() quic.transport_parameters.Parameters {
    var held = quic.transport_parameters.Parameters.initial();
    held.initial_max_data = client_window;
    return held;
}

const client_window: u64 = 65_536;

/// The corpus's suite. Only `open`, and what the receive path calls around it, is reached.
const GoldenSuite = struct {
    /// Whether the previous phase's read keys are held (RFC 9001 §6.5).
    previous_held: bool = false,
    /// Whether more packets have failed than the integrity limit permits (RFC 9001 §6.6).
    integrity_exhausted: bool = false,

    fn suite(self: *GoldenSuite) crypto.Suite {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    fn open(context: *anyopaque, opening: crypto.suite.Opening) crypto.suite.OpenError!crypto.suite.Opened {
        const self: *GoldenSuite = @ptrCast(@alignCast(context));
        if (self.integrity_exhausted) return error.IntegrityLimitReached;
        const protected_len = opening.packet.len - opening.packet_number_offset;
        // A number and a tag, whose last octet is the marker.
        if (protected_len < 1 + tag_len) return error.Discarded;
        const key_set = key_set_of(self, opening.level, opening.packet[opening.packet.len - 1]) orelse
            return error.Discarded;
        return .{
            .packet_number = opening.packet[opening.packet_number_offset],
            .packet_number_len = 1,
            .payload_len = protected_len - 1 - tag_len,
            .key_set = key_set,
        };
    }

    /// The keys `marker` names, or null when none this suite holds opens the packet. RFC 9001
    /// §6.1's Note: "Keys of packets other than the 1-RTT packets are never updated".
    fn key_set_of(self: *const GoldenSuite, level: Level, marker: u8) ?crypto.suite.KeySet {
        if (marker == marker_current) return .current;
        if (level != .application) return null;
        if (marker == marker_next) return .next;
        if (marker == marker_previous and self.previous_held) return .previous;
        return null;
    }

    fn update_keys(_: *anyopaque) crypto.suite.UpdateError!void {}
    fn key_phase(_: *const anyopaque) bool {
        return false;
    }
    fn discard_previous_keys(_: *anyopaque) void {}
    fn discard_keys(_: *anyopaque, _: Level) void {}
    fn keys_available(_: *const anyopaque, _: Level, _: crypto.suite.Direction) bool {
        return true;
    }
    fn install_initial_keys(_: *anyopaque, _: crypto.suite.Role, _: []const u8) crypto.suite.InstallError!void {}
    fn seal(_: *anyopaque, _: crypto.suite.Sealing, _: []u8) crypto.suite.SealError!usize {
        unreachable;
    }
    fn retry_tag_valid(_: *const anyopaque, _: []const u8, _: *const [crypto.constants.retry_integrity_tag_len]u8) bool {
        unreachable;
    }
    fn retry_tag_write(_: *const anyopaque, _: []const u8, _: *[crypto.constants.retry_integrity_tag_len]u8) crypto.suite.RetryTagError!void {
        unreachable;
    }
    fn retry_token_write(_: *anyopaque, _: []const u8, _: *const crypto.suite.RetryConnectionIds, _: u64, _: []u8) crypto.suite.TokenError!usize {
        unreachable;
    }
    fn retry_token_check(_: *const anyopaque, _: []const u8, _: []const u8, _: u64) crypto.suite.TokenCheck {
        unreachable;
    }

    const table: crypto.suite.VTable = .{
        .install_initial_keys = install_initial_keys,
        .keys_available = keys_available,
        .seal = seal,
        .open = open,
        .retry_tag_valid = retry_tag_valid,
        .retry_tag_write = retry_tag_write,
        .retry_token_write = retry_token_write,
        .retry_token_check = retry_token_check,
        .update_keys = update_keys,
        .key_phase = key_phase,
        .discard_previous_keys = discard_previous_keys,
        .discard_keys = discard_keys,
    };
};
