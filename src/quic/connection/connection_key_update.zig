//! RFC 9001 §6's key update, which is timing and nothing else. colibri holds no key (decision
//! 48), so every rule here is about when it tells the caller's `crypto.Suite` to move to the next
//! key phase, and when it refuses.
//!
//! **Three moments.** §6.1 has this endpoint start one, which the application asks for and
//! `initiate` permits or refuses. §6.2 has it answer one, which `on_packet_opened` reaches when a
//! packet opens under the next keys. §6.2 and §6.4 turn two orderings only a peer can produce
//! into a connection error of type KEY_UPDATE_ERROR.
//!
//! **What the connection remembers.** §6.1 states its own recipe — "tracking the lowest packet
//! number sent with each key phase and the highest acknowledged packet number in the 1-RTT space"
//! — and that is `Connection.phase_lowest_sent` against what the application space already holds.
//! §6.5 needs the lowest packet number *processed* under the current phase, which is
//! `Connection.current_phase_lowest`, because a delayed packet of the phase before carries the
//! same Key Phase bit as the first of the phase after.
//!
//! **What is not here.** §6.5's discard of the previous read keys is a SHOULD measured in three
//! Probe Timeouts, and nothing drives a timer yet. §6.6's AEAD limits are the suite's counts, and
//! the send path does not act on them yet. §6.2's last paragraph — an acknowledgment carried in a
//! packet protected with old keys that names a packet protected with newer ones — needs the ACK's
//! contents beside the key set, which `connection_frames.process` is not told.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const error_code = @import("../error_code.zig");
const connection_module = @import("connection.zig");

const Level = core.Level;
const KeySet = crypto.suite.KeySet;
const Suite = crypto.Suite;
const Connection = connection_module.Connection;

/// Why RFC 9001 §6.1 does not permit a key update now. None of these is the peer's doing and none
/// closes the connection: the endpoint asked too early and asks again later.
pub const InitiateError = error{
    /// RFC 9001 §6.1: the handshake is not confirmed yet (§4.1.2).
    HandshakeNotConfirmed,
    /// RFC 9001 §6.1: no packet sent under the current key phase has been acknowledged.
    PhaseNotAcknowledged,
} || crypto.suite.UpdateError;

/// Why a packet that opened ended the connection. `connection_error_code` says which code the
/// CONNECTION_CLOSE carries (RFC 9000 §20.1).
pub const Error = error{
    /// RFC 9001 §6.2: the peer updated keys a second time before this endpoint acknowledged the
    /// first update under the new keys.
    ConsecutiveKeyUpdate,
    /// RFC 9001 §6.4: a packet opened with the previous keys although a lower-numbered packet had
    /// opened with the current ones.
    OldKeysAboveCurrentPhase,
    /// The suite opened a packet with its next keys and then would not move to them. It is the
    /// caller's code contradicting itself, so it is not a KEY_UPDATE_ERROR.
    SuiteRefusedUpdate,
};

/// The code a CONNECTION_CLOSE carries for `failure`.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        // RFC 9001 §6.7: "The KEY_UPDATE_ERROR error code (0x0e) is used to signal errors related
        // to key updates", which is what §6.2 and §6.4 each name.
        error.ConsecutiveKeyUpdate, error.OldKeysAboveCurrentPhase => error_code.key_update_error,
        // RFC 9000 §11: an endpoint with no more specific code sends INTERNAL_ERROR.
        error.SuiteRefusedUpdate => error_code.internal_error,
    };
}

/// Starts a key update (RFC 9001 §6.1). The application decides when; this answers whether §6.1
/// permits it, and when it does it tells the suite to move both directions to the next phase.
pub fn initiate(connection: *Connection, suite: Suite) InitiateError!void {
    // RFC 9001 §6.1: "An endpoint MUST NOT initiate a key update prior to having confirmed the
    // handshake (Section 4.1.2)."
    if (!connection.handshake_confirmed) return InitiateError.HandshakeNotConfirmed;
    // RFC 9001 §6.1: "An endpoint MUST NOT initiate a subsequent key update unless it has
    // received an acknowledgment for a packet that was sent protected with keys from the current
    // key phase." The first update is held to it too, because §6.1's own recipe does not except
    // it and a phase nothing was sent in is one no peer can have acknowledged.
    if (!current_phase_acknowledged(connection)) return InitiateError.PhaseNotAcknowledged;
    try suite.vtable.update_keys(suite.context);
    // §6.1: "The endpoint that initiates a key update also updates the keys that it uses for
    // receiving packets", so nothing has been processed under the new read keys either.
    enter_next_phase(connection, null, false);
    assert(connection.phase_lowest_sent == null);
    assert(!connection.pending_phase_ack);
}

/// RFC 9001 §6.1: "This can be implemented by tracking the lowest packet number sent with each
/// key phase and the highest acknowledged packet number in the 1-RTT space: once the latter is
/// higher than or equal to the former, another key update can be initiated."
fn current_phase_acknowledged(connection: *Connection) bool {
    const lowest = connection.phase_lowest_sent orelse return false;
    const acknowledged = connection.space_at(.application).largest_acknowledged orelse return false;
    return acknowledged >= lowest;
}

/// What a 1-RTT packet that opened means for the key phase (RFC 9001 §6.2, §6.4, §6.5). The
/// receive path calls it for an application-level packet and for no other: §6.1's Note says
/// "Keys of packets other than the 1-RTT packets are never updated".
pub fn on_packet_opened(
    connection: *Connection,
    suite: Suite,
    packet_number: u64,
    key_set: KeySet,
) Error!void {
    switch (key_set) {
        .current => note_current_phase(connection, packet_number),
        .next => try answer_key_update(connection, suite, packet_number),
        .previous => try refuse_old_above_current(connection, packet_number),
    }
}

/// RFC 9001 §6.5: "A recovered packet number that is lower than any packet number from the
/// current key phase uses the previous packet protection keys", so what the suite is given is the
/// lowest number that opened under the current keys and not the first one to arrive.
fn note_current_phase(connection: *Connection, packet_number: u64) void {
    const lowest = connection.current_phase_lowest orelse std.math.maxInt(u64);
    connection.current_phase_lowest = @min(lowest, packet_number);
    assert(connection.current_phase_lowest != null);
    assert(connection.current_phase_lowest.? <= packet_number);
}

/// RFC 9001 §6.2: "If a packet is successfully processed using the next key and IV, then the peer
/// has initiated a key update. The endpoint MUST update its send keys to the corresponding key
/// phase in response". Updating before the receive path returns is what holds §6.2's "Sending
/// keys MUST be updated before sending an acknowledgment for the packet that was received with
/// updated keys", whatever the send path writes next.
fn answer_key_update(connection: *Connection, suite: Suite, packet_number: u64) Error!void {
    // RFC 9001 §6.2: an update detected before this endpoint has "sent any packets with updated
    // keys containing an acknowledgment for the packet that initiated the key update ... indicates
    // that its peer has updated keys twice without awaiting confirmation".
    if (connection.pending_phase_ack) return Error.ConsecutiveKeyUpdate;
    suite.vtable.update_keys(suite.context) catch return Error.SuiteRefusedUpdate;
    enter_next_phase(connection, packet_number, true);
    assert(connection.pending_phase_ack);
    assert(connection.current_phase_lowest.? == packet_number);
}

/// RFC 9001 §6.4: "An endpoint that successfully removes protection with old keys when newer keys
/// were used for packets with lower packet numbers MUST treat this as a connection error of type
/// KEY_UPDATE_ERROR." The lowest number processed under the current keys is that comparison.
fn refuse_old_above_current(connection: *const Connection, packet_number: u64) Error!void {
    const lowest = connection.current_phase_lowest orelse return;
    if (packet_number > lowest) return Error.OldKeysAboveCurrentPhase;
}

/// One packet this endpoint sealed (RFC 9001 §6.1, §6.2). The send path calls it once per packet,
/// after the suite protected it, because a packet that would not seal never went out.
pub fn on_packet_sent(connection: *Connection, level: Level, packet_number: u64, carries_ack: bool) void {
    // §6.1's Note again: nothing below the application level has a key phase to move.
    if (level != .application) return;
    // RFC 9001 §6.1: the lowest packet number sent with the current key phase, which is the first
    // one sent since the phase changed.
    if (connection.phase_lowest_sent == null) connection.phase_lowest_sent = packet_number;
    // RFC 9001 §6.2: "By acknowledging the packet that triggered the key update in a packet
    // protected with the updated keys, the endpoint signals that the key update is complete."
    if (carries_ack) connection.pending_phase_ack = false;
    assert(connection.phase_lowest_sent != null);
    assert(connection.phase_lowest_sent.? <= packet_number);
}

/// The three fields a phase change moves, in one place so they cannot disagree.
fn enter_next_phase(connection: *Connection, current_phase_lowest: ?u64, pending_phase_ack: bool) void {
    connection.current_phase_lowest = current_phase_lowest;
    // RFC 9001 §6.1: the count starts again, because no packet has gone out under the new keys.
    connection.phase_lowest_sent = null;
    connection.pending_phase_ack = pending_phase_ack;
}

test {
    _ = @import("connection_key_update_test.zig");
}
