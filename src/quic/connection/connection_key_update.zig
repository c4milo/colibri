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
//! **Where the rest of §6 lives.** §6.2's last paragraph needs an ACK frame's contents beside the
//! key set, so `acknowledges_newer_keys` is the state and `connection_frames.take_ack` is the
//! check. §6.6's limits are counted by the suite, so they arrive as a refusal to seal or to open:
//! `packet_build` answers the first with `initiate_at_aead_limit` and `connection_receive` ends
//! the walk on the second.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const crypto = @import("crypto");
const error_code = @import("../error_code.zig");
const connection_module = @import("connection.zig");

const Level = core.Level;
const KeySet = crypto.suite.KeySet;
const Suite = crypto.Suite;
const Connection = connection_module.Connection;

/// What RFC 9001 §6 has a connection remember about its key phase. colibri holds no key
/// (decision 48), so all of it is packet numbers and instants; the keys themselves, and which
/// phase they are in, are the suite's.
pub const Phase = struct {
    /// The lowest packet number processed under the current key phase, or null before any
    /// (§6.5). It is what tells a delayed packet of the previous phase from the first of the
    /// next, because the two carry the same Key Phase bit.
    current_lowest: ?u64,
    /// The lowest packet number sent under the current key phase, or null before any (§6.1).
    /// Against the largest number the peer acknowledged in the 1-RTT space it is what says
    /// whether another key update may be initiated.
    lowest_sent: ?u64,
    /// Whether this endpoint answered a key update and has not yet sent a 1-RTT packet carrying
    /// an acknowledgment under the new keys (§6.2). A second update while it is true is the peer
    /// updating twice without awaiting confirmation.
    pending_ack: bool,
    /// Whether the suite still holds the read keys of the phase before (§6.5). False before the
    /// first key update, and false again once colibri told the suite to forget them.
    previous_held: bool,
    /// The instant a packet protected with the current phase's keys was received, or null before
    /// one was. §6.5 measures the retention of the old read keys from it.
    previous_since_ns: ?u64,
    /// The instant an acknowledgment first confirmed the current phase, or null before one did.
    /// §6.5 measures its wait before the next key update from it.
    confirmed_at_ns: ?u64,

    pub fn init(phase: *Phase) void {
        phase.* = .{
            .current_lowest = null,
            .lowest_sent = null,
            .pending_ack = false,
            .previous_held = false,
            .previous_since_ns = null,
            .confirmed_at_ns = null,
        };
    }
};

/// The packet that started a key update this endpoint answered (RFC 9001 §6.2), or null when
/// this endpoint initiated one itself (§6.1).
const Answered = struct {
    packet_number: u64,
    received_at_ns: u64,
};

/// Why RFC 9001 §6.1 does not permit a key update now. None of these is the peer's doing and none
/// closes the connection: the endpoint asked too early and asks again later.
pub const InitiateError = error{
    /// RFC 9001 §6.1: the handshake is not confirmed yet (§4.1.2).
    HandshakeNotConfirmed,
    /// RFC 9001 §6.1: no packet sent under the current key phase has been acknowledged.
    PhaseNotAcknowledged,
    /// RFC 9001 §6.5: the acknowledgment that confirmed the current phase is less than three
    /// Probe Timeouts old, so the peer may still be unable to read a packet under new keys.
    PhaseNotSettled,
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
pub fn initiate(connection: *Connection, suite: Suite, now_ns: u64) InitiateError!void {
    // §6.1's two rules are MUSTs and are asked first; §6.5's wait sits over the top of them.
    try permitted(connection);
    // RFC 9001 §6.5: "Endpoints SHOULD wait three times the PTO before initiating a key update
    // after receiving an acknowledgment that confirms that the previous key update was received."
    if (!settled(connection, now_ns)) return InitiateError.PhaseNotSettled;
    return move_phase(connection, suite);
}

/// The key update RFC 9001 §6.6 demands when the keys will protect nothing more. It skips §6.5's
/// wait and nothing else: §6.5's wait is a SHOULD about packets the peer might discard, where
/// §6.6's update is a MUST about what the AEAD is still safe to protect.
pub fn initiate_at_aead_limit(connection: *Connection, suite: Suite) InitiateError!void {
    try permitted(connection);
    return move_phase(connection, suite);
}

/// RFC 9001 §6.1's two refusals, which every key update this endpoint starts is held to.
fn permitted(connection: *Connection) InitiateError!void {
    // §6.1: "An endpoint MUST NOT initiate a key update prior to having confirmed the handshake
    // (Section 4.1.2)."
    if (!connection.handshake_confirmed) return InitiateError.HandshakeNotConfirmed;
    // §6.1: "An endpoint MUST NOT initiate a subsequent key update unless it has received an
    // acknowledgment for a packet that was sent protected with keys from the current key phase."
    // The first update is held to it too, because §6.1's own recipe does not except it and a
    // phase nothing was sent in is one no peer can have acknowledged.
    if (!current_phase_acknowledged(connection)) return InitiateError.PhaseNotAcknowledged;
}

/// Tells the suite to move both directions to the next phase (RFC 9001 §6.1).
fn move_phase(connection: *Connection, suite: Suite) InitiateError!void {
    try suite.vtable.update_keys(suite.context);
    // §6.1: "The endpoint that initiates a key update also updates the keys that it uses for
    // receiving packets", so nothing has been processed under the new read keys either.
    enter_next_phase(&connection.key_phase, null);
    assert(connection.key_phase.lowest_sent == null);
    assert(!connection.key_phase.pending_ack);
}

/// Whether RFC 9001 §6.5's wait since the current phase was acknowledged has passed.
fn settled(connection: *const Connection, now_ns: u64) bool {
    const confirmed_at_ns = connection.key_phase.confirmed_at_ns orelse return false;
    return now_ns >= confirmed_at_ns +| three_probe_timeouts_ns(connection);
}

/// The period RFC 9001 §6.5 measures both of its waits in. The `true` includes the peer's
/// max_ack_delay (RFC 9002 §6.2.1), which applies to the application level, and §6.1's Note
/// leaves every other level's keys unupdated anyway.
fn three_probe_timeouts_ns(connection: *const Connection) u64 {
    return constants.key_update_probe_timeouts *| connection.recovery.rtt.probe_timeout_ns(true);
}

/// RFC 9001 §6.5's "acknowledgment that confirms that the previous key update was received",
/// which is the first acknowledgment of a packet sent under the current key phase (§6.1). The
/// frame layer calls it once a peer's ACK has been taken.
pub fn on_ack_processed(connection: *Connection, level: Level, now_ns: u64) void {
    if (level != .application) return;
    if (connection.key_phase.confirmed_at_ns != null) return;
    if (!current_phase_acknowledged(connection)) return;
    connection.key_phase.confirmed_at_ns = now_ns;
    assert(connection.key_phase.confirmed_at_ns != null);
}

/// The instant RFC 9001 §6.5 has the previous read keys discarded, or null when none are held or
/// nothing has arrived under the new ones yet.
pub fn previous_keys_deadline_ns(connection: *const Connection) ?u64 {
    const since_ns = connection.key_phase.previous_since_ns orelse return null;
    // The instant is recorded only while the keys are held, and discarding them clears both, so
    // one field answers: a phase with an instant here has keys left to discard.
    assert(connection.key_phase.previous_held);
    return since_ns +| three_probe_timeouts_ns(connection);
}

/// RFC 9001 §6.5: "An endpoint SHOULD retain old read keys for no more than three times the PTO
/// after having received a packet protected using the new keys. After this period, old read keys
/// and their corresponding secrets SHOULD be discarded."
///
/// It is public because a caller driving timers may reach the instant before a packet does; the
/// receive path calls it on every 1-RTT packet that opens, which is when colibri hears a clock.
pub fn on_instant(connection: *Connection, suite: Suite, now_ns: u64) void {
    const phase = &connection.key_phase;
    if (!phase.previous_held) return;
    const since_ns = phase.previous_since_ns orelse return;
    if (now_ns < since_ns +| three_probe_timeouts_ns(connection)) return;
    suite.vtable.discard_previous_keys(suite.context);
    phase.previous_held = false;
    phase.previous_since_ns = null;
    assert(!phase.previous_held);
}

/// RFC 9001 §6.1: "This can be implemented by tracking the lowest packet number sent with each
/// key phase and the highest acknowledged packet number in the 1-RTT space: once the latter is
/// higher than or equal to the former, another key update can be initiated."
fn current_phase_acknowledged(connection: *Connection) bool {
    const lowest = connection.key_phase.lowest_sent orelse return false;
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
    now_ns: u64,
) Error!void {
    switch (key_set) {
        .current => note_current_phase(connection, packet_number, now_ns),
        .next => try answer_key_update(connection, suite, packet_number, now_ns),
        .previous => try refuse_old_above_current(connection, packet_number),
    }
    // RFC 9001 §6.5 times the old read keys from a packet arriving under the new ones, and a
    // packet arriving is when colibri is told an instant at all.
    on_instant(connection, suite, now_ns);
}

/// RFC 9001 §6.5: "A recovered packet number that is lower than any packet number from the
/// current key phase uses the previous packet protection keys", so what the suite is given is the
/// lowest number that opened under the current keys and not the first one to arrive.
fn note_current_phase(connection: *Connection, packet_number: u64, now_ns: u64) void {
    const phase = &connection.key_phase;
    const lowest = phase.current_lowest orelse std.math.maxInt(u64);
    phase.current_lowest = @min(lowest, packet_number);
    // RFC 9001 §6.5 retains the old read keys from "having received a packet protected using the
    // new keys", which for a phase this endpoint initiated is the first one to arrive under it.
    if (phase.previous_held and phase.previous_since_ns == null) phase.previous_since_ns = now_ns;
    assert(phase.current_lowest != null);
    assert(phase.current_lowest.? <= packet_number);
}

/// RFC 9001 §6.2: "If a packet is successfully processed using the next key and IV, then the peer
/// has initiated a key update. The endpoint MUST update its send keys to the corresponding key
/// phase in response". Updating before the receive path returns is what holds §6.2's "Sending
/// keys MUST be updated before sending an acknowledgment for the packet that was received with
/// updated keys", whatever the send path writes next.
fn answer_key_update(connection: *Connection, suite: Suite, packet_number: u64, now_ns: u64) Error!void {
    // RFC 9001 §6.2: an update detected before this endpoint has "sent any packets with updated
    // keys containing an acknowledgment for the packet that initiated the key update ... indicates
    // that its peer has updated keys twice without awaiting confirmation".
    if (connection.key_phase.pending_ack) return Error.ConsecutiveKeyUpdate;
    suite.vtable.update_keys(suite.context) catch return Error.SuiteRefusedUpdate;
    // §6.5: this packet is itself protected with the new keys, so it starts the retention of the
    // old read keys.
    enter_next_phase(&connection.key_phase, .{ .packet_number = packet_number, .received_at_ns = now_ns });
    assert(connection.key_phase.pending_ack);
    assert(connection.key_phase.current_lowest.? == packet_number);
}

/// RFC 9001 §6.4: "An endpoint that successfully removes protection with old keys when newer keys
/// were used for packets with lower packet numbers MUST treat this as a connection error of type
/// KEY_UPDATE_ERROR." The lowest number processed under the current keys is that comparison.
fn refuse_old_above_current(connection: *const Connection, packet_number: u64) Error!void {
    const lowest = connection.key_phase.current_lowest orelse return;
    if (packet_number > lowest) return Error.OldKeysAboveCurrentPhase;
}

/// Whether RFC 9001 §6.2's last rule refuses this acknowledgment: it arrived in a packet opened
/// with the previous keys, and it names a packet this endpoint protected with the current ones.
/// §6.2 says what that means — "a peer has received and acknowledged a packet that initiates a
/// key update, but has not updated keys in response".
///
/// RFC 9000 §19.3 makes Largest Acknowledged a packet the frame acknowledges, and no number it
/// names is above that one, so it alone answers §6.2's "any acknowledged packet".
pub fn acknowledges_newer_keys(connection: *const Connection, key_set: KeySet, largest: u64) bool {
    if (key_set != .previous) return false;
    // RFC 9001 §6.1: every packet numbered from here up went out under the current key phase.
    const lowest = connection.key_phase.lowest_sent orelse return false;
    return largest >= lowest;
}

/// One packet this endpoint sealed (RFC 9001 §6.1, §6.2). The send path calls it once per packet,
/// after the suite protected it, because a packet that would not seal never went out.
pub fn on_packet_sent(connection: *Connection, level: Level, packet_number: u64, carries_ack: bool) void {
    // §6.1's Note again: nothing below the application level has a key phase to move.
    if (level != .application) return;
    // RFC 9001 §6.1: the lowest packet number sent with the current key phase, which is the first
    // one sent since the phase changed.
    if (connection.key_phase.lowest_sent == null) connection.key_phase.lowest_sent = packet_number;
    // RFC 9001 §6.2: "By acknowledging the packet that triggered the key update in a packet
    // protected with the updated keys, the endpoint signals that the key update is complete."
    if (carries_ack) connection.key_phase.pending_ack = false;
    assert(connection.key_phase.lowest_sent != null);
    assert(connection.key_phase.lowest_sent.? <= packet_number);
}

/// Every field a phase change moves, in one place so they cannot disagree. `answered` is the
/// peer's packet that started this update, or null when this endpoint started it.
fn enter_next_phase(phase: *Phase, answered: ?Answered) void {
    phase.current_lowest = if (answered) |held| held.packet_number else null;
    // RFC 9001 §6.1: the count starts again, because no packet has gone out under the new keys.
    phase.lowest_sent = null;
    // RFC 9001 §6.2: only an update this endpoint answered owes an acknowledgment under the new
    // keys; one it started is the peer's to answer.
    phase.pending_ack = answered != null;
    // RFC 9001 §6.1: "An endpoint MUST retain old keys until it has successfully unprotected a
    // packet sent using the new keys", and §6.5 says how much longer than that.
    phase.previous_held = true;
    phase.previous_since_ns = if (answered) |held| held.received_at_ns else null;
    // §6.5: nothing has acknowledged the new phase yet.
    phase.confirmed_at_ns = null;
}

test {
    _ = @import("connection_key_update_test.zig");
    _ = @import("connection_key_update_limit_test.zig");
}
