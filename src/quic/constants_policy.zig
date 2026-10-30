//! The values colibri chose for quic within what the RFCs allow, which size nothing.
//! Decision 137 groups them, and `constants.zig` exports this file as `policy`.
const std = @import("std");
const assert = std.debug.assert;

/// How many PATH_CHALLENGE frames one attempt at validating a new path sends, each with data of
/// its own. RFC 9000 §13.3 sends one "periodically until a matching PATH_RESPONSE frame is
/// received", and §8.2.4 gives the attempt three PTOs, so colibri sends one each PTO.
pub const path_challenge_attempts: u8 = 3;
/// The ones after the first, which the caller hands over with the first (decision 72).
pub const path_challenge_resends: u8 = path_challenge_attempts - 1;

/// How many packets of ACK frames alone an endpoint sends at the application level before RFC
/// 9000 §13.2.4's PING may join the next (decision 73). The answer to a PING is one such packet,
/// so with two the answers never ask for answers of their own.
pub const ack_only_packets_before_ping: u8 = 2;

/// Ack-eliciting packets a receiver takes before it sends an ACK frame (RFC 9000 §13.2.2): a
/// receiver SHOULD send one after at least two.
pub const ack_eliciting_before_ack: u64 = 2;

/// Probe Timeouts the closing and draining states last, and the floor RFC 9000 §10.1 puts under
/// the idle timeout: §10.2 says both states SHOULD persist for at least three times the current
/// PTO, and §10.1 says the idle period MUST be at least that too, so several probes can be sent
/// and lost before a connection is given up.
pub const close_probe_timeouts: u64 = 3;

/// Probe Timeouts a flow control limited endpoint with nothing in flight waits before it sends
/// its BLOCKED frames again. RFC 9000 §4.1 says only "periodically", to keep the peer's idle
/// timeout from closing the connection, so the period is colibri's. One PTO is longer than a
/// round trip, so a frame is not repeated before an answer could arrive, and the idle timeout is
/// at least `close_probe_timeouts` of them (§10.1), so the frame goes out before it runs out.
pub const blocked_repeat_probe_timeouts: u64 = 1;

/// Probe Timeouts RFC 9001 §6.5 measures both of its key update waits in: an endpoint "SHOULD
/// retain old read keys for no more than three times the PTO after having received a packet
/// protected using the new keys", and "SHOULD wait three times the PTO before initiating a key
/// update after receiving an acknowledgment that confirms that the previous key update was
/// received".
pub const key_update_probe_timeouts: u64 = 3;

/// Probe Timeouts RFC 9000 §8.2.4 gives a path validation before it is abandoned: "A value of
/// three times the larger of the current PTO or the PTO for the new path ... is RECOMMENDED",
/// which "allows for multiple PTOs to expire prior to failing path validation, so that loss of a
/// single PATH_CHALLENGE or PATH_RESPONSE frame does not cause path validation failure".
pub const path_probe_timeouts: u64 = 3;

/// How the answers of a closing endpoint thin out (RFC 9000 §10.2.1): each one waits for this
/// many times as many received packets as the last, which is the "progressively increasing
/// number of received packets" the section offers.
pub const close_answer_backoff: u64 = 2;

/// When a receiver advertises more flow control credit (RFC 9000 §4.2, which leaves the timing
/// to the implementation): once the peer has used this fraction of the window, so that a round
/// trip of silence would leave it blocked. A larger fraction sends fewer frames and risks the
/// peer stalling; a smaller one spends frames on credit the peer has not asked for.
pub const flow_credit_fraction: u64 = 2;

/// How the receive window grows (decision 49). A receiver that credits again within this many
/// round trips was draining faster than the peer could learn of the room, so the window and not
/// the path is the limit, and it is multiplied by the factor below. Two round trips is what
/// Chromium's QUIC, quiche and TCP's receive buffer auto-tuning all settle on: one for the
/// credit to reach the peer and one for the data to come back.
pub const flow_tune_round_trips: u64 = 2;
pub const flow_window_growth: u64 = 2;

/// RFC 9000 §13.4.2: an endpoint "could set an ECT codepoint for only the first ten outgoing
/// packets on a path, or for a period of three PTOs". Decision 69 ends a path's ECN test at
/// whichever comes first.
pub const ecn_testing_packets: u64 = 10;
pub const ecn_testing_probe_timeouts: u64 = 3;

/// The fewest octets of room for which a packet tries one more STREAM frame (RFC 9000 §19.8).
pub const stream_frame_room_min: usize = 8;

/// The fewest 1-RTT packets colibri sends between two packet numbers it skips (RFC 9000 §21.4).
/// Each interval adds one octet the caller drew at start, so a skip comes 128 to 383 packets
/// after the one before: often enough to catch a peer that acknowledges packets it never
/// received, and seldom enough that a peer's ACK frames carry few gaps for them.
pub const packet_number_skip_interval_min: u16 = 128;

/// The priority a stream sends at until the caller sets one (RFC 9000 §2.3). A lower value goes
/// first, and this is the middle of the range, so the caller can put a stream before or after the
/// rest.
pub const stream_priority_default: u8 = 128;

/// Decision 65: how many times per connection a server sends its Initial CRYPTO octets again at
/// once, before the PTO, when its client shows it lacks them (RFC 9002 §6.2.3). §6.2.3 limits it
/// because "An endpoint that always retransmits packets in response to receiving packets that it
/// cannot process risks creating an infinite exchange of packets".
pub const early_crypto_resends_max: u8 = 2;

comptime {
    // Both of §6.5's sentences say "three times the PTO", so the number is the RFC's and not a
    // knob: a change here is a change to what the specification asks for.
    assert(key_update_probe_timeouts == 3);
    // The BLOCKED frames repeat inside the idle timeout, which §10.1 holds at three PTOs or more.
    assert(blocked_repeat_probe_timeouts < close_probe_timeouts);
}
