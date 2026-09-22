//! One packet number space (RFC 9000 §12.3): the numbers this endpoint has sent in it, the ones
//! it has received, the ECN counts it owes the peer, and whether an acknowledgment is due.
//! There are three — Initial, Handshake and Application data — and they share no state, which is
//! the cryptographic separation §12.3 exists for: an Initial packet is acknowledged only in an
//! Initial packet, and a number means nothing outside the space it was used in.
//!
//! This is part of design §8 step 9. It reads no clock: every instant is a parameter
//! (design §4.2). It holds no key: a packet's protection is the suite's (decision 48).
//!
//! What it does not do is loss recovery. Nothing here remembers what was sent, so nothing here
//! can say a packet was lost; RFC 9002 is step 10's, and `on_ack` reports what an acknowledgment
//! said so that step can act on it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const space_received = @import("space_received.zig");

const Writer = core.Writer;
const Received = space_received.Received;
const Verdict = space_received.Verdict;

/// The three spaces of RFC 9000 §12.3. They are the encryption levels of RFC 9001 §4.1.4,
/// because 0-RTT and 1-RTT share both a space and a level.
pub const Kind = enum(u2) {
    initial = 0,
    handshake = 1,
    application = 2,
};

/// The counts an endpoint reports for the codepoints it received (RFC 9000 §13.4.1, §19.3.2).
/// Each space keeps its own, and a coalesced packet raises the count of its own space alone.
pub const EcnCounts = struct {
    ect_0: u64 = 0,
    ect_1: u64 = 0,
    ecn_ce: u64 = 0,
};

/// What a received ACK frame said, for the loss recovery of step 10 to act on.
pub const AckReport = struct {
    /// The largest number the peer acknowledged, which is at or above any it named before.
    largest_acknowledged: u64,
    /// Whether that number is one the peer had not acknowledged before.
    largest_is_new: bool,
    /// The frame's ACK Delay field, before the peer's ack_delay_exponent is applied
    /// (RFC 9000 §19.3, §18.2). The exponent is a transport parameter this layer does not hold.
    delay: u64,
    /// The counts the peer reported, when the frame carried them (§19.3.2).
    ecn: ?frame.EcnCounts,
};

/// Why a received ACK frame ended the connection.
pub const AckError = error{
    /// RFC 9000 §13.1: an endpoint treats an acknowledgment for a packet it did not send as a
    /// connection error of PROTOCOL_VIOLATION, when it can detect it. A number at or above the
    /// next one this endpoint would send was never sent.
    AcknowledgedUnsentPacket,
};

/// RFC 9000 §20.1: the transport error code `AcknowledgedUnsentPacket` closes with.
pub const protocol_violation: u64 = 0x0a;

/// Why a packet number could not be taken for sending.
pub const SendError = error{
    /// RFC 9000 §12.3: the number reached 2^62-1, and the sender closes the connection without
    /// a CONNECTION_CLOSE frame and sends nothing further.
    PacketNumbersExhausted,
};

pub const Space = struct {
    kind: Kind,
    /// RFC 9000 §12.3: numbers start at 0 in each space and increase by at least one.
    next_packet_number: u64,
    /// The largest the peer has acknowledged in this space, or null before it acknowledged any.
    largest_acknowledged: ?u64,
    received: Received,
    ecn: EcnCounts,
    /// Ack-eliciting packets received since the last ACK frame went out (RFC 9000 §13.2.2).
    ack_eliciting_since_ack: u64,
    /// Whether an ACK is owed without waiting, which RFC 9000 §13.2.1 asks for on an out-of-order
    /// ack-eliciting packet and on one marked ECN-CE.
    ack_immediately: bool,
    /// The instant the largest number received arrived, which the ACK Delay is measured from
    /// (RFC 9000 §13.2.5). Read only when something has been received.
    largest_received_at_ns: u64,
    /// The instant the oldest ack-eliciting packet not yet acknowledged arrived, or null when
    /// none is pending. RFC 9000 §13.2.1 measures max_ack_delay from it, and it is the oldest
    /// rather than the newest because the promise is about every packet: the oldest is the one
    /// nearest to breaking it.
    ack_eliciting_since_at_ns: ?u64,

    pub fn init(space: *Space, kind: Kind) void {
        space.* = .{
            .kind = kind,
            .next_packet_number = 0,
            .largest_acknowledged = null,
            .received = .empty,
            .ecn = .{},
            .ack_eliciting_since_ack = 0,
            .ack_immediately = false,
            .largest_received_at_ns = 0,
            .ack_eliciting_since_at_ns = null,
        };
    }

    /// Takes the next number to send (RFC 9000 §12.3). A number is never reused, so this is the
    /// one place it advances.
    /// The number the next packet of this space would take, without spending it. A packet that
    /// turns out to carry nothing must leave no hole (invariant 17), so a builder asks first and
    /// spends only once the packet exists.
    pub fn peek_number(space: *const Space) SendError!u64 {
        // RFC 9000 §12.3: at 2^62-1 the sender closes the connection and sends nothing further.
        if (space.next_packet_number > constants.packet_number_max) return error.PacketNumbersExhausted;
        return space.next_packet_number;
    }

    pub fn next_number(space: *Space) SendError!u64 {
        // RFC 9000 §12.3: at 2^62-1 the sender closes the connection and sends nothing further.
        if (space.next_packet_number > constants.packet_number_max) return error.PacketNumbersExhausted;
        const number = space.next_packet_number;
        space.next_packet_number = number + 1;
        return number;
    }

    /// What a packet carrying `packet_number` would be, without recording it. RFC 9000 §12.3 has
    /// the receive path ask this the moment a packet is unprotected, because a duplicate is
    /// discarded rather than read; `receive` is called afterwards, once every frame has been
    /// processed, which is what §13.1 requires before a packet may be acknowledged.
    pub fn duplicate_verdict(space: *const Space, packet_number: u64) Verdict {
        return space.received.verdict_for(packet_number);
    }

    /// Records a packet this endpoint received and processed, and says whether it is new.
    /// `ack_eliciting` is whether any frame in it elicits an acknowledgment (RFC 9000 §13.2.1),
    /// and `ecn` is the codepoint its datagram carried (§13.4.1).
    pub fn receive(space: *Space, packet_number: u64, now_ns: u64, ack_eliciting: bool, ecn: Ecn) Verdict {
        const was_largest = space.received.largest();
        const verdict = space.received.receive(packet_number);
        // RFC 9000 §13.4.1: the counts rise only when a packet is processed, so a duplicate
        // raises none.
        if (verdict != .new) return verdict;
        space.count_ecn(ecn);
        if (was_largest == null or packet_number > was_largest.?) {
            space.largest_received_at_ns = now_ns;
        }
        if (!ack_eliciting) return verdict;
        // RFC 9000 §13.2.1's delay runs from the oldest packet still unacknowledged, so the
        // instant is taken on the first since the last ACK and not on every one.
        if (space.ack_eliciting_since_ack == 0) space.ack_eliciting_since_at_ns = now_ns;
        space.ack_eliciting_since_ack += 1;
        // RFC 9000 §13.2.1: "An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
        // packets immediately." The handshake has no max_ack_delay to spend — §18.2 applies that
        // parameter to the application space alone — so one such packet owes an ACK at once,
        // where §13.2.2's count of two would hold the handshake up waiting for a second.
        if (space.kind != .application) space.ack_immediately = true;
        // §13.2.1: an ack-eliciting packet that arrives out of order, or one marked ECN-CE, is
        // acknowledged without delay whichever space it arrived in.
        const out_of_order = was_largest != null and packet_number != was_largest.? + 1;
        if (out_of_order or ecn == .ecn_ce) space.ack_immediately = true;
        return verdict;
    }

    /// The ECN field of the datagram a packet arrived in (RFC 9000 §13.4). Its names are §13.4's;
    /// the two bits each stands for belong to the IP header the caller owns.
    pub const Ecn = enum { not_ect, ect_0, ect_1, ecn_ce };

    fn count_ecn(space: *Space, ecn: Ecn) void {
        // RFC 9000 §13.4.1: on an ECT(0), ECT(1) or ECN-CE codepoint the matching count rises.
        switch (ecn) {
            .not_ect => {},
            .ect_0 => space.ecn.ect_0 += 1,
            .ect_1 => space.ecn.ect_1 += 1,
            .ecn_ce => space.ecn.ecn_ce += 1,
        }
    }

    /// Whether an ACK frame is owed at `now_ns`. RFC 9000 §13.2.2 has a receiver send one after
    /// at least two ack-eliciting packets, §13.2.1 makes some owed at once, and §13.2.1 puts a
    /// deadline under both: "ack-eliciting packets MUST be acknowledged at least once within the
    /// maximum delay an endpoint communicated using the max_ack_delay transport parameter".
    /// `max_ack_delay_ns` is what this endpoint advertised (§18.2).
    pub fn owes_ack(space: *const Space, now_ns: u64, max_ack_delay_ns: u64) bool {
        if (space.owes_ack_at_once()) return true;
        const deadline_ns = space.ack_deadline_ns(max_ack_delay_ns) orelse return false;
        return now_ns >= deadline_ns;
    }

    /// The half of §13.2.1 and §13.2.2 that needs no instant: a packet that must be acknowledged
    /// without waiting, or enough of them to have earned one.
    fn owes_ack_at_once(space: *const Space) bool {
        const owed = space.ack_immediately or
            space.ack_eliciting_since_ack >= constants.ack_eliciting_before_ack;
        // Nothing is owed before anything is received: both of those move only on a packet this
        // space processed. Stated rather than guarded, so a later change that empties a space
        // without clearing them fails here instead of writing an ACK frame with no ranges.
        assert(!owed or !space.received.is_empty());
        return owed;
    }

    /// The instant an ACK becomes owed by RFC 9000 §13.2.1's deadline, or null when nothing is
    /// pending or one is owed already. A space with an ACK owed now needs no timer: the caller
    /// writes it on its next pass.
    pub fn ack_deadline_ns(space: *const Space, max_ack_delay_ns: u64) ?u64 {
        if (space.owes_ack_at_once()) return null;
        // §13.2.1: an Initial or Handshake packet is acknowledged immediately, which `receive`
        // records as `ack_immediately`, so only the application space ever reaches here.
        const since_ns = space.ack_eliciting_since_at_ns orelse return null;
        return since_ns +| max_ack_delay_ns;
    }

    /// Writes an ACK frame for everything received in this space (RFC 9000 §19.3), all of it or
    /// none, and returns whether one was written. `now_ns` gives the ACK Delay and
    /// `ack_delay_exponent` is this endpoint's transport parameter (§18.2). `report_ecn` is
    /// whether the counts are included, which §13.4.1 leaves to an endpoint that can read them.
    pub fn write_ack(
        space: *Space,
        writer: *Writer,
        now_ns: u64,
        ack_delay_exponent: u6,
        report_ecn: bool,
    ) core.writer.Error!bool {
        if (space.received.is_empty()) return false;
        var copy = writer.*;
        try space.write_ack_at(&copy, now_ns, ack_delay_exponent, report_ecn);
        writer.* = copy;
        // RFC 9000 §13.2.2: the count starts again once the frame is written.
        space.ack_eliciting_since_ack = 0;
        space.ack_immediately = false;
        space.ack_eliciting_since_at_ns = null;
        return true;
    }

    fn write_ack_at(
        space: *const Space,
        writer: *Writer,
        now_ns: u64,
        ack_delay_exponent: u6,
        report_ecn: bool,
    ) core.writer.Error!void {
        const count = space.received.len - 1;
        // RFC 9000 §19.3: the type is 0x02, or 0x03 when the ECN counts follow (§19.3.2).
        const frame_type = if (report_ecn) constants.frame_ack_ecn else constants.frame_ack;
        try frame.write_type(writer, frame_type);
        const first = space.received.range_at(0);
        try wire.varint.encode(writer, first.largest);
        try wire.varint.encode(writer, space.ack_delay(now_ns, ack_delay_exponent));
        try wire.varint.encode(writer, count);
        // RFC 9000 §19.3: the First ACK Range counts the packets below the largest in its range.
        try wire.varint.encode(writer, first.largest - first.smallest);
        var previous_smallest = first.smallest;
        for (1..space.received.len) |index| {
            const range = space.received.range_at(index);
            // RFC 9000 §19.3.1: largest = previous_smallest - gap - 2, so the gap is what is
            // left after those two steps.
            try wire.varint.encode(writer, previous_smallest - range.largest - gap_step);
            try wire.varint.encode(writer, range.largest - range.smallest);
            previous_smallest = range.smallest;
        }
        if (!report_ecn) return;
        try wire.varint.encode(writer, space.ecn.ect_0);
        try wire.varint.encode(writer, space.ecn.ect_1);
        try wire.varint.encode(writer, space.ecn.ecn_ce);
    }

    /// The ACK Delay field: how long since the largest number arrived, in microseconds, shifted
    /// down by the exponent (RFC 9000 §19.3, §13.2.5).
    fn ack_delay(space: *const Space, now_ns: u64, ack_delay_exponent: u6) u64 {
        assert(now_ns >= space.largest_received_at_ns);
        const elapsed_us = (now_ns - space.largest_received_at_ns) / constants.nanoseconds_per_microsecond;
        return elapsed_us >> ack_delay_exponent;
    }

    /// Reads what an ACK frame the peer sent means for this space (RFC 9000 §13.1).
    pub fn on_ack(space: *Space, ack: frame.Ack) AckError!AckReport {
        const largest = ack.ranges.largest_acknowledged;
        // RFC 9000 §13.1: an acknowledgment for a packet this endpoint did not send is a
        // connection error of PROTOCOL_VIOLATION. Every number it sent is below the next one.
        if (largest >= space.next_packet_number) return error.AcknowledgedUnsentPacket;
        const largest_is_new = space.largest_acknowledged == null or largest > space.largest_acknowledged.?;
        // RFC 9000 §13.2: acknowledgments are irrevocable, so the largest never goes backward.
        if (largest_is_new) space.largest_acknowledged = largest;
        return .{
            .largest_acknowledged = largest,
            .largest_is_new = largest_is_new,
            .delay = ack.delay,
            .ecn = ack.ecn,
        };
    }
};

/// RFC 9000 §19.3.1: two steps separate one range's smallest from the next range's largest.
const gap_step: u64 = 2;

test {
    _ = space_received;
    _ = @import("space_test.zig");
}
