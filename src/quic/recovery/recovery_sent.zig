//! What this endpoint has sent and not yet heard about, per packet number space (RFC 9002
//! Appendix A.1.1). Part of design §8 step 10.
//!
//! Loss recovery needs four facts about every packet still outstanding: its number, when it went
//! out, how large it was, and whether it counts toward the bytes in flight. RFC 9002 keeps them
//! in `sent_packets`, one collection per space, and every algorithm in its Appendix A walks that
//! collection. This is that collection, with the two properties CLAUDE.md requires of it: it
//! holds no memory of its own beyond what the caller placed (decision 35), and every walk over
//! it is bounded by a named limit.
//!
//! The records are held in send order, which is packet number order, because RFC 9000 §12.3 has
//! a sender increase the number of every packet it sends in a space. That ordering is what makes
//! this cheap: a number is found by halving rather than by scanning, and the oldest records are
//! the first to leave, so the storage behaves as a ring with the acknowledged slots falling off
//! the front.
//!
//! It reads no clock. `sent_at_ns` arrives from the caller, which is non-negotiable 3.
//!
//! What it does not do is decide anything. Which packets are lost is RFC 9002 §6.1's and lives
//! in `recovery_loss.zig`; how many bytes may be in flight is §7's. This file answers what was
//! sent and removes what no longer is.
const std = @import("std");
const assert = std.debug.assert;
const space = @import("../space/space.zig");

/// The ECN codepoint of the datagram a packet went out in (RFC 9000 §13.4). It is the type the
/// receiving side already names, because §13.4.1 counts the same four values coming in.
pub const Ecn = space.Space.Ecn;

/// Which flow a packet's `data_offset` and `data_len` describe (RFC 9000 §13.3). A packet carries
/// at most one CRYPTO frame or one STREAM frame and never both (decisions 56 and 57), so one range
/// describes either.
pub const Carries = enum(u8) {
    none,
    crypto,
    stream,
    /// A STREAM frame with the FIN bit set (RFC 9000 §19.8). §4.5: "A sender always communicates
    /// the final size of a stream to the receiver reliably", so a lost FIN is sent again, with or
    /// without octets beside it.
    stream_fin,
};

pub const Error = error{
    /// Every slot is in use. RFC 9002 places no bound on `sent_packets`, so colibri's is its own
    /// and the sender must wait for an acknowledgment rather than send past it. Nothing changed.
    Full,
};

/// One outstanding packet (RFC 9002 Appendix A.1.1).
pub const Record = struct {
    /// RFC 9000 §12.3: the number the packet was sent with, which is above every number sent
    /// before it in this space.
    number: u64,
    /// The instant the caller sent it. RFC 9002's pseudocode calls this `time_sent` and reads it
    /// from `now()`; colibri takes it as a parameter (non-negotiable 3).
    sent_at_ns: u64,
    /// RFC 9002 Appendix A.1.1: the octets of the packet, QUIC framing included and the UDP and
    /// IP headers excluded. A UDP payload holds at most 65527 octets, so 16 bits carry it.
    sent_len: u16,
    /// RFC 9002 §2: whether the packet carries a frame other than ACK, PADDING and
    /// CONNECTION_CLOSE, which is what obliges the peer to acknowledge it.
    ack_eliciting: bool,
    /// RFC 9002 §2: "Packets are considered in flight when they are ack-eliciting or contain a
    /// PADDING frame". Both halves matter to the sender: a packet carrying only ACK is not in
    /// flight, and one padded to RFC 9000 §14.1's 1,200 octets is, whatever else it holds.
    in_flight: bool,
    /// The ECN codepoint the datagram carrying it went out with (RFC 9000 §13.4). colibri owns
    /// no socket, so the IP header is the caller's and this is what the caller set; §13.4.2.1
    /// validates the peer's counts against it.
    ecn: Ecn = .not_ect,
    /// Which flow the packet's octets were in, if any. RFC 9000 §13.3 retransmits CRYPTO data
    /// "until all data has been acknowledged" and STREAM data "in new STREAM frames", so a lost
    /// packet must say which octets to send again, and an acknowledged one which octets arrived.
    carries: Carries = .none,
    /// Where those octets sat in their flow: the level's for CRYPTO (RFC 9000 §19.6), the
    /// stream's for STREAM (§19.8).
    ///
    /// The range sits here flat rather than in a struct of its own because a struct of `u64` and
    /// `u16` pads to sixteen octets, and 256 records in each of three spaces pay for every one.
    data_offset: u64 = 0,
    /// Octets, which one packet bounds, so 16 bits carry it (RFC 9000 §14.1, §18.2). Zero with
    /// `stream_fin` is a FIN sent on its own.
    data_len: u16 = 0,
    /// The stream the octets belong to, by its 62-bit identifier (RFC 9000 §2.1), when `carries`
    /// is a stream. A table slot would not do: a slot is reused, and a late acknowledgment would
    /// count toward the next stream in it (decision 57).
    stream_id: u64 = 0,
};

/// Whether a packet the sender just framed counts toward the bytes in flight. RFC 9002 §2:
/// "Packets are considered in flight when they are ack-eliciting or contain a PADDING frame".
///
/// It is a function rather than a rule each caller restates, because the two halves come apart:
/// RFC 9000 §14.1 makes a client pad every datagram carrying an Initial to 1,200 octets, so a
/// padded acknowledgment is in flight while eliciting nothing, and reading only `ack_eliciting`
/// would under-count the congestion window by the whole of that datagram.
pub fn counts_in_flight(ack_eliciting: bool, carries_padding: bool) bool {
    return ack_eliciting or carries_padding;
}

/// What `remove_range` took out, so a caller walking ACK ranges sums one struct per range rather
/// than one per packet.
pub const Removed = struct {
    /// How many records left the table.
    count: usize,
    /// Their octets, counting the ones in flight alone (RFC 9002 §7.2: `bytes_in_flight`).
    in_flight_len: u64,
    /// The largest number removed, or null when none was.
    largest: ?u64,
    /// When that largest one was sent, which RFC 9002 §5.1 needs to take a round trip sample.
    largest_sent_at_ns: u64,
    /// Whether any of them was ack-eliciting, which RFC 9002 Appendix A.7 requires before a
    /// round trip sample may be taken at all.
    any_ack_eliciting: bool,
    /// The last record taken, which is the largest, or null when none was.
    record: ?Record,
    /// How many of them went out with each ECT codepoint (RFC 9000 §13.4.2.1), which is "the
    /// number of newly acknowledged packets that were originally sent with an ECT(0) marking"
    /// and its ECT(1) twin.
    ect_0: usize,
    ect_1: usize,
    /// How many of them were written to the caller's slice, and how many did not fit. A caller
    /// that wants every one passes a slice as long as its table.
    written: usize,
    unwritten: usize,

    pub fn none() Removed {
        return .{
            .count = 0,
            .in_flight_len = 0,
            .largest = null,
            .largest_sent_at_ns = 0,
            .any_ack_eliciting = false,
            .record = null,
            .ect_0 = 0,
            .ect_1 = 0,
            .written = 0,
            .unwritten = 0,
        };
    }
};

/// Where the records sit in the caller's storage. It is held apart from the storage itself so
/// that every scan below is a file-scope function over slices, scored on its own against
/// CLAUDE.md's complexity limit, exactly as `core/slots.zig` does it.
pub const Counts = struct {
    /// The slot holding the oldest record, and how many slots the records span from it. The
    /// span covers dead slots too, so `head + span` is where the next record goes.
    head: usize,
    span: usize,
    /// How many of those slots are live, and the octets of the live ones that are in flight.
    count: usize,
    in_flight_len: u64,
    /// How many of the live ones are ack-eliciting, which RFC 9002 Appendix A.8 asks of every
    /// space before it arms a Probe Timeout for it.
    ack_eliciting_count: usize,
};

/// A table of at most `capacity` outstanding packets. One space's, never shared: RFC 9000 §12.3
/// gives each space its own numbers, and a number means nothing outside the space it was used in.
pub fn Sent(comptime capacity: usize) type {
    comptime assert(capacity > 0);

    return struct {
        const Table = @This();

        records: [capacity]Record,
        /// Whether the slot still holds an outstanding packet. A slot goes dead when its packet
        /// is acknowledged or declared lost, and its record stays in place until an end of the
        /// span reaches it, which is what keeps the numbers ascending across the whole span.
        live: [capacity]bool,
        counts: Counts,

        pub fn init(table: *Table) void {
            table.live = @splat(false);
            table.counts = .{ .head = 0, .span = 0, .count = 0, .in_flight_len = 0, .ack_eliciting_count = 0 };
        }

        /// How many packets are outstanding, and their octets counting the ones in flight alone
        /// (RFC 9002 §7.2: `bytes_in_flight`).
        pub fn count(table: *const Table) usize {
            return table.counts.count;
        }

        pub fn in_flight_len(table: *const Table) u64 {
            return table.counts.in_flight_len;
        }

        /// How many outstanding packets the peer must acknowledge (RFC 9002 Appendix A.8).
        pub fn ack_eliciting_count(table: *const Table) usize {
            return table.counts.ack_eliciting_count;
        }

        /// Remembers a packet this endpoint has just sent (RFC 9002 Appendix A.5).
        pub fn record(table: *Table, sent: Record) Error!void {
            return append(&table.records, &table.live, &table.counts, sent);
        }

        /// Takes out every record the peer named in one ACK range, from `smallest` to `largest`
        /// inclusive (RFC 9000 §19.3). A number the table never held, or already gave up, is
        /// passed over, which is what makes a repeated acknowledgment cost nothing.
        pub fn remove_range(table: *Table, smallest: u64, largest: u64) Removed {
            return table.remove_range_into(smallest, largest, &.{});
        }

        /// `remove_range`, and writes each record it takes into `taken`, in packet number order,
        /// as far as the slice holds them. RFC 9000 §13.3 sends information again by what a lost
        /// packet carried, and an acknowledged packet is what ends that for everything it
        /// carried, so a caller that must learn which octets the peer now holds reads them here.
        pub fn remove_range_into(table: *Table, smallest: u64, largest: u64, taken: []Record) Removed {
            return take_range(&table.records, &table.live, &table.counts, smallest, largest, taken);
        }

        /// Takes out one record, whatever its place (RFC 9002 Appendix A.10 removes a packet it
        /// has declared lost). Null when the table does not hold it.
        pub fn remove(table: *Table, number: u64) ?Record {
            const removed = take_range(&table.records, &table.live, &table.counts, number, number, &.{});
            if (removed.count == 0) return null;
            return removed.record.?;
        }

        /// Gives up every record, which RFC 9002 Appendix A.11 does when a space's keys are
        /// discarded: its packets are neither acknowledged nor lost, and they stop counting
        /// toward the bytes in flight. Returns what left.
        pub fn discard(table: *Table) Removed {
            return take_all(&table.records, &table.live, &table.counts);
        }

        /// Walks the live records from the oldest, which is the `foreach unacked in sent_packets`
        /// of RFC 9002 Appendix A.10.
        pub fn iterator(table: *const Table) Iterator {
            return .{ .records = &table.records, .live = &table.live, .counts = table.counts, .from = 0 };
        }

        /// The smallest number still outstanding, or null when nothing is.
        pub fn oldest(table: *const Table) ?Record {
            if (table.counts.count == 0) return null;
            return table.records[table.counts.head];
        }
    };
}

/// Walks the live records in packet number order.
pub const Iterator = struct {
    records: []const Record,
    live: []const bool,
    counts: Counts,
    from: usize,

    pub fn next(walk: *Iterator) ?Record {
        // Bounded by the span, which is at most the storage the caller placed.
        while (walk.from < walk.counts.span) {
            const at = slot_at(walk.records.len, walk.counts.head, walk.from);
            walk.from += 1;
            if (walk.live[at]) return walk.records[at];
        }
        return null;
    }
};

fn append(records: []Record, live: []bool, counts: *Counts, sent: Record) Error!void {
    assert(records.len == live.len);
    // RFC 9000 §12.3: numbers increase within a space, so a record never lands behind one
    // already held. This is colibri's own bookkeeping, not a peer's input (invariant 24).
    assert(counts.span == 0 or sent.number > records[slot_at(records.len, counts.head, counts.span - 1)].number);
    if (counts.span == records.len) return Error.Full;
    const at = slot_at(records.len, counts.head, counts.span);
    records[at] = sent;
    live[at] = true;
    counts.span += 1;
    counts.count += 1;
    if (sent.in_flight) counts.in_flight_len += sent.sent_len;
    if (sent.ack_eliciting) counts.ack_eliciting_count += 1;
}

fn take_range(records: []Record, live: []bool, counts: *Counts, smallest: u64, largest: u64, taken: []Record) Removed {
    assert(smallest <= largest);
    var removed = Removed.none();
    var from = lower_bound(records, counts.*, smallest);
    // Bounded by the span, which is at most the storage the caller placed.
    while (from < counts.span) : (from += 1) {
        const at = slot_at(records.len, counts.head, from);
        if (records[at].number > largest) break;
        if (live[at]) take(records, live, counts, at, &removed, taken);
    }
    compact(records.len, live, counts);
    return removed;
}

fn take_all(records: []Record, live: []bool, counts: *Counts) Removed {
    var removed = Removed.none();
    // Bounded by the span, which is at most the storage the caller placed.
    for (0..counts.span) |from| {
        const at = slot_at(records.len, counts.head, from);
        if (live[at]) take(records, live, counts, at, &removed, &.{});
    }
    compact(records.len, live, counts);
    assert(counts.count == 0 and counts.span == 0 and counts.in_flight_len == 0);
    assert(counts.ack_eliciting_count == 0);
    return removed;
}

/// Takes the record in `at` out, adds it to `removed` and writes it into `taken` when there is
/// room. The slot stays where it is so the numbers keep ascending; `compact` is what frees it.
fn take(records: []const Record, live: []bool, counts: *Counts, at: usize, removed: *Removed, taken: []Record) void {
    assert(live[at]);
    const held = records[at];
    live[at] = false;
    counts.count -= 1;
    removed.count += 1;
    removed.record = held;
    if (removed.written < taken.len) {
        taken[removed.written] = held;
        removed.written += 1;
    } else {
        removed.unwritten += 1;
    }
    if (held.in_flight) {
        assert(counts.in_flight_len >= held.sent_len);
        counts.in_flight_len -= held.sent_len;
        removed.in_flight_len += held.sent_len;
    }
    // The records are taken in ascending order, so the last one taken is the largest.
    removed.largest = held.number;
    removed.largest_sent_at_ns = held.sent_at_ns;
    if (held.ack_eliciting) {
        assert(counts.ack_eliciting_count > 0);
        counts.ack_eliciting_count -= 1;
        removed.any_ack_eliciting = true;
    }
    // RFC 9000 §13.4.2.1 counts the newly acknowledged packets per ECT codepoint, which is what
    // the peer's reported increase is measured against.
    switch (held.ecn) {
        .ect_0 => removed.ect_0 += 1,
        .ect_1 => removed.ect_1 += 1,
        .not_ect, .ecn_ce => {},
    }
}

/// Returns the dead slots at either end of the span for reuse. A dead slot between two live ones
/// stays where it is, because moving it would break the ascending order every search here
/// depends on; it returns when an end reaches it.
fn compact(capacity: usize, live: []const bool, counts: *Counts) void {
    // The front, which is where acknowledgments normally land: the head passes them. Bounded by
    // the capacity, which is a named limit of whoever placed the storage.
    for (0..capacity) |_| {
        if (counts.span == 0 or live[counts.head]) break;
        counts.head = (counts.head + 1) % capacity;
        counts.span -= 1;
    }
    // The back, so a peer acknowledging the newest packet first does not leave the table full of
    // slots holding nothing. Bounded the same way.
    for (0..capacity) |_| {
        if (counts.span == 0 or live[slot_at(capacity, counts.head, counts.span - 1)]) break;
        counts.span -= 1;
    }
    if (counts.span == 0) counts.head = 0;
}

/// What a halving search cuts the remaining range by at each step.
const search_divisor: usize = 2;

/// The first place in the span whose number is at or above `number`, or the span when every
/// number is below it. The numbers ascend across the whole span, dead slots included, so halving
/// finds it.
fn lower_bound(records: []const Record, counts: Counts, number: u64) usize {
    var low: usize = 0;
    var high: usize = counts.span;
    // Each step halves the distance, so the width of a `usize` bounds the loop whatever the
    // capacity is.
    for (0..@bitSizeOf(usize)) |_| {
        if (low >= high) break;
        const middle = low + (high - low) / search_divisor;
        if (records[slot_at(records.len, counts.head, middle)].number < number) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    assert(low == high);
    return low;
}

/// The slot `from` places past the head.
fn slot_at(capacity: usize, head: usize, from: usize) usize {
    assert(from < capacity);
    return (head + from) % capacity;
}

test {
    _ = @import("recovery_sent_test.zig");
}
