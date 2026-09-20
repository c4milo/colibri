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

    pub fn none() Removed {
        return .{
            .count = 0,
            .in_flight_len = 0,
            .largest = null,
            .largest_sent_at_ns = 0,
            .any_ack_eliciting = false,
            .record = null,
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
            return take_range(&table.records, &table.live, &table.counts, smallest, largest);
        }

        /// Takes out one record, whatever its place (RFC 9002 Appendix A.10 removes a packet it
        /// has declared lost). Null when the table does not hold it.
        pub fn remove(table: *Table, number: u64) ?Record {
            const removed = take_range(&table.records, &table.live, &table.counts, number, number);
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

fn take_range(records: []Record, live: []bool, counts: *Counts, smallest: u64, largest: u64) Removed {
    assert(smallest <= largest);
    var removed = Removed.none();
    var from = lower_bound(records, counts.*, smallest);
    // Bounded by the span, which is at most the storage the caller placed.
    while (from < counts.span) : (from += 1) {
        const at = slot_at(records.len, counts.head, from);
        if (records[at].number > largest) break;
        if (live[at]) take(records, live, counts, at, &removed);
    }
    compact(records.len, live, counts);
    return removed;
}

fn take_all(records: []Record, live: []bool, counts: *Counts) Removed {
    var removed = Removed.none();
    // Bounded by the span, which is at most the storage the caller placed.
    for (0..counts.span) |from| {
        const at = slot_at(records.len, counts.head, from);
        if (live[at]) take(records, live, counts, at, &removed);
    }
    compact(records.len, live, counts);
    assert(counts.count == 0 and counts.span == 0 and counts.in_flight_len == 0);
    assert(counts.ack_eliciting_count == 0);
    return removed;
}

/// Takes the record in `at` out and adds it to `removed`. The slot stays where it is so the
/// numbers keep ascending; `compact` is what frees it.
fn take(records: []const Record, live: []bool, counts: *Counts, at: usize, removed: *Removed) void {
    assert(live[at]);
    const held = records[at];
    live[at] = false;
    counts.count -= 1;
    removed.count += 1;
    removed.record = held;
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

const testing = std.testing;

/// The table the tests drive. Its capacity is small so a test can fill it and wrap it. Test-only.
const test_capacity: usize = 4;
const TestTable = Sent(test_capacity);
var test_table: TestTable = undefined;
/// A packet size the tests can add up by eye, and an instant to measure sends from.
const test_len: u16 = 100;
const test_sent_at_ns: u64 = 7;

/// An ack-eliciting packet in flight, numbered `number` and sent `number` units in.
fn eliciting(number: u64) Record {
    return .{
        .number = number,
        .sent_at_ns = test_sent_at_ns + number,
        .sent_len = test_len,
        .ack_eliciting = true,
        .in_flight = true,
    };
}

/// A packet carrying only ACK, and no PADDING: RFC 9002 §2 has it neither ack-eliciting nor in
/// flight, so it is remembered but counts toward nothing. Adding one PADDING frame would put it
/// in flight without making it ack-eliciting, which is the case §14.1 forces on every sender.
fn acknowledgment_only(number: u64) Record {
    return .{
        .number = number,
        .sent_at_ns = test_sent_at_ns + number,
        .sent_len = test_len,
        .ack_eliciting = false,
        .in_flight = false,
    };
}

/// The numbers the table holds, oldest first. Test-only.
fn held_numbers(out: *[test_capacity]u64) []const u64 {
    var walk = test_table.iterator();
    var len: usize = 0;
    while (walk.next()) |held| {
        out[len] = held.number;
        len += 1;
    }
    return out[0..len];
}

test "A.1.1: records are held in send order and the table fills" {
    test_table.init();
    try testing.expectEqual(null, test_table.oldest());
    for (0..test_capacity) |number| try test_table.record(eliciting(number));
    try testing.expectEqual(test_capacity, test_table.count());
    try testing.expectEqual(test_capacity * test_len, test_table.in_flight_len());
    try testing.expectEqual(test_capacity, test_table.ack_eliciting_count());
    try testing.expectEqual(0, test_table.oldest().?.number);
    var numbers: [test_capacity]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 3 }, held_numbers(&numbers));
    // RFC 9002 places no bound on `sent_packets`; colibri's is its own and it fails closed.
    try testing.expectError(Error.Full, test_table.record(eliciting(test_capacity)));
    try testing.expectEqual(test_capacity, test_table.count());
    try testing.expectEqual(test_capacity * test_len, test_table.in_flight_len());
}

test "§7.2: a packet not in flight is remembered and counts toward nothing" {
    test_table.init();
    try test_table.record(eliciting(0));
    try test_table.record(acknowledgment_only(1));
    try testing.expectEqual(2, test_table.count());
    try testing.expectEqual(test_len, test_table.in_flight_len());
    // RFC 9002 Appendix A.8 arms a probe only where the peer owes an acknowledgment.
    try testing.expectEqual(1, test_table.ack_eliciting_count());
    // What leaves reports only the octets that were in flight, and only an ack-eliciting packet
    // sets the flag RFC 9002 Appendix A.7 requires before a round trip sample may be taken.
    const removed = test_table.remove_range(1, 1);
    try testing.expectEqual(1, removed.count);
    try testing.expectEqual(0, removed.in_flight_len);
    try testing.expect(!removed.any_ack_eliciting);
    try testing.expectEqual(1, removed.largest);
    try testing.expectEqual(test_len, test_table.in_flight_len());
}

test "§19.3: one ACK range takes out every number it covers and no other" {
    test_table.init();
    for (0..test_capacity) |number| try test_table.record(eliciting(number));
    const removed = test_table.remove_range(1, 2);
    try testing.expectEqual(2, removed.count);
    try testing.expectEqual(2 * test_len, removed.in_flight_len);
    try testing.expect(removed.any_ack_eliciting);
    // RFC 9002 §5.1: the sample is measured from when the largest newly acknowledged was sent.
    try testing.expectEqual(2, removed.largest);
    try testing.expectEqual(test_sent_at_ns + 2, removed.largest_sent_at_ns);
    var numbers: [test_capacity]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{ 0, 3 }, held_numbers(&numbers));
    try testing.expectEqual(2 * test_len, test_table.in_flight_len());
    // A range naming numbers the table never held changes nothing.
    const again = test_table.remove_range(1, 2);
    try testing.expectEqual(0, again.count);
    try testing.expectEqual(null, again.largest);
    try testing.expectEqual(2, test_table.count());
}

test "§19.3: a range below or above everything held takes out nothing" {
    test_table.init();
    for (2..4) |number| try test_table.record(eliciting(number));
    try testing.expectEqual(0, test_table.remove_range(0, 1).count);
    try testing.expectEqual(0, test_table.remove_range(4, 9).count);
    try testing.expectEqual(2, test_table.count());
    // A range covering everything takes everything.
    const removed = test_table.remove_range(0, 9);
    try testing.expectEqual(2, removed.count);
    try testing.expectEqual(3, removed.largest);
    try testing.expectEqual(0, test_table.count());
    try testing.expectEqual(0, test_table.in_flight_len());
}

test "A.10: one record leaves from the middle and the rest keep their order" {
    test_table.init();
    for (0..test_capacity) |number| try test_table.record(eliciting(number));
    try testing.expectEqual(2, test_table.remove(2).?.number);
    try testing.expectEqual(test_sent_at_ns + 1, test_table.remove(1).?.sent_at_ns);
    // A number already given up, or never held, is not there to take.
    try testing.expectEqual(null, test_table.remove(2));
    try testing.expectEqual(null, test_table.remove(9));
    var numbers: [test_capacity]u64 = undefined;
    try testing.expectEqualSlices(u64, &.{ 0, 3 }, held_numbers(&numbers));
    try testing.expectEqual(2 * test_len, test_table.in_flight_len());
}

test "a slot returns when it is at an end of the span, and not before" {
    test_table.init();
    for (0..test_capacity) |number| try test_table.record(eliciting(number));
    var numbers: [test_capacity]u64 = undefined;
    // A slot between two live ones frees nothing: moving it would break the ascending order the
    // searches depend on, so it waits for the head.
    _ = test_table.remove(1);
    try testing.expectError(Error.Full, test_table.record(eliciting(4)));
    // The newest frees its own slot, which is what keeps a peer that acknowledges in order from
    // filling the table with nothing.
    _ = test_table.remove(3);
    try test_table.record(eliciting(4));
    try testing.expectEqualSlices(u64, &.{ 0, 2, 4 }, held_numbers(&numbers));
    try testing.expectError(Error.Full, test_table.record(eliciting(5)));
    // Taking the oldest moves the head past it and past the dead slot behind it, freeing both.
    _ = test_table.remove(0);
    try test_table.record(eliciting(5));
    try test_table.record(eliciting(6));
    // Those wrapped past the end of the storage, and the numbers still ascend across the wrap.
    try testing.expectEqualSlices(u64, &.{ 2, 4, 5, 6 }, held_numbers(&numbers));
    try testing.expectEqual(2, test_table.oldest().?.number);
    const removed = test_table.remove_range(4, 5);
    try testing.expectEqual(2, removed.count);
    try testing.expectEqual(5, removed.largest);
    try testing.expectEqualSlices(u64, &.{ 2, 6 }, held_numbers(&numbers));
}

test "A.11: discarding a space gives up every record at once" {
    test_table.init();
    try test_table.record(eliciting(0));
    try test_table.record(acknowledgment_only(1));
    try test_table.record(eliciting(2));
    const removed = test_table.discard();
    try testing.expectEqual(3, removed.count);
    // RFC 9002 Appendix A.11: the octets stop counting toward the bytes in flight, and only the
    // ones that were in flight are reported.
    try testing.expectEqual(2 * test_len, removed.in_flight_len);
    try testing.expectEqual(2, removed.largest);
    try testing.expect(removed.any_ack_eliciting);
    try testing.expectEqual(0, test_table.count());
    try testing.expectEqual(0, test_table.ack_eliciting_count());
    try testing.expectEqual(null, test_table.oldest());
    // The table is usable again, and discarding an empty one reports nothing.
    try testing.expectEqual(0, test_table.discard().count);
    try test_table.record(eliciting(3));
    try testing.expectEqual(3, test_table.oldest().?.number);
}

test "RFC 9002 §2: PADDING puts a packet in flight without eliciting an acknowledgment" {
    // The ordinary packet: it elicits an acknowledgment, so it is in flight whatever else it holds.
    try testing.expect(counts_in_flight(true, false));
    try testing.expect(counts_in_flight(true, true));
    // RFC 9000 §14.1's padded datagram. Nothing in it elicits an acknowledgment and it is still
    // in flight, which is the half a sender reading only `ack_eliciting` would lose.
    try testing.expect(counts_in_flight(false, true));
    // A packet carrying only ACK is the one case that counts toward neither.
    try testing.expect(!counts_in_flight(false, false));
}
