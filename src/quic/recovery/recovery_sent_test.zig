//! The tests of `recovery_sent.zig`, split out because a hand-written source file stays at or
//! under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const recovery_sent = @import("recovery_sent.zig");

const Record = recovery_sent.Record;
const Removed = recovery_sent.Removed;
const Sent = recovery_sent.Sent;
const Error = recovery_sent.Error;
const counts_in_flight = recovery_sent.counts_in_flight;

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

test "§19.3: the records a range takes out are written for the caller, as far as they fit" {
    test_table.init();
    for (0..test_capacity) |number| try test_table.record(eliciting(number));
    var taken: [2]Record = undefined;
    const removed = test_table.remove_range_into(0, 2, &taken);
    // The slice bounds what is written, never what is taken out.
    try testing.expectEqual(3, removed.count);
    try testing.expectEqual(2, removed.written);
    try testing.expectEqual(1, removed.unwritten);
    try testing.expectEqual(1, test_table.count());
    // In packet number order, which is the order the table holds them in.
    try testing.expectEqual(0, taken[0].number);
    try testing.expectEqual(1, taken[1].number);
    try testing.expectEqual(test_sent_at_ns + 1, taken[1].sent_at_ns);
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

test "RFC 9002 Appendix A.1.1: a record stays small, because 256 of them sit in every space" {
    // `sent_packets_max` is 256 and RFC 9000 §12.3 gives a connection three spaces, so every
    // octet here is paid for 768 times. The number is pinned so a field added without measuring
    // shows up as a failing test rather than as memory nobody looked at.
    try testing.expectEqual(32, @sizeOf(Record));
}
