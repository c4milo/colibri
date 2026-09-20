//! The packet number space's tests (RFC 9000 §12.3, §13.1, §13.2, §13.4.1), kept out of
//! `space.zig` so it stays inside the 500-line limit. What an ACK frame the space writes says is
//! checked by reading it back through the frame layer, so the two agree about §19.3.1's
//! arithmetic rather than each agreeing with itself.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const space_module = @import("space.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Space = space_module.Space;
const Ecn = Space.Ecn;
const testing = std.testing;

/// The space the tests drive, and where an ACK frame is written. Test-only.
var test_space: Space = undefined;
const ack_buffer_len = 512;
var buffer: [ack_buffer_len]u8 = @splat(0);

/// The exponent an endpoint that applies none uses (RFC 9000 §18.2). Test-only.
const no_exponent: u6 = 0;
/// One microsecond and one millisecond in nanoseconds, as the instants a test passes. Test-only.
const microsecond_ns = constants.nanoseconds_per_microsecond;
const microseconds_per_millisecond = 1_000;
const millisecond_ns = microseconds_per_millisecond * microsecond_ns;

/// Receives `numbers` as ack-eliciting packets with no ECN marking, one per instant. Test-only.
fn receive_all(numbers: []const u64) void {
    for (numbers, 0..) |number, index| {
        _ = test_space.receive(number, index * millisecond_ns, true, .not_ect);
    }
}

/// Writes the space's ACK frame and reads it back through the frame layer. Test-only.
fn written_ack(now_ns: u64, report_ecn: bool) !frame.Ack {
    var writer = Writer.init(&buffer);
    try testing.expect(try test_space.write_ack(&writer, now_ns, no_exponent, report_ecn));
    var reader = Reader.init(writer.written());
    const read_back = (try frame.read(&reader)).ack;
    // The frame occupies every octet written and no more.
    try testing.expectEqual(writer.written().len, reader.offset);
    return read_back;
}

test "§12.3: numbers start at 0, rise by one, and are never reused" {
    test_space.init(.initial);
    try testing.expectEqual(0, try test_space.next_number());
    try testing.expectEqual(1, try test_space.next_number());
    try testing.expectEqual(2, try test_space.next_number());
    // RFC 9000 §12.3: at 2^62-1 the sender stops rather than reusing a number.
    test_space.next_packet_number = constants.packet_number_max;
    try testing.expectEqual(constants.packet_number_max, try test_space.next_number());
    try testing.expectError(error.PacketNumbersExhausted, test_space.next_number());
}

test "§19.3: an ACK frame the space writes reads back as the ranges it holds" {
    test_space.init(.application);
    // Received 0..3, 8..9 and 20, which is three ranges descending.
    receive_all(&.{ 0, 1, 2, 3, 8, 9, 20 });
    const ack = try written_ack(20 * millisecond_ns, false);
    try testing.expectEqual(20, ack.ranges.largest_acknowledged);
    try testing.expectEqual(2, ack.ranges.count);
    try testing.expectEqual(null, ack.ecn);
    var walk = ack.ranges.iterator();
    try testing.expectEqual(frame.frame_ack.Range{ .smallest = 20, .largest = 20 }, walk.next().?);
    try testing.expectEqual(frame.frame_ack.Range{ .smallest = 8, .largest = 9 }, walk.next().?);
    try testing.expectEqual(frame.frame_ack.Range{ .smallest = 0, .largest = 3 }, walk.next().?);
    try testing.expectEqual(null, walk.next());
}

test "§19.3: one range writes a First ACK Range and no others" {
    test_space.init(.handshake);
    receive_all(&.{ 5, 6, 7 });
    const ack = try written_ack(7 * millisecond_ns, false);
    try testing.expectEqual(7, ack.ranges.largest_acknowledged);
    try testing.expectEqual(0, ack.ranges.count);
    try testing.expectEqual(2, ack.ranges.first_range);
    try testing.expectEqual(5, ack.ranges.smallest_acknowledged());
    // A space that has received nothing writes no frame at all.
    test_space.init(.handshake);
    var writer = Writer.init(&buffer);
    try testing.expect(!try test_space.write_ack(&writer, 0, no_exponent, false));
    try testing.expectEqual(0, writer.written().len);
}

test "§19.3, §13.2.5: the ACK Delay is the time since the largest arrived, shifted" {
    test_space.init(.application);
    // The largest, 4, arrived at 2 ms; 3 arrived later and does not move the instant.
    _ = test_space.receive(4, 2 * millisecond_ns, true, .not_ect);
    _ = test_space.receive(3, 5 * millisecond_ns, true, .not_ect);
    const ack = try written_ack(2 * millisecond_ns + 64 * microsecond_ns, false);
    try testing.expectEqual(64, ack.delay);
    // RFC 9000 §18.2: the exponent divides the field by a power of two.
    test_space.ack_eliciting_since_ack = 0;
    var writer = Writer.init(&buffer);
    _ = try test_space.write_ack(&writer, 2 * millisecond_ns + 64 * microsecond_ns, 3, false);
    var reader = Reader.init(writer.written());
    try testing.expectEqual(8, (try frame.read(&reader)).ack.delay);
}

test "§13.4.1: the counts rise per codepoint, once per packet, and never for a duplicate" {
    test_space.init(.application);
    _ = test_space.receive(0, 0, true, .ect_0);
    _ = test_space.receive(1, millisecond_ns, true, .ect_1);
    _ = test_space.receive(2, 2 * millisecond_ns, true, .ecn_ce);
    _ = test_space.receive(3, 3 * millisecond_ns, true, .not_ect);
    try testing.expectEqual(space_module.EcnCounts{ .ect_0 = 1, .ect_1 = 1, .ecn_ce = 1 }, test_space.ecn);
    // A duplicate is not processed, so no count moves.
    _ = test_space.receive(2, 4 * millisecond_ns, true, .ecn_ce);
    try testing.expectEqual(space_module.EcnCounts{ .ect_0 = 1, .ect_1 = 1, .ecn_ce = 1 }, test_space.ecn);
    // The frame carries the three counts when the endpoint reports them, and type 0x03 with it.
    const ack = try written_ack(4 * millisecond_ns, true);
    try testing.expectEqual(frame.EcnCounts{ .ect_0 = 1, .ect_1 = 1, .ecn_ce = 1 }, ack.ecn.?);
    var writer = Writer.init(&buffer);
    _ = try test_space.write_ack(&writer, 4 * millisecond_ns, no_exponent, true);
    try testing.expectEqual(constants.frame_ack_ecn, writer.written()[0]);
}

test "§13.2.1, §13.2.2: an ACK is owed after two, at once when out of order or marked" {
    test_space.init(.application);
    try testing.expect(!test_space.owes_ack());
    _ = test_space.receive(0, 0, true, .not_ect);
    // One ack-eliciting packet in order is not yet two.
    try testing.expect(!test_space.owes_ack());
    _ = test_space.receive(1, millisecond_ns, true, .not_ect);
    try testing.expect(test_space.owes_ack());
    // Writing the frame starts the count again.
    var writer = Writer.init(&buffer);
    _ = try test_space.write_ack(&writer, millisecond_ns, no_exponent, false);
    try testing.expect(!test_space.owes_ack());

    // RFC 9000 §13.2.1: a gap before an ack-eliciting packet is acknowledged without delay.
    _ = test_space.receive(5, 2 * millisecond_ns, true, .not_ect);
    try testing.expect(test_space.owes_ack());
    // And so is one marked ECN-CE, on its own.
    test_space.init(.application);
    _ = test_space.receive(0, 0, true, .ecn_ce);
    try testing.expect(test_space.owes_ack());
    // A packet that elicits nothing owes nothing, however many arrive.
    test_space.init(.application);
    _ = test_space.receive(0, 0, false, .not_ect);
    _ = test_space.receive(1, millisecond_ns, false, .not_ect);
    try testing.expect(!test_space.owes_ack());
}

test "§13.1: an acknowledgment for a packet never sent ends the connection" {
    test_space.init(.application);
    _ = try test_space.next_number();
    _ = try test_space.next_number();
    // Two packets sent, so 0 and 1 may be acknowledged and 2 may not.
    const report = try test_space.on_ack(ack_of(1));
    try testing.expectEqual(1, report.largest_acknowledged);
    try testing.expect(report.largest_is_new);
    try testing.expectError(error.AcknowledgedUnsentPacket, test_space.on_ack(ack_of(2)));
    // RFC 9000 §20.1: PROTOCOL_VIOLATION is 0x0a.
    try testing.expectEqual(0x0a, space_module.protocol_violation);
}

test "§13.2: acknowledgments are irrevocable, so the largest never goes backward" {
    test_space.init(.application);
    for (0..5) |_| _ = try test_space.next_number();
    _ = try test_space.on_ack(ack_of(3));
    try testing.expectEqual(3, test_space.largest_acknowledged.?);
    // An older frame says nothing new and leaves the largest where it is.
    const older = try test_space.on_ack(ack_of(1));
    try testing.expect(!older.largest_is_new);
    try testing.expectEqual(3, test_space.largest_acknowledged.?);
    const newer = try test_space.on_ack(ack_of(4));
    try testing.expect(newer.largest_is_new);
    try testing.expectEqual(4, test_space.largest_acknowledged.?);
}

/// An ACK frame acknowledging `largest` alone. Test-only.
fn ack_of(largest: u64) frame.Ack {
    return .{
        .ranges = .{ .largest_acknowledged = largest, .first_range = 0, .octets = "", .count = 0 },
        .delay = 0,
        .ecn = null,
    };
}

test "§12.3: the three spaces share nothing" {
    var initial: Space = undefined;
    var application: Space = undefined;
    initial.init(.initial);
    application.init(.application);
    _ = try initial.next_number();
    _ = initial.receive(7, 0, true, .ecn_ce);
    // The other space has its own numbers, its own ranges and its own counts.
    try testing.expectEqual(0, application.next_packet_number);
    try testing.expect(application.received.is_empty());
    try testing.expectEqual(space_module.EcnCounts{}, application.ecn);
    try testing.expectEqual(1, initial.ecn.ecn_ce);
}
