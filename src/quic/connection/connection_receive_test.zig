//! The tests of `connection_receive.zig`: RFC 9000 §12.2's coalescing walk, read against
//! datagrams built by `packet_header_write.zig` and opened by a suite that does no cryptography.
//!
//! `quic` cannot import `sim` (design §3), so the suite here is test-local. It holds no key: what
//! it models is the shape of `crypto.Suite.open` — where the Packet Number field sits, how long
//! the payload is, and which packets it refuses — because that is all the walk reads.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const header_write = @import("../packet/packet_header_write.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const identity_module = @import("connection_identity.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");

const testing = std.testing;
const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
var opener: Opener = undefined;
var walk: receive.Walk = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;

/// The connection IDs of RFC 9000 §7.3's Figure 7, as fixed octets (invariant 5).
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const other_octet: u8 = 0x77;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const other_id: [id_len]u8 = @splat(other_octet);

/// One octet of made-up payload, repeated. Nothing reads its value.
const payload_octet: u8 = 0x33;
/// A payload long enough that the Packet Number field and it reach RFC 9001 §5.4.2's sample, plus
/// room for the tag this opener pretends to strip.
const payload_len: usize = 8;
const tag_len: usize = constants.aead_tag_len;
const protected_len: usize = payload_len + tag_len;
const test_payload: [protected_len]u8 = @splat(payload_octet);

const datagram_len: usize = 512;
var datagram: [datagram_len]u8 = undefined;

/// A `crypto.Suite` that performs no cryptography. `open` reports the Packet Number field as one
/// octet, the payload as everything after it less a tag, and the number as that octet's value —
/// enough for the walk, which reads the offsets and nothing else.
const Opener = struct {
    /// Packet numbers this opener refuses, modelling RFC 9001 §5.5's failure. Test-only.
    refuses: ?u64,
    opened: usize,

    fn init(held: *Opener) void {
        held.* = .{ .refuses = null, .opened = 0 };
    }

    fn suite(held: *Opener) crypto.Suite {
        return .{ .context = held, .vtable = &vtable };
    }

    fn open(context: *anyopaque, opening: crypto.suite.Opening) crypto.suite.OpenError!crypto.suite.Opened {
        const held: *Opener = @ptrCast(@alignCast(context));
        const protected = opening.packet.len - opening.packet_number_offset;
        // RFC 9001 §5.5: a packet too short to hold a Packet Number field and an authentication
        // tag cannot be authenticated, and an endpoint discards it rather than failing.
        if (protected < 1 + tag_len) return error.Discarded;
        const number = opening.packet[opening.packet_number_offset];
        if (held.refuses) |refused| {
            // RFC 9001 §5.5: what a real suite answers when the tag does not match, which is
            // what the walk must carry on past.
            if (number == refused) return error.Discarded;
        }
        held.opened += 1;
        return .{
            .packet_number = number,
            .packet_number_len = 1,
            .payload_len = protected - 1 - tag_len,
            .key_set = .current,
        };
    }

    const vtable: crypto.suite.VTable = .{
        .install_initial_keys = unreachable_install,
        .keys_available = unreachable_available,
        .seal = unreachable_seal,
        .open = open,
        .retry_tag_valid = unreachable_tag_valid,
        .retry_tag_write = unreachable_tag_write,
        .update_keys = unreachable_update,
        .key_phase = unreachable_phase,
        .discard_previous_keys = unreachable_discard_previous,
        .discard_keys = unreachable_discard,
    };
};

/// The walk calls `open` alone, so every other member is unreached: a call to one would mean a
/// test drove something these cases do not cover.
fn unreachable_install(_: *anyopaque, _: crypto.suite.Role, _: []const u8) crypto.suite.InstallError!void {
    unreachable;
}
fn unreachable_available(_: *const anyopaque, _: Level, _: crypto.suite.Direction) bool {
    unreachable;
}
fn unreachable_seal(_: *anyopaque, _: crypto.suite.Sealing, _: []u8) crypto.suite.SealError!usize {
    unreachable;
}
fn unreachable_tag_valid(
    _: *const anyopaque,
    _: []const u8,
    _: *const [crypto.constants.retry_integrity_tag_len]u8,
) bool {
    unreachable;
}
fn unreachable_tag_write(
    _: *const anyopaque,
    _: []const u8,
    _: *[crypto.constants.retry_integrity_tag_len]u8,
) crypto.suite.RetryTagError!void {
    unreachable;
}
fn unreachable_update(_: *anyopaque) crypto.suite.UpdateError!void {
    unreachable;
}
fn unreachable_phase(_: *const anyopaque) bool {
    unreachable;
}
fn unreachable_discard_previous(_: *anyopaque) void {
    unreachable;
}
fn unreachable_discard(_: *anyopaque, _: Level) void {
    unreachable;
}

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// A connection with every level installed for reading and the handshake complete, so a test that
/// is about the walk is never stopped by RFC 9001 §4.9 or §5.7.
fn open_connection() void {
    opener.init();
    test_connection.init(.{
        .role = .client,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    keys.on_keys_installed(&test_connection, .initial, .read);
    keys.on_keys_installed(&test_connection, .handshake, .read);
    keys.on_keys_installed(&test_connection, .application, .read);
    test_connection.handshake_complete = true;
}

/// Writes one long-header packet into `writer` and returns nothing: the payload is made up and
/// the opener strips a tag off it.
fn write_packet(writer: *Writer, long_type: anytype, dcid: []const u8, number: u8) !void {
    try header_write.write_long(writer, .{
        .type = long_type,
        .dcid = dcid,
        .scid = &peer_id,
        .packet_number = .{ .value = number, .len = 1 },
        .protected_payload_len = protected_len,
    });
    try writer.write_bytes(&test_payload);
}

fn start(len: usize) void {
    walk.init(.{ .octets = datagram[0..len], .now_ns = test_now_ns, .ecn = .not_ect });
}

test "RFC 9000 §12.2: two packets coalesced in one datagram are both processed" {
    open_connection();
    var writer = Writer.init(&datagram);
    // "Coalescing packets in order of increasing encryption levels (Initial, 0-RTT, Handshake,
    // 1-RTT) makes it more likely that the receiver will be able to process all the packets in a
    // single pass", which is the order a real sender uses.
    try write_packet(&writer, .initial, &local_id, 0);
    try write_packet(&writer, .handshake, &local_id, 1);
    start(writer.written().len);

    const first = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(Level.initial, first.opened.level);
    try testing.expectEqual(0, first.opened.packet_number);
    try testing.expectEqual(payload_len, first.opened.payload.len);
    // RFC 9000 §17.2: the Payload begins after the Packet Number field, so the frames start at
    // `packet_number_offset + packet_number_len` and the number's own octet is not one of them.
    // Every payload octet is the same value and the number's is not, so a slice taken one octet
    // early shows here rather than in the length, which would still be right.
    for (first.opened.payload) |octet| try testing.expectEqual(payload_octet, octet);

    const second = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(Level.handshake, second.opened.level);
    try testing.expectEqual(1, second.opened.packet_number);

    // "Every QUIC packet that is coalesced into a single UDP datagram is separate and complete",
    // so the datagram is spent once both have been taken.
    try testing.expectEqual(null, try receive.next(&walk, &test_connection, opener.suite()));
    try testing.expectEqual(2, opener.opened);
}

test "RFC 9000 §12.2: a packet that will not open does not stop the ones after it" {
    open_connection();
    var writer = Writer.init(&datagram);
    try write_packet(&writer, .initial, &local_id, 0);
    try write_packet(&writer, .handshake, &local_id, 1);
    start(writer.written().len);
    // §12.2: "if decryption fails ... the receiver MAY either discard or buffer the packet for
    // later processing and MUST attempt to process the remaining packets." colibri discards.
    opener.refuses = 0;

    const first = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(receive.Discarded.would_not_open, first.discarded);
    // The Length field is what said where the refused packet ended, so the next one is found.
    const second = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(Level.handshake, second.opened.level);
    try testing.expectEqual(1, second.opened.packet_number);
}

test "RFC 9000 §12.2: a later packet with another Destination Connection ID is ignored" {
    open_connection();
    var writer = Writer.init(&datagram);
    try write_packet(&writer, .initial, &local_id, 0);
    // "Receivers SHOULD ignore any subsequent packets with a different Destination Connection ID
    // than the first packet in the datagram."
    try write_packet(&writer, .handshake, &other_id, 1);
    try write_packet(&writer, .handshake, &local_id, 2);
    start(writer.written().len);

    _ = (try receive.next(&walk, &test_connection, opener.suite())).?;
    const ignored = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(receive.Discarded.other_connection, ignored.discarded);
    // It was stepped over rather than ending the walk, so the third packet still arrives.
    const third = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(2, third.opened.packet_number);
    // And the ignored one never reached the suite.
    try testing.expectEqual(2, opener.opened);
}

test "RFC 9000 §12.3: a packet number already processed is discarded, not read again" {
    open_connection();
    var writer = Writer.init(&datagram);
    try write_packet(&writer, .initial, &local_id, 0);
    try write_packet(&writer, .initial, &local_id, 0);
    start(writer.written().len);

    _ = (try receive.next(&walk, &test_connection, opener.suite())).?;
    // The walk asks the space; nothing has recorded the number yet, because §13.1 waits for the
    // frames. So the test records it the way the frame layer will.
    _ = test_connection.space_at(.initial).receive(0, test_now_ns, true, .not_ect);
    const repeat = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(receive.Discarded.already_processed, repeat.discarded);
}

test "RFC 9001 §4.9, §5.7: a level colibri cannot read is a discard and not an error" {
    open_connection();
    // A client discards its Initial keys when it first sends a Handshake packet (§4.9.1), and
    // §4.9.1 adds that endpoints "MUST NOT send Initial packets after this point". One arriving
    // afterwards is dropped rather than closed on.
    keys.on_keys_installed(&test_connection, .handshake, .write);
    var writer = Writer.init(&datagram);
    try write_packet(&writer, .initial, &local_id, 0);
    try write_packet(&writer, .handshake, &local_id, 1);
    start(writer.written().len);
    test_connection.keys.mark_discarded(.initial);

    const dropped = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(receive.Discarded.no_keys, dropped.discarded);
    try testing.expectEqual(0, opener.opened);
    // The Handshake packet behind it is still read, which is what §12.2 requires.
    const kept = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(Level.handshake, kept.opened.level);
}

test "RFC 9001 §5.7: a 1-RTT packet before the handshake completes is not opened" {
    open_connection();
    test_connection.handshake_complete = false;
    var writer = Writer.init(&datagram);
    try header_write.write_short(&writer, .{
        .dcid = &local_id,
        .packet_number = .{ .value = 0, .len = 1 },
        .key_phase = false,
    });
    try writer.write_bytes(&test_payload);
    start(writer.written().len);

    // "Endpoints in either role MUST NOT decrypt 1-RTT packets from their peer prior to
    // completing the handshake", even though the keys are installed.
    const dropped = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(receive.Discarded.no_keys, dropped.discarded);
    try testing.expectEqual(0, opener.opened);
}

test "RFC 9000 §17.3: a short header is the last packet of its datagram" {
    open_connection();
    var writer = Writer.init(&datagram);
    try write_packet(&writer, .initial, &local_id, 0);
    try header_write.write_short(&writer, .{
        .dcid = &local_id,
        .packet_number = .{ .value = 9, .len = 1 },
        .key_phase = false,
    });
    try writer.write_bytes(&test_payload);
    start(writer.written().len);

    _ = (try receive.next(&walk, &test_connection, opener.suite())).?;
    const last = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(Level.application, last.opened.level);
    try testing.expectEqual(9, last.opened.packet_number);
    // A short header carries no Length, so its packet runs to the end and nothing follows it.
    try testing.expectEqual(null, try receive.next(&walk, &test_connection, opener.suite()));
}

test "RFC 9000 §12.2: a header that will not parse ends the walk" {
    open_connection();
    var writer = Writer.init(&datagram);
    try write_packet(&writer, .initial, &local_id, 0);
    const good = writer.written().len;
    // A long header whose Fixed Bit is zero, which §17.2 says MUST be discarded. Where the packet
    // ends is unknown, so there is no way to find what follows it.
    datagram[good] = 0x80;
    start(good + 1);

    _ = (try receive.next(&walk, &test_connection, opener.suite())).?;
    const stopped = (try receive.next(&walk, &test_connection, opener.suite())).?;
    try testing.expectEqual(receive.Discarded.unreadable_header, stopped.discarded);
    try testing.expectEqual(null, try receive.next(&walk, &test_connection, opener.suite()));
}
