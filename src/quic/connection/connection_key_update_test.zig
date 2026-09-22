//! The tests of `connection_key_update.zig`: RFC 9001 §6's timing, driven both directly and
//! through the two call sites that reach it — `connection_receive.zig` on the way in and
//! `packet_build.zig` on the way out.
//!
//! `quic` cannot import `sim` (design §3), so the suite is `packet_build_test.zig`'s `RoundTrip`,
//! which protects nothing and reports the key set a test asks it for. What is checked here is
//! when colibri calls `update_keys` and when it refuses, which is all §6 leaves to colibri.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const header_write = @import("../packet/packet_header_write.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const key_update = @import("connection_key_update.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const packet_build = @import("packet_build.zig");
const build_test = @import("packet_build_test.zig");

const testing = std.testing;
const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;
var scratch: packet_build.DefaultScratch = .{};
var walk: receive.Walk = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

/// Handshake octets a provider owes, which is what gives a packet below the application level
/// something to carry.
const crypto_octet: u8 = 0x6d;
const crypto_octets: [payload_len]u8 = @splat(crypto_octet);

/// One octet of made-up payload, repeated. Nothing reads its value.
const payload_octet: u8 = 0x33;
/// Long enough that the octets after the Packet Number field hold a tag and a payload.
const payload_len: usize = 8;
const protected_len: usize = payload_len + constants.aead_tag_len;
const test_payload: [protected_len]u8 = @splat(payload_octet);

const datagram_len: usize = 256;
var datagram: [datagram_len]u8 = undefined;

/// Where `ack_payload` builds one packet's octets: an ACK frame and the octets `RoundTrip` reads
/// as a tag.
const ack_octets_len: usize = 32;
var ack_octets: [ack_octets_len]u8 = undefined;
const tag_octets: [constants.aead_tag_len]u8 = @splat(0);

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// A connection with the 1-RTT keys installed both ways and the handshake complete, which is the
/// state RFC 9001 §6 begins in: §5.7 forbids opening a 1-RTT packet before it.
fn open_connection() void {
    suite_holder.init();
    provider_holder = .{};
    test_connection.init(.{
        .role = .client,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    keys.on_keys_installed(&test_connection, .application, .read);
    keys.on_keys_installed(&test_connection, .application, .write);
    test_connection.handshake_complete = true;
    test_connection.handshake_confirmed = true;
}

fn suite() crypto.Suite {
    return suite_holder.suite();
}

/// Sends one 1-RTT packet number and has the peer acknowledge it, which is the state RFC 9001
/// §6.1 requires before another key update may be initiated.
fn send_and_acknowledge() void {
    const space = test_connection.space_at(.application);
    const number = space.next_number() catch unreachable;
    key_update.on_packet_sent(&test_connection, .application, number, false);
    space.largest_acknowledged = number;
}

/// Says the peer acknowledged every 1-RTT packet up to `number`, which is what RFC 9001 §6.1
/// compares the lowest number sent in the current phase against.
fn acknowledge(number: u64) void {
    test_connection.space_at(.application).largest_acknowledged = number;
}

/// Walks one 1-RTT packet the peer wrote, under the key set `suite_holder.opens_with` names.
fn walk_short(number: u8) !receive.Outcome {
    return walk_payload(number, &test_payload);
}

/// The same, over octets a test chose. `body` ends with the octets `RoundTrip` treats as the
/// tag, so the frames the frame layer reads are everything before them.
fn walk_payload(number: u8, body: []const u8) !receive.Outcome {
    var writer = Writer.init(&datagram);
    try header_write.write_short(&writer, .{
        .dcid = &local_id,
        .packet_number = .{ .value = number, .len = 1 },
        // RFC 9001 §6: the bit the peer wrote. `RoundTrip` reads the key set from its own field
        // rather than from the bit, so what this value is does not steer the test.
        .key_phase = false,
    });
    try writer.write_bytes(body);
    const len = writer.written().len;
    walk.init(.{ .octets = datagram[0..len], .now_ns = test_now_ns, .ecn = .not_ect });
    return (try receive.next(&walk, &test_connection, suite())).?;
}

/// One ACK frame naming `largest`, followed by the octets `RoundTrip` strips as a tag
/// (RFC 9000 §19.3).
fn ack_payload(largest: u64) []const u8 {
    var writer = Writer.init(&ack_octets);
    frame_module.write(&writer, .{ .ack = .{
        .ranges = .{ .largest_acknowledged = largest, .first_range = 0, .octets = &.{}, .count = 0 },
        .delay = 0,
        .ecn = null,
    } }) catch unreachable;
    writer.write_bytes(&tag_octets) catch unreachable;
    return writer.written();
}

test "RFC 9001 §6.2: the key set of the packet that opened reaches the frame layer" {
    open_connection();
    // RFC 9001 §6.1: packet 4 and every number above it went out under the current key phase.
    key_update.on_packet_sent(&test_connection, .application, 4, false);
    suite_holder.opens_with = .previous;

    // §6.2: an acknowledgment carried under the old keys that names a packet protected with the
    // newer ones. The receive path opened it; the frame layer is what refuses it.
    const outcome = try walk_payload(6, ack_payload(4));
    try testing.expectError(
        frames.Error.OldKeysAcknowledgeNew,
        frames.process(&test_connection, outcome.opened, test_now_ns),
    );
}

test "RFC 9001 §6.1: a key update is refused before the handshake is confirmed" {
    open_connection();
    test_connection.handshake_confirmed = false;
    key_update.on_packet_sent(&test_connection, .application, 0, false);
    acknowledge(0);
    try testing.expectError(error.HandshakeNotConfirmed, key_update.initiate(&test_connection, suite()));
    try testing.expectEqual(0, suite_holder.updates);
}

test "RFC 9001 §6.1: a key update waits for an acknowledgment of the current phase" {
    open_connection();
    // Nothing has gone out in this phase, so nothing in it can have been acknowledged.
    try testing.expectError(error.PhaseNotAcknowledged, key_update.initiate(&test_connection, suite()));

    key_update.on_packet_sent(&test_connection, .application, 7, false);
    try testing.expectEqual(7, test_connection.key_phase.lowest_sent.?);
    // A packet has gone out, and the peer has acknowledged nothing in the 1-RTT space at all.
    try testing.expectError(error.PhaseNotAcknowledged, key_update.initiate(&test_connection, suite()));

    // An acknowledgment below the lowest number of this phase names a packet of the phase before.
    acknowledge(6);
    try testing.expectError(error.PhaseNotAcknowledged, key_update.initiate(&test_connection, suite()));

    acknowledge(7);
    try key_update.initiate(&test_connection, suite());
    try testing.expectEqual(1, suite_holder.updates);
    // RFC 9001 §6.1: the new phase has sent nothing and received nothing yet.
    try testing.expectEqual(null, test_connection.key_phase.lowest_sent);
    try testing.expectEqual(null, test_connection.key_phase.current_lowest);
    try testing.expect(!test_connection.key_phase.pending_ack);
}

test "RFC 9001 §6.1: a suite that offers no key update refuses one" {
    open_connection();
    suite_holder.refuses_update = true;
    key_update.on_packet_sent(&test_connection, .application, 3, false);
    acknowledge(3);
    try testing.expectError(error.Unsupported, key_update.initiate(&test_connection, suite()));
    try testing.expectEqual(0, suite_holder.updates);
}

test "RFC 9001 §6.1: only a 1-RTT packet moves what the phase counts" {
    open_connection();
    key_update.on_packet_sent(&test_connection, .initial, 2, true);
    key_update.on_packet_sent(&test_connection, .handshake, 3, true);
    try testing.expectEqual(null, test_connection.key_phase.lowest_sent);
    key_update.on_packet_sent(&test_connection, .application, 9, false);
    key_update.on_packet_sent(&test_connection, .application, 10, false);
    // The lowest sent in the phase, not the latest.
    try testing.expectEqual(9, test_connection.key_phase.lowest_sent.?);
}

test "RFC 9001 §6.2: a packet under the next keys moves this endpoint's keys too" {
    open_connection();
    suite_holder.opens_with = .next;
    const outcome = try walk_short(4);
    try testing.expectEqual(Level.application, outcome.opened.level);
    try testing.expectEqual(1, suite_holder.updates);
    // §6.2: the packet that initiated the update is the first of the new phase.
    try testing.expectEqual(4, test_connection.key_phase.current_lowest.?);
    try testing.expect(test_connection.key_phase.pending_ack);
    // §6.1: the new phase has sent nothing, so §6.1 refuses an update of colibri's own.
    try testing.expectEqual(null, test_connection.key_phase.lowest_sent);
}

test "RFC 9001 §6.2: a second update before the answer is acknowledged closes the connection" {
    open_connection();
    suite_holder.opens_with = .next;
    _ = try walk_short(4);
    // The peer updated again without waiting for an acknowledgment under the first update's keys.
    try testing.expectError(error.ConsecutiveKeyUpdate, walk_short(5));
    try testing.expectEqual(1, suite_holder.updates);
    // RFC 9001 §6.7: KEY_UPDATE_ERROR is 0x0e.
    try testing.expectEqual(
        error_code.key_update_error,
        receive.connection_error_code(error.ConsecutiveKeyUpdate),
    );
}

test "RFC 9001 §6.2: an acknowledgment under the new keys completes the update" {
    open_connection();
    suite_holder.opens_with = .next;
    _ = try walk_short(4);
    // A 1-RTT packet carrying no ACK does not complete it: §6.2 asks for the acknowledgment.
    key_update.on_packet_sent(&test_connection, .application, 8, false);
    try testing.expect(test_connection.key_phase.pending_ack);
    key_update.on_packet_sent(&test_connection, .application, 9, true);
    try testing.expect(!test_connection.key_phase.pending_ack);

    // The next update is now the peer awaiting confirmation properly, and is answered.
    _ = try walk_short(10);
    try testing.expectEqual(2, suite_holder.updates);
}

test "RFC 9001 §6.2: a suite that will not move to its next keys ends the connection" {
    open_connection();
    suite_holder.opens_with = .next;
    suite_holder.refuses_update = true;
    try testing.expectError(error.SuiteRefusedUpdate, walk_short(4));
    // RFC 9000 §11: no code names this, so it is INTERNAL_ERROR and not KEY_UPDATE_ERROR.
    try testing.expectEqual(
        error_code.internal_error,
        receive.connection_error_code(error.SuiteRefusedUpdate),
    );
}

test "RFC 9001 §6.4: old keys above the current phase's lowest close the connection" {
    open_connection();
    suite_holder.opens_with = .current;
    _ = try walk_short(5);
    try testing.expectEqual(5, test_connection.key_phase.current_lowest.?);

    suite_holder.opens_with = .previous;
    // Below the lowest of the current phase, this is the delayed packet §6.5 keeps old keys for.
    _ = try walk_short(3);
    // Above it, a lower-numbered packet used newer keys, which §6.4 makes a KEY_UPDATE_ERROR.
    try testing.expectError(error.OldKeysAboveCurrentPhase, walk_short(7));
    try testing.expectEqual(
        error_code.key_update_error,
        receive.connection_error_code(error.OldKeysAboveCurrentPhase),
    );
}

test "RFC 9001 §6.4: old keys before any current-phase packet close nothing" {
    open_connection();
    suite_holder.opens_with = .previous;
    // Nothing has opened under the current keys, so no lower-numbered packet used newer ones.
    const outcome = try walk_short(9);
    try testing.expectEqual(9, outcome.opened.packet_number);
    try testing.expectEqual(null, test_connection.key_phase.current_lowest);
}

test "RFC 9001 §6.5: the current phase's lowest is the lowest, not the first to arrive" {
    open_connection();
    suite_holder.opens_with = .current;
    _ = try walk_short(7);
    _ = try walk_short(4);
    try testing.expectEqual(4, test_connection.key_phase.current_lowest.?);
    _ = try walk_short(9);
    try testing.expectEqual(4, test_connection.key_phase.current_lowest.?);
}

test "RFC 9001 §6: a 1-RTT packet carries the Key Phase bit the suite answers" {
    open_connection();
    owe_ack(0, 1);
    const first = (try build_1rtt()).?;
    try testing.expect(!key_phase_of(datagram[0..first.len]));

    // RFC 9001 §6.1: "The endpoint toggles the value of the Key Phase bit and uses the updated
    // key and IV to protect all subsequent packets."
    try suite_holder.suite().vtable.update_keys(&suite_holder);
    owe_ack(2, 3);
    const second = (try build_1rtt()).?;
    try testing.expect(key_phase_of(datagram[0..second.len]));
}

test "RFC 9001 §6.1, §6.2: the send path reports what it sealed" {
    open_connection();
    test_connection.key_phase.pending_ack = true;
    owe_ack(0, 1);

    const built = (try build_1rtt()).?;
    // The packet carried an ACK, so §6.2's answer is complete and §6.1 has a lowest number.
    try testing.expect(!test_connection.key_phase.pending_ack);
    try testing.expectEqual(built.packet_number, test_connection.key_phase.lowest_sent.?);
}

/// RFC 9000 §13.2.2: a receiver owes an ACK after two ack-eliciting packets, which is what makes
/// the next 1-RTT packet this endpoint builds carry one.
fn owe_ack(first: u64, second: u64) void {
    const space = test_connection.space_at(.application);
    _ = space.receive(first, test_now_ns, true, .not_ect);
    _ = space.receive(second, test_now_ns, true, .not_ect);
    std.debug.assert(space.owes_ack());
}

fn build_1rtt() !?packet_build.Built {
    return build_at(.application);
}

fn build_at(level: Level) !?packet_build.Built {
    return packet_build.build(
        &test_connection,
        suite(),
        provider_holder.provider(),
        level,
        &scratch,
        &datagram,
        test_now_ns,
    );
}

test "RFC 9001 §6.6: the confidentiality limit is met with a key update, not a close" {
    open_connection();
    owe_ack(0, 1);
    // §6.1 permits an update: the handshake is confirmed and the peer acknowledged this phase.
    send_and_acknowledge();
    // RFC 9001 §6.6: these keys will protect nothing more.
    suite_holder.seals_left = 0;
    suite_holder.seals_per_key = 1;

    const built = (try build_1rtt()).?;
    try testing.expectEqual(1, suite_holder.updates);
    // §6.1: the packet went out under the new phase, so it carries the toggled bit.
    try testing.expect(key_phase_of(datagram[0..built.len]));
}

test "RFC 9001 §6.6: a limit no key update can free ends the connection" {
    open_connection();
    owe_ack(0, 1);
    // §6.1 refuses: no packet of this phase has been acknowledged, so no update is possible.
    suite_holder.seals_left = 0;
    try testing.expectError(error.AeadLimitReached, build_1rtt());
    try testing.expectEqual(0, suite_holder.updates);
    // §6.6: "the endpoint MUST stop using those keys", so the packet is not offered to them a
    // second time once §6.1 has refused the update that would have replaced them.
    try testing.expectEqual(1, suite_holder.seal_attempts);
    // RFC 9001 §6.6 names AEAD_LIMIT_REACHED, which RFC 9000 §20.1 numbers 0x0f.
    try testing.expectEqual(
        error_code.aead_limit_reached,
        packet_build.connection_error_code(error.AeadLimitReached).?,
    );
}

test "RFC 9001 §6.6: keys that refuse again after an update end the connection" {
    open_connection();
    owe_ack(0, 1);
    send_and_acknowledge();
    // The update installs a set that is already at its own limit.
    suite_holder.seals_left = 0;
    suite_holder.seals_per_key = 0;
    try testing.expectError(error.AeadLimitReached, build_1rtt());
    try testing.expectEqual(1, suite_holder.updates);
}

test "RFC 9001 §6.6: below the application level no key update can free the keys" {
    open_connection();
    keys.on_keys_installed(&test_connection, .initial, .write);
    provider_holder = .{ .owed = &crypto_octets, .owed_level = .initial };
    // §6.1 would permit an update, so what stops one here is the level and nothing else.
    send_and_acknowledge();
    suite_holder.seals_left = 0;
    // §6.1's Note: "Keys of packets other than the 1-RTT packets are never updated."
    try testing.expectError(error.AeadLimitReached, build_at(.initial));
    try testing.expectEqual(0, suite_holder.updates);
}

test "RFC 9000 §12.3: a space out of packet numbers closes with no frame" {
    // "the sender MUST close the connection without sending a CONNECTION_CLOSE frame or any
    // further packets", so there is no code to carry.
    try testing.expectEqual(null, packet_build.connection_error_code(error.PacketNumbersExhausted));
}

/// RFC 9000 §17.3.1: the Key Phase bit of a short header, which RFC 9001 §5.4 protects and this
/// suite leaves in the clear.
fn key_phase_of(packet: []const u8) bool {
    return packet[0] & constants.key_phase_bit != 0;
}
