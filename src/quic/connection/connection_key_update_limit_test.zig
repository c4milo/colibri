//! RFC 9001 §6.6's AEAD limits as the send path meets them, which is the other half of the key
//! update: §6.6 is what makes an endpoint update its keys when it would rather not.
//!
//! The fixture is `connection_key_update_test.zig`'s, because these cases drive the same
//! connection and the same `RoundTrip` suite; split off it for length.
const std = @import("std");
const error_code = @import("../error_code.zig");
const keys = @import("connection_keys.zig");
const packet_build = @import("packet_build/packet_build.zig");
const fixture = @import("connection_key_update_test.zig");

const testing = std.testing;

test "RFC 9001 §6.6: the confidentiality limit is met with a key update, not a close" {
    fixture.open_connection();
    fixture.owe_ack(0, 1);
    // §6.1 permits an update: the handshake is confirmed and the peer acknowledged this phase.
    // §6.5's wait has not passed, and §6.6's update is a MUST that does not wait on a SHOULD.
    fixture.send_and_acknowledge();
    // RFC 9001 §6.6: these keys will protect nothing more.
    fixture.suite_holder.seals_left = 0;
    fixture.suite_holder.seals_per_key = 1;

    const built = (try fixture.build_1rtt()).?;
    try testing.expectEqual(1, fixture.suite_holder.updates);
    // §6.1: the packet went out under the new phase, so it carries the toggled bit.
    try testing.expect(fixture.key_phase_of(fixture.datagram[0..built.len]));
}

test "RFC 9001 §6.6: a limit no key update can free ends the connection" {
    fixture.open_connection();
    fixture.owe_ack(0, 1);
    // §6.1 refuses: no packet of this phase has been acknowledged, so no update is possible.
    fixture.suite_holder.seals_left = 0;
    try testing.expectError(error.AeadLimitReached, fixture.build_1rtt());
    try testing.expectEqual(0, fixture.suite_holder.updates);
    // §6.6: "the endpoint MUST stop using those keys", so the packet is not offered to them a
    // second time once §6.1 has refused the update that would have replaced them.
    try testing.expectEqual(1, fixture.suite_holder.seal_attempts);
    // RFC 9001 §6.6 names AEAD_LIMIT_REACHED, which RFC 9000 §20.1 numbers 0x0f.
    try testing.expectEqual(
        error_code.aead_limit_reached,
        packet_build.connection_error_code(error.AeadLimitReached).?,
    );
}

test "RFC 9001 §6.6: keys that refuse again after an update end the connection" {
    fixture.open_connection();
    fixture.owe_ack(0, 1);
    fixture.send_and_acknowledge();
    // The update installs a set that is already at its own limit.
    fixture.suite_holder.seals_left = 0;
    fixture.suite_holder.seals_per_key = 0;
    try testing.expectError(error.AeadLimitReached, fixture.build_1rtt());
    try testing.expectEqual(1, fixture.suite_holder.updates);
}

test "RFC 9001 §6.6: below the application level no key update can free the keys" {
    fixture.open_connection();
    keys.on_keys_installed(&fixture.test_connection, .initial, .write);
    fixture.provider_holder = .{ .owed = &fixture.crypto_octets, .owed_level = .initial };
    // §6.1 would permit an update, so what stops one here is the level and nothing else.
    fixture.send_and_acknowledge();
    fixture.suite_holder.seals_left = 0;
    // §6.1's Note: "Keys of packets other than the 1-RTT packets are never updated."
    try testing.expectError(error.AeadLimitReached, fixture.build_at(.initial));
    try testing.expectEqual(0, fixture.suite_holder.updates);
}

test "RFC 9000 §12.3: a space out of packet numbers closes with no frame" {
    // "the sender MUST close the connection without sending a CONNECTION_CLOSE frame or any
    // further packets", so there is no code to carry.
    try testing.expectEqual(null, packet_build.connection_error_code(error.PacketNumbersExhausted));
}
