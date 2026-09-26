//! The tests of the Destination Connection ID a 1-RTT packet carries (RFC 9000 §5.1.2): the
//! active ID the peer issued, whose length need not be the handshake's.
//!
//! The fixture is `packet_build_test.zig`'s.
const std = @import("std");
const constants = @import("../../constants.zig");
const connection_id = @import("../../connection_id.zig");
const keys = @import("../connection_keys.zig");
const connection_module = @import("../connection.zig");
const fixture = @import("packet_build_test.zig");

const testing = std.testing;
const Connection = connection_module.Connection;

/// The peer's handshake ID, and a longer one it issues after. Test-only.
const first_len: usize = 4;
const first_octet: u8 = 0x51;
const first_id: [first_len]u8 = @splat(first_octet);
const next_len: usize = 8;
const next_octet: u8 = 0x5e;
const next_id: [next_len]u8 = @splat(next_octet);
const limit = constants.active_connection_id_limit_min;

test "RFC 9000 §17.3: a 1-RTT packet is laid out for the length of the ID it goes to" {
    fixture.open_connection();
    for ([_]*Connection{ &fixture.test_connection, &fixture.peer_connection }) |connection| {
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
        connection.handshake_complete = true;
    }
    const remote = &fixture.test_connection.remote_ids;
    remote.hold_initial(&first_id);
    var next: connection_id.Entry = .{ .sequence_number = 1, .len = next_len, .octets = @splat(0), .stateless_reset_token = @splat(0) };
    @memcpy(next.octets[0..next_len], &next_id);
    // RFC 9000 §5.1.2: a Retire Prior To of 1 moves colibri to the longer ID.
    try remote.offer(next, 1, limit);
    // A short header carries no length for its Destination Connection ID (§17.3), so a builder
    // that sized the header by another ID would lay the packet out past the datagram, which only
    // a payload that fills the room shows.
    fixture.fake = .{ .owed = &fixture.long_flight, .owed_level = .application };
    const built = (try fixture.build_at(.application)).?;
    try testing.expectEqual(fixture.datagram.len, built.len);
    try testing.expectEqualSlices(u8, &next_id, fixture.datagram[1 .. 1 + next_len]);
}
