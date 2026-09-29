//! RFC 9369 §4.1's versions as the receive walk meets them: a client's one switch at the first long
//! header in another version, and the drop of a packet in a version the connection does not admit.
//!
//! The fixture is `connection_receive_test.zig`'s, because these cases drive the same walk and
//! the same suite; split off it for length.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const header_write = @import("../packet/packet_header_write.zig");
const receive = @import("connection_receive.zig");
const connection_version = @import("connection_version.zig");
const fixture = @import("connection_receive_test.zig");

const testing = std.testing;
const Writer = core.Writer;
const Version = crypto.suite.Version;

/// Writes one long-header packet of `version` to this endpoint, from the fixture's peer.
fn write_versioned(writer: *Writer, version: Version, long_type: anytype, number: u8) !void {
    try header_write.write_long(writer, .{
        .version = version,
        .type = long_type,
        .dcid = &fixture.local_id,
        .scid = &fixture.peer_id,
        .packet_number = .{ .value = number, .len = 1 },
        .protected_payload_len = fixture.protected_len,
    });
    try writer.write_bytes(&fixture.test_payload);
}

fn next() !receive.Outcome {
    return (try receive.next(&fixture.walk, &fixture.test_connection, fixture.opener.suite())).?;
}

fn expect_dropped(outcome: receive.Outcome) !void {
    try testing.expectEqual(receive.Discarded.other_version, outcome.discarded);
}

test "RFC 9369 §4.1: a client switches at the first long header in another version, then opens it" {
    fixture.open_connection();
    var writer = Writer.init(&fixture.datagram);
    try write_versioned(&writer, .v2, .initial, 0);
    try write_versioned(&writer, .v2, .handshake, 0);
    try write_versioned(&writer, .v1, .handshake, 1);
    fixture.start(writer.written().len);
    // "The client learns the negotiated version by observing the first long header Version field
    // that differs from the original version", and the switch comes before the packet opens.
    try testing.expectEqual(.initial, (try next()).opened.level);
    try testing.expectEqual(Version.v2, fixture.opener.switched.?);
    const versions = fixture.test_connection.versions;
    try testing.expect(versions.negotiated == .v2 and versions.original == .v1 and versions.settled);
    // "Both endpoints MUST send Handshake and 1-RTT packets using the negotiated version. An
    // endpoint MUST drop packets using any other version."
    try testing.expectEqual(.handshake, (try next()).opened.level);
    try expect_dropped(try next());
    // A 1-RTT packet names no version, and opens in the negotiated one.
    writer = Writer.init(&fixture.datagram);
    try header_write.write_short(&writer, .{ .dcid = &fixture.local_id, .packet_number = .{ .value = 0, .len = 1 }, .key_phase = false });
    try writer.write_bytes(&fixture.test_payload);
    fixture.start(writer.written().len);
    try testing.expectEqual(.application, (try next()).opened.level);
    // The server answers Initial packets in the original version until it has read the client's
    // transport parameters, so one of those still opens.
    writer = Writer.init(&fixture.datagram);
    try write_versioned(&writer, .v1, .initial, 1);
    fixture.start(writer.written().len);
    try testing.expectEqual(.initial, (try next()).opened.level);
    try testing.expectEqual(4, fixture.opener.opened);
}

test "RFC 9369 §4.1: once the version is settled, a packet in another version is dropped and the walk goes on" {
    // A client that read the server's CRYPTO octets in the original version switches no more.
    fixture.open_connection();
    connection_version.settle(&fixture.test_connection);
    var writer = Writer.init(&fixture.datagram);
    try write_versioned(&writer, .v2, .initial, 0);
    try write_versioned(&writer, .v1, .handshake, 0);
    fixture.start(writer.written().len);
    try expect_dropped(try next());
    try testing.expectEqual(.handshake, (try next()).opened.level);
    try testing.expectEqual(null, fixture.opener.switched);
    // A server runs the version of the client's first flight: one that lists version 2 as well
    // (RFC 9368 §3) still drops a version 2 packet on a connection that started in version 1.
    fixture.open_server();
    fixture.test_connection.local_parameters.version_information = .of(0x0000_0001, &.{ 0x0000_0001, 0x6b33_43cf });
    writer = Writer.init(&fixture.datagram);
    try write_versioned(&writer, .v2, .initial, 0);
    fixture.start(writer.written().len);
    try expect_dropped(try next());
    try testing.expectEqual(0, fixture.opener.opened);
}

test "RFC 9369 §4.1: a switch the suite refuses, or to a version the client did not list, drops the packet" {
    fixture.open_connection();
    fixture.opener.refuses_switch = true;
    var writer = Writer.init(&fixture.datagram);
    try write_versioned(&writer, .v2, .initial, 0);
    fixture.start(writer.written().len);
    try expect_dropped(try next());
    try testing.expectEqual(Version.v1, fixture.test_connection.versions.negotiated);
    // RFC 9368 §4: a client that listed version 1 alone never takes the server to another.
    fixture.open_connection();
    fixture.test_connection.local_parameters.version_information = .of(0x0000_0001, &.{0x0000_0001});
    fixture.start(writer.written().len);
    try expect_dropped(try next());
    try testing.expectEqual(null, fixture.opener.switched);
    try testing.expectEqual(0, fixture.opener.opened);
}
