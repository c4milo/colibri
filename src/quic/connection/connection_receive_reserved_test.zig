//! RFC 9000 §17.2 and §17.3.1's Reserved Bits as the receive walk meets them: checked once packet
//! and header protection are both removed, and never before.
//!
//! The fixture is `connection_receive_test.zig`'s, because these cases drive the same walk and
//! the same suite; split off it for length.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const header_write = @import("../packet/packet_header_write.zig");
const receive = @import("connection_receive.zig");
const fixture = @import("connection_receive_test.zig");

const testing = std.testing;
const Writer = core.Writer;

test "RFC 9000 §17.2: a long header whose Reserved Bits are set once opened is PROTOCOL_VIOLATION" {
    fixture.open_connection();
    var writer = Writer.init(&fixture.datagram);
    try fixture.write_packet(&writer, .handshake, &fixture.local_id, 0);
    fixture.start(writer.written().len);
    // A reserved bit of the long header that the short header does not reserve, so a check that
    // read the wrong form's mask would pass it.
    fixture.opener.revealed_bits = constants.long_reserved_bits & ~constants.short_reserved_bits;
    try testing.expectError(
        receive.Error.ReservedBitsSet,
        receive.next(&fixture.walk, &fixture.test_connection, fixture.opener.suite()),
    );
    // RFC 9000 §17.2: "a connection error of type PROTOCOL_VIOLATION", which §20.1 numbers 0x0a.
    try testing.expectEqual(
        error_code.protocol_violation,
        receive.connection_error_code(receive.Error.ReservedBitsSet),
    );
}

test "RFC 9000 §17.3.1: a short header whose Reserved Bits are set once opened is refused" {
    fixture.open_connection();
    var writer = Writer.init(&fixture.datagram);
    try header_write.write_short(&writer, .{
        .dcid = &fixture.local_id,
        .packet_number = .{ .value = 9, .len = 1 },
        .key_phase = false,
    });
    try writer.write_bytes(&fixture.test_payload);
    fixture.start(writer.written().len);
    // A reserved bit of the short header that the long header does not reserve.
    fixture.opener.revealed_bits = constants.short_reserved_bits & ~constants.long_reserved_bits;
    try testing.expectError(
        receive.Error.ReservedBitsSet,
        receive.next(&fixture.walk, &fixture.test_connection, fixture.opener.suite()),
    );
}
