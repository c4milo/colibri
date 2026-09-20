//! Version negotiation's tests (RFC 9000 §6, §17.2.1, RFC 8999 §6), kept out of
//! `connection_version.zig` so it stays inside the 500-line limit.
//!
//! What a server writes is checked by reading it back through `packet_header.read`, so the writer
//! and the reader agree about RFC 8999 §6's layout rather than each agreeing with itself.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const invariant = @import("../packet/invariant.zig");
const header = @import("../packet/packet_header.zig");
const connection_module = @import("connection.zig");
const transport_parameters = @import("../transport_parameters.zig");
const version = @import("connection_version.zig");

const Connection = connection_module.Connection;
const testing = std.testing;

/// A datagram long enough for RFC 9000 §5.2.2, and one octet short of it. Test-only.
var datagram: [constants.datagram_len_min]u8 = @splat(0);
/// Where a Version Negotiation packet is written. Test-only.
var output: [constants.datagram_len_min]u8 = @splat(0);
/// The connection the client tests drive. Test-only.
var test_connection: Connection = undefined;

/// The version colibri does not speak, which every unsupported-version test uses. Test-only.
const other_version: u32 = 0xfaceb00c;
/// A reserved version of RFC 9000 §15's 0x?a?a?a?a form. Test-only.
const reserved_version: u32 = 0x1a2a3a4a;

/// RFC 8999 §5: the Header Form bit, set in a long header. Test-only.
const header_form_bit: u8 = 0x80;
/// The connection-level data a test connection grants, which only has to be non-zero. Test-only.
const test_max_data: u64 = 1_048_576;

/// The connection IDs the client chose: C1 is its Source and S1 its Destination (§7.3), each one
/// octet repeated so no array literal is needed. Test-only.
const client_source_octet: u8 = 0xc1;
const client_destination_octet: u8 = 0x51;
const client_source_len = 4;
const client_destination_len = 8;
const client_source: [client_source_len]u8 = @splat(client_source_octet);
const client_destination: [client_destination_len]u8 = @splat(client_destination_octet);
/// A connection ID belonging to nobody in this test, and a Retry's Source (§17.2.5.2). Test-only.
const stranger_octet: u8 = 0xff;
const stranger: [client_source_len]u8 = @splat(stranger_octet);
const retry_source_octet: u8 = 0x52;
const retry_source: [client_source_len]u8 = @splat(retry_source_octet);
/// The longest connection ID a length octet carries, and one past version 1's (§17.2). Test-only.
const invariant_dcid_len = 255;
const invariant_scid_len = 21;

/// Fills `datagram` with a long header of `version` carrying the client's connection IDs, and
/// answers how many octets the header occupies. Test-only.
fn write_long(packet_version: u32, dcid: []const u8, scid: []const u8) usize {
    var writer = core.Writer.init(&datagram);
    // RFC 8999 §5.1: the Header Form bit is set, then the Version and both connection IDs.
    writer.write_byte(header_form_bit | constants.fixed_bit) catch unreachable;
    writer.write_int(u32, packet_version) catch unreachable;
    invariant.write_connection_id(&writer, dcid) catch unreachable;
    invariant.write_connection_id(&writer, scid) catch unreachable;
    return writer.written().len;
}

/// A client's connection that has sent its first Initial and received nothing. Test-only.
fn init_client() void {
    var parameters = transport_parameters.Parameters.initial();
    parameters.initial_max_data = test_max_data;
    test_connection.init(.{
        .role = .client,
        .local_parameters = parameters,
        .now_ns = 0,
        .identity = .{
            .local_initial_source = &client_source,
            .original_destination = &client_destination,
        },
    });
}

/// The Version Negotiation packet a server would send this client, with `supported` listed.
/// Test-only.
fn negotiation_of(dcid: []const u8, scid: []const u8, supported: []const u32) header.VersionNegotiation {
    var writer = core.Writer.init(&output);
    writer.write_byte(header_form_bit | constants.fixed_bit) catch unreachable;
    writer.write_int(u32, invariant.version_negotiation) catch unreachable;
    invariant.write_connection_id(&writer, dcid) catch unreachable;
    invariant.write_connection_id(&writer, scid) catch unreachable;
    for (supported) |one| writer.write_int(u32, one) catch unreachable;
    return (header.read(writer.written(), client_source.len) catch unreachable).version_negotiation;
}

/// The Version Negotiation packet addressed as this client's server would address it. Test-only.
fn addressed_negotiation(supported: []const u32) header.VersionNegotiation {
    // RFC 8999 §6: the reply's Destination Connection ID is the client's Source and its Source
    // Connection ID is the client's Destination.
    return negotiation_of(&client_source, &client_destination, supported);
}

test "RFC 9000 §5.2.2, §17.2.1: a server answers an unsupported version with the versions it speaks" {
    _ = write_long(other_version, &client_destination, &client_source);
    const answer = version.answer(.server, &datagram, &output);
    const written = answer.written;
    // §17.2.1: the packet is a whole datagram, and reads back as a Version Negotiation packet.
    const read_back = (try header.read(output[0..written], 0)).version_negotiation;
    try testing.expectEqual(1, read_back.supported.count());
    try testing.expectEqual(constants.version_1, read_back.supported.at(0));
    // RFC 8999 §6: the connection IDs are the received packet's, swapped.
    try testing.expectEqualSlices(u8, &client_source, read_back.dcid);
    try testing.expectEqualSlices(u8, &client_destination, read_back.scid);
    // §17.2.1: "servers SHOULD set the most significant bit of this field (0x40) to 1".
    try testing.expectEqual(constants.fixed_bit, output[0] & constants.fixed_bit);
    // The Version field is 0, which is what identifies the packet at all.
    try testing.expectEqual(0, std.mem.readInt(u32, output[1..5], .big));
    // Every octet the packet occupies was written and no more, which `version_negotiation_len`
    // said before the first one went down.
    const received = try invariant.read_long(&datagram);
    try testing.expectEqual(invariant.version_negotiation_len(received, 1), written);
}

test "RFC 9000 §5.2.2: a datagram below the minimum size is dropped rather than answered" {
    const header_len = write_long(other_version, &client_destination, &client_source);
    // "Servers MUST drop smaller packets that specify unsupported versions." §14.1 puts the size
    // at 1200 octets, so 1199 is dropped and 1200 is answered.
    const short = datagram[0 .. constants.datagram_len_min - 1];
    try testing.expectEqual(version.Silence.datagram_too_small, version.answer(.server, short, &output).none);
    try testing.expect(version.answer(.server, &datagram, &output) == .written);
    // A datagram no longer than its own header is short for the same reason, not another.
    const bare = datagram[0..header_len];
    try testing.expectEqual(version.Silence.datagram_too_small, version.answer(.server, bare, &output).none);
}

test "RFC 8999 §5.1: a datagram with no readable long header is answered with nothing" {
    const header_len = write_long(other_version, &client_destination, &client_source);
    // `answer` reads the datagram itself, so a header cut before its end says nothing about a
    // version and is not one to answer. Every cut short of the whole header reads the same way.
    for (0..header_len) |len| {
        try testing.expectEqual(version.Silence.unreadable, version.answer(.server, datagram[0..len], &output).none);
    }
    // The whole header is readable, and is then short for RFC 9000 §5.2.2's reason instead.
    try testing.expectEqual(
        version.Silence.datagram_too_small,
        version.answer(.server, datagram[0..header_len], &output).none,
    );
}

test "RFC 9000 §6.1, §17.2.1, RFC 8999 §6: the four datagrams a server answers nothing with" {
    // §17.2.1: "It is only sent by servers."
    _ = write_long(other_version, &client_destination, &client_source);
    try testing.expectEqual(version.Silence.not_a_server, version.answer(.client, &datagram, &output).none);
    // A version the server speaks belongs to a connection instead.
    _ = write_long(constants.version_1, &client_destination, &client_source);
    try testing.expectEqual(version.Silence.version_supported, version.answer(.server, &datagram, &output).none);
    // RFC 9000 §6.1: "An endpoint MUST NOT send a Version Negotiation packet in response to
    // receiving a Version Negotiation packet."
    _ = write_long(invariant.version_negotiation, &client_destination, &client_source);
    try testing.expectEqual(
        version.Silence.is_version_negotiation,
        version.answer(.server, &datagram, &output).none,
    );
    // RFC 8999 §6: "Packets with a short header do not trigger version negotiation."
    _ = write_long(other_version, &client_destination, &client_source);
    datagram[0] &= ~header_form_bit;
    try testing.expectEqual(version.Silence.short_header, version.answer(.server, &datagram, &output).none);
}

test "RFC 9000 §17.2.1: no version 1 rule reaches the decision to send one" {
    // "Version-specific rules for the connection ID therefore MUST NOT influence a decision about
    // whether to send a Version Negotiation packet." Twenty-one octets is one past version 1's
    // maximum, and 255 is the most a length octet carries.
    const long_scid: [invariant_scid_len]u8 = @splat(client_source_octet);
    const long_dcid: [invariant_dcid_len]u8 = @splat(client_destination_octet);
    _ = write_long(other_version, &long_dcid, &long_scid);
    const written = version.answer(.server, &datagram, &output).written;
    const read_back = (try header.read(output[0..written], 0)).version_negotiation;
    try testing.expectEqualSlices(u8, &long_scid, read_back.dcid);
    try testing.expectEqualSlices(u8, &long_dcid, read_back.scid);
    // The same octets read as version 1 are refused for exactly the rule §17.2.1 holds off.
    _ = write_long(constants.version_1, &long_dcid, &long_scid);
    try testing.expectError(error.ConnectionIdTooLong, header.read(&datagram, 0));
}

test "RFC 9000 §6.2: a client abandons the attempt, once, and sends nothing" {
    init_client();
    try testing.expect(test_connection.termination.state == .active);
    const reaction = version.on_version_negotiation(&test_connection, addressed_negotiation(&.{other_version}));
    try testing.expectEqual(version.Reaction.abandon, reaction);
    // "abandon the current connection attempt": the connection is over and nothing is sent, as
    // RFC 9000 §10.1's idle timeout leaves it.
    try testing.expectEqual(.closed, test_connection.termination.state);
    try testing.expectEqual(.abandoned, test_connection.termination.reason.?);
    try testing.expectEqual(.send_nothing, test_connection.termination.permission());
    // §6.2: "including an earlier Version Negotiation packet" — the second is discarded.
    const again = version.on_version_negotiation(&test_connection, addressed_negotiation(&.{other_version}));
    try testing.expectEqual(version.Reaction.already_processed, again);
}

test "RFC 9000 §6.2: a packet listing the version the client selected is discarded" {
    init_client();
    // "A client MUST discard a Version Negotiation packet that lists the QUIC version selected by
    // the client", wherever in the list it sits.
    const listed = [_]u32{ other_version, reserved_version, constants.version_1 };
    try testing.expectEqual(
        version.Reaction.lists_selected_version,
        version.on_version_negotiation(&test_connection, addressed_negotiation(&listed)),
    );
    try testing.expectEqual(.active, test_connection.termination.state);
    // The same list without version 1 ends the attempt, so it is that entry that decided it.
    const unlisted = [_]u32{ other_version, reserved_version };
    try testing.expectEqual(
        version.Reaction.abandon,
        version.on_version_negotiation(&test_connection, addressed_negotiation(&unlisted)),
    );
}

test "RFC 9000 §6.2: a client that has processed a packet discards the Version Negotiation packet" {
    init_client();
    // "A client MUST discard any Version Negotiation packet if it has received and successfully
    // processed any other packet". A packet is processed once the caller records it in its space.
    _ = test_connection.spaces[@intFromEnum(core.Level.initial)].receive(0, 0, true, .not_ect);
    try testing.expectEqual(
        version.Reaction.already_processed,
        version.on_version_negotiation(&test_connection, addressed_negotiation(&.{other_version})),
    );
    try testing.expectEqual(.active, test_connection.termination.state);
    // RFC 9000 §17.2.5.2: a Retry carries no packet number, so no space holds it, and the Source
    // Connection ID it made the client address is what says it was processed.
    init_client();
    test_connection.identity.on_retry(&retry_source);
    try testing.expectEqual(
        version.Reaction.already_processed,
        version.on_version_negotiation(&test_connection, addressed_negotiation(&.{other_version})),
    );
}

test "RFC 9000 §5.2.1, §17.2.1: a packet that echoes neither connection ID is discarded" {
    init_client();
    // §5.2.1: the Destination Connection ID must be one this client selected, which is the
    // Source Connection ID it put in its Initial.
    try testing.expectEqual(
        version.Reaction.other_connection,
        version.on_version_negotiation(&test_connection, negotiation_of(&stranger, &client_destination, &.{other_version})),
    );
    // §17.2.1: the Source Connection ID is copied from what the client addressed, which is what
    // shows the sender observed the Initial.
    try testing.expectEqual(
        version.Reaction.not_an_echo,
        version.on_version_negotiation(&test_connection, negotiation_of(&client_source, &stranger, &.{other_version})),
    );
    try testing.expectEqual(.active, test_connection.termination.state);
}

test "RFC 9000 §17.2.1: a server receiving a Version Negotiation packet discards it" {
    var parameters = transport_parameters.Parameters.initial();
    parameters.initial_max_data = test_max_data;
    test_connection.init(.{
        .role = .server,
        .local_parameters = parameters,
        .now_ns = 0,
        .identity = .{
            .local_initial_source = &client_destination,
            .original_destination = &client_destination,
            .peer_initial_source = &client_source,
        },
    });
    // "It is only sent by servers", so one arriving at a server says nothing and changes nothing.
    try testing.expectEqual(
        version.Reaction.not_a_client,
        version.on_version_negotiation(&test_connection, addressed_negotiation(&.{other_version})),
    );
    try testing.expectEqual(.active, test_connection.termination.state);
}

test "RFC 9000 §6.1: colibri lists the one version it speaks" {
    try testing.expectEqual(1, version.supported_versions.len);
    try testing.expectEqual(constants.version_1, version.supported_versions[0]);
    try testing.expect(version.speaks(constants.version_1));
    try testing.expect(!version.speaks(other_version));
    // RFC 8999 §5.4 reserves 0 for version negotiation, so it is no version to speak.
    try testing.expect(!version.speaks(invariant.version_negotiation));
}
