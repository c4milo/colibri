//! The tests of `transport_parameters.zig` and `transport_parameters_read.zig`, split out because
//! a hand-written source file stays at or under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const transport_parameters = @import("transport_parameters.zig");
const transport_parameters_read = @import("transport_parameters_read.zig");

const testing = std.testing;
const Reader = core.Reader;
const Writer = core.Writer;
const Id = transport_parameters.Id;
const Parameters = transport_parameters.Parameters;
const ConnectionId = transport_parameters.ConnectionId;
const read = transport_parameters_read.read;

/// Octets one test's extension is built in. Larger than any set of parameters a test writes.
const test_buffer_len: usize = 512;
var test_buffer: [test_buffer_len]u8 = undefined;

/// Writes one parameter by hand, so a test can build octets `write` would assert against.
fn one(id: u64, body: []const u8) ![]const u8 {
    var writer = Writer.init(&test_buffer);
    try wire.varint.encode(&writer, id);
    try wire.varint.encode(&writer, body.len);
    try writer.write_bytes(body);
    return writer.written();
}

/// How many copies `twice` writes, which is what makes the second one a repeat.
const repeat_count: usize = 2;

/// The same parameter, twice over, for the repeat rule.
fn twice(id: u64, body: []const u8) ![]const u8 {
    var writer = Writer.init(&test_buffer);
    for (0..repeat_count) |_| {
        try wire.varint.encode(&writer, id);
        try wire.varint.encode(&writer, body.len);
        try writer.write_bytes(body);
    }
    return writer.written();
}

/// One parameter whose value is a variable-length integer.
fn integer(id: u64, value: u64) ![]const u8 {
    var body: [wire.constants.varint_len_max]u8 = undefined;
    var body_writer = Writer.init(&body);
    try wire.varint.encode(&body_writer, value);
    var writer = Writer.init(&test_buffer);
    try wire.varint.encode(&writer, id);
    try wire.varint.encode(&writer, body_writer.written().len);
    try writer.write_bytes(body_writer.written());
    return writer.written();
}

test "RFC 9000 §18.2: an extension that states nothing means every default, and four are not zero" {
    // The constants first, against the numbers RFC 9000 §18.2 states. Comparing a parsed value
    // with the constant alone would pass whatever the constant said.
    try testing.expectEqual(65527, transport_parameters.default_max_udp_payload_size);
    try testing.expectEqual(3, transport_parameters.default_ack_delay_exponent);
    try testing.expectEqual(25, transport_parameters.default_max_ack_delay_ms);
    try testing.expectEqual(2, transport_parameters.default_active_connection_id_limit);
    // And the bounds, likewise.
    try testing.expectEqual(1200, transport_parameters.max_udp_payload_size_min);
    try testing.expectEqual(20, transport_parameters.ack_delay_exponent_max);
    try testing.expectEqual(16384, transport_parameters.max_ack_delay_ms_max);
    try testing.expectEqual(2, transport_parameters.active_connection_id_limit_min);

    var reader = Reader.init(&.{});
    const parameters = try read(&reader, .server);
    try testing.expectEqual(transport_parameters.default_max_udp_payload_size, parameters.max_udp_payload_size);
    try testing.expectEqual(transport_parameters.default_ack_delay_exponent, parameters.ack_delay_exponent);
    try testing.expectEqual(transport_parameters.default_max_ack_delay_ms, parameters.max_ack_delay_ms);
    try testing.expectEqual(transport_parameters.default_active_connection_id_limit, parameters.active_connection_id_limit);
    // Everything else RFC 9000 §18.2 defaults to zero, or to absent.
    try testing.expectEqual(0, parameters.initial_max_data);
    try testing.expectEqual(0, parameters.max_idle_timeout_ms);
    try testing.expectEqual(null, parameters.initial_source_connection_id);
    try testing.expect(!parameters.disable_active_migration);
}

test "every parameter colibri writes reads back as the value it wrote" {
    var sent = Parameters.initial();
    sent.original_destination_connection_id = ConnectionId.of(&.{ 1, 2, 3, 4 });
    sent.initial_source_connection_id = ConnectionId.of(&.{ 5, 6 });
    sent.retry_source_connection_id = ConnectionId.of(&.{7});
    sent.stateless_reset_token = @splat(9);
    sent.max_idle_timeout_ms = 30_000;
    sent.max_udp_payload_size = 1500;
    sent.initial_max_data = 1 << 20;
    sent.initial_max_stream_data_bidi_local = 1 << 16;
    sent.initial_max_stream_data_bidi_remote = 1 << 17;
    sent.initial_max_stream_data_uni = 1 << 18;
    sent.initial_max_streams_bidi = 100;
    sent.initial_max_streams_uni = 3;
    sent.ack_delay_exponent = 10;
    sent.max_ack_delay_ms = 50;
    sent.disable_active_migration = true;
    sent.active_connection_id_limit = 4;

    var writer = Writer.init(&test_buffer);
    try transport_parameters.write(&writer, &sent, .server);
    var reader = Reader.init(writer.written());
    const got = try read(&reader, .server);

    try testing.expectEqualSlices(u8, sent.original_destination_connection_id.?.slice(), got.original_destination_connection_id.?.slice());
    try testing.expectEqualSlices(u8, sent.initial_source_connection_id.?.slice(), got.initial_source_connection_id.?.slice());
    try testing.expectEqualSlices(u8, sent.retry_source_connection_id.?.slice(), got.retry_source_connection_id.?.slice());
    try testing.expectEqualSlices(u8, &sent.stateless_reset_token.?, &got.stateless_reset_token.?);
    try testing.expectEqual(sent.max_idle_timeout_ms, got.max_idle_timeout_ms);
    try testing.expectEqual(sent.max_udp_payload_size, got.max_udp_payload_size);
    try testing.expectEqual(sent.initial_max_data, got.initial_max_data);
    try testing.expectEqual(sent.initial_max_stream_data_bidi_local, got.initial_max_stream_data_bidi_local);
    try testing.expectEqual(sent.initial_max_stream_data_bidi_remote, got.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(sent.initial_max_stream_data_uni, got.initial_max_stream_data_uni);
    try testing.expectEqual(sent.initial_max_streams_bidi, got.initial_max_streams_bidi);
    try testing.expectEqual(sent.initial_max_streams_uni, got.initial_max_streams_uni);
    try testing.expectEqual(sent.ack_delay_exponent, got.ack_delay_exponent);
    try testing.expectEqual(sent.max_ack_delay_ms, got.max_ack_delay_ms);
    try testing.expectEqual(sent.disable_active_migration, got.disable_active_migration);
    try testing.expectEqual(sent.active_connection_id_limit, got.active_connection_id_limit);
}

test "a value the writer leaves out is the default the reader supplies" {
    // Every value is its default, so `write` emits nothing at all and the reader still answers
    // the same set. That is the whole reason a default is not an absence.
    const sent = Parameters.initial();
    var writer = Writer.init(&test_buffer);
    try transport_parameters.write(&writer, &sent, .client);
    try testing.expectEqual(0, writer.written().len);
    var reader = Reader.init(writer.written());
    const got = try read(&reader, .client);
    try testing.expectEqual(sent.max_udp_payload_size, got.max_udp_payload_size);
    try testing.expectEqual(sent.ack_delay_exponent, got.ack_delay_exponent);
    try testing.expectEqual(sent.max_ack_delay_ms, got.max_ack_delay_ms);
    try testing.expectEqual(sent.active_connection_id_limit, got.active_connection_id_limit);
}

test "RFC 9000 §18.2: each bound stated as invalid refuses the value one past it" {
    const cases = [_]struct { id: Id, value: u64 }{
        // "Values below 1200 are invalid."
        .{ .id = .max_udp_payload_size, .value = transport_parameters.max_udp_payload_size_min - 1 },
        // "Values above 20 are invalid."
        .{ .id = .ack_delay_exponent, .value = transport_parameters.ack_delay_exponent_max + 1 },
        // "Values of 2^14 or greater are invalid."
        .{ .id = .max_ack_delay, .value = transport_parameters.max_ack_delay_ms_max },
        // "An endpoint that receives a value less than 2 MUST close the connection."
        .{ .id = .active_connection_id_limit, .value = transport_parameters.active_connection_id_limit_min - 1 },
        // RFC 9000 §4.6: a stream limit above 2^60 is invalid.
        .{ .id = .initial_max_streams_bidi, .value = constants.max_streams_max + 1 },
        .{ .id = .initial_max_streams_uni, .value = constants.max_streams_max + 1 },
    };
    for (cases) |case| {
        var reader = Reader.init(try integer(@intFromEnum(case.id), case.value));
        try testing.expectError(error.ParameterInvalid, read(&reader, .server));
    }
    // The value at each bound is admitted, so the refusal is the bound and not one short of it.
    const admitted = [_]struct { id: Id, value: u64 }{
        .{ .id = .max_udp_payload_size, .value = transport_parameters.max_udp_payload_size_min },
        .{ .id = .ack_delay_exponent, .value = transport_parameters.ack_delay_exponent_max },
        .{ .id = .max_ack_delay, .value = transport_parameters.max_ack_delay_ms_max - 1 },
        .{ .id = .active_connection_id_limit, .value = transport_parameters.active_connection_id_limit_min },
        .{ .id = .initial_max_streams_bidi, .value = constants.max_streams_max },
    };
    for (admitted) |case| {
        var reader = Reader.init(try integer(@intFromEnum(case.id), case.value));
        _ = try read(&reader, .server);
    }
}

test "RFC 9000 §7.4: the same parameter twice is refused" {
    var reader = Reader.init(try twice(@intFromEnum(Id.initial_max_data), &.{0}));
    try testing.expectError(error.ParameterRepeated, read(&reader, .server));
}

test "RFC 9000 §18.2: a client may not send a server-only parameter" {
    const server_only = [_]Id{
        .original_destination_connection_id,
        .preferred_address,
        .retry_source_connection_id,
        .stateless_reset_token,
    };
    for (server_only) |id| {
        var reader = Reader.init(try one(@intFromEnum(id), &.{}));
        try testing.expectError(error.ParameterServerOnly, read(&reader, .client));
    }
    // The same parameters from a server are read, not refused. A zero-length one is enough to
    // show the role is what decided, since the value itself is not what was wrong.
    var reader = Reader.init(try one(@intFromEnum(Id.preferred_address), &.{}));
    _ = try read(&reader, .server);
}

test "RFC 9000 §7.4.2 and §18.1: a parameter colibri does not know is read past" {
    // §18.1 reserves the identifiers 31*N+27 to exercise exactly this. N = 1 gives 58.
    const reserved: u64 = 31 * 1 + 27;
    var writer = Writer.init(&test_buffer);
    try wire.varint.encode(&writer, reserved);
    try wire.varint.encode(&writer, 3);
    try writer.write_bytes(&.{ 0xaa, 0xbb, 0xcc });
    try wire.varint.encode(&writer, @intFromEnum(Id.initial_max_data));
    try wire.varint.encode(&writer, 1);
    try writer.write_bytes(&.{42});
    var reader = Reader.init(writer.written());
    const parameters = try read(&reader, .server);
    // The unknown one changed nothing and the one after it was still read.
    try testing.expectEqual(42, parameters.initial_max_data);
}

test "a value that is not the shape its parameter defines is refused" {
    // RFC 9000 §18.2: a stateless reset token is a sequence of 16 bytes.
    var short = Reader.init(try one(@intFromEnum(Id.stateless_reset_token), &.{ 1, 2, 3 }));
    try testing.expectError(error.ParameterInvalid, read(&short, .server));
    // RFC 9000 §18.2: disable_active_migration is included with a zero-length value.
    var carried = Reader.init(try one(@intFromEnum(Id.disable_active_migration), &.{1}));
    try testing.expectError(error.ParameterInvalid, read(&carried, .server));
    // RFC 9000 §17.2: a version 1 connection ID is at most 20 octets.
    const too_long: [constants.connection_id_len_max + 1]u8 = @splat(7);
    var long = Reader.init(try one(@intFromEnum(Id.initial_source_connection_id), &too_long));
    try testing.expectError(error.ParameterInvalid, read(&long, .server));
    // RFC 9000 §18: the Length field is the length of the Value field, so an integer parameter
    // carrying octets past its integer states a value it does not define.
    var padded = Reader.init(try one(@intFromEnum(Id.initial_max_data), &.{ 0, 0 }));
    try testing.expectError(error.ParameterInvalid, read(&padded, .server));
}

test "octets that end inside a parameter are a value that cannot be read" {
    // A length longer than the octets that follow it.
    var writer = Writer.init(&test_buffer);
    try wire.varint.encode(&writer, @intFromEnum(Id.initial_max_data));
    try wire.varint.encode(&writer, 8);
    try writer.write_bytes(&.{ 1, 2 });
    var reader = Reader.init(writer.written());
    try testing.expectError(error.ParameterTruncated, read(&reader, .server));
    // An identifier with no length after it.
    var lone = Reader.init(&.{0x04});
    try testing.expectError(error.ParameterTruncated, read(&lone, .server));
}
