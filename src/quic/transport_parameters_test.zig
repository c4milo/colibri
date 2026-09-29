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
const VersionInformation = transport_parameters.VersionInformation;
const read = transport_parameters_read.read;

/// RFC 9369 §3.1's version 2, and a reserved version of RFC 9000 §15's 0x?a?a?a?a form. Test-only.
const version_2: u32 = 0x6b33_43cf;
const reserved_version: u32 = 0x1a2a_3a4a;

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

test "RFC 9368 §3: Version Information is written as §3 lays it out and reads back the same" {
    // Identifier 0x11 (§10.1), a length of 8, then the Chosen Version and one Available Version,
    // four octets each in network byte order.
    var sent = Parameters.initial();
    sent.version_information = .of(constants.version_1, &.{version_2});
    var writer = Writer.init(&test_buffer);
    try transport_parameters.write(&writer, &sent, .server);
    try testing.expectEqualSlices(u8, "\x11\x08\x00\x00\x00\x01\x6b\x33\x43\xcf", writer.written());
    // A client lists its Chosen Version among the versions its first flight is compatible with,
    // and a server lists its Fully Deployed Versions, which need not include its Chosen Version
    // and may be none.
    const cases = [_]struct { sender: transport_parameters.Role, info: VersionInformation }{
        .{ .sender = .client, .info = .of(version_2, &.{ reserved_version, version_2, constants.version_1 }) },
        .{ .sender = .server, .info = .of(constants.version_1, &.{reserved_version}) },
        .{ .sender = .server, .info = .of(constants.version_1, &.{}) },
    };
    for (cases) |case| {
        sent.version_information = case.info;
        writer = Writer.init(&test_buffer);
        try transport_parameters.write(&writer, &sent, case.sender);
        var reader = Reader.init(writer.written());
        try testing.expectEqualDeep(case.info, (try read(&reader, case.sender)).version_information.?);
    }
}

test "RFC 9368 §4: Version Information that fails to parse is refused" {
    const refused = [_]struct { sender: transport_parameters.Role, body: []const u8 }{
        // "if it is too short or if its length is not divisible by four"
        .{ .sender = .server, .body = "" },
        .{ .sender = .server, .body = "\x00\x00\x00\x01\x00\x00" },
        // "a Chosen Version equal to zero, or any Available Version equal to zero"
        .{ .sender = .server, .body = "\x00\x00\x00\x00" },
        .{ .sender = .server, .body = "\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00" },
        // "If a server receives Version Information where the Chosen Version is not included in
        // Available Versions, it MUST treat it as a parsing failure."
        .{ .sender = .client, .body = "\x00\x00\x00\x01\x6b\x33\x43\xcf" },
        .{ .sender = .client, .body = "\x00\x00\x00\x01" },
    };
    for (refused) |case| {
        var reader = Reader.init(try one(@intFromEnum(Id.version_information), case.body));
        try testing.expectError(error.ParameterInvalid, read(&reader, case.sender));
    }
    // The last two from a server are read: §3 lets a server leave its Chosen Version out.
    for (refused[refused.len - 2 ..]) |case| {
        var reader = Reader.init(try one(@intFromEnum(Id.version_information), case.body));
        try testing.expectEqual(constants.version_1, (try read(&reader, .server)).version_information.?.chosen_version);
    }
    // RFC 9000 §7.4: the parameter twice is a connection error, as any other known one is.
    var repeated = Reader.init(try twice(@intFromEnum(Id.version_information), "\x00\x00\x00\x01"));
    try testing.expectError(error.ParameterRepeated, read(&repeated, .server));
}

test "RFC 9368 §4: a list longer than colibri keeps is checked whole, and still names its Chosen Version" {
    // One more version than colibri keeps, the client's Chosen Version last among them.
    const listed = constants.version_information_versions_max + 1;
    var body: [(listed + 1) * @sizeOf(u32)]u8 = undefined;
    var writer = Writer.init(&body);
    try writer.write_int(u32, version_2);
    for (0..listed - 1) |i| try writer.write_int(u32, reserved_version + @as(u32, @intCast(i)));
    try writer.write_int(u32, version_2);
    var reader = Reader.init(try one(@intFromEnum(Id.version_information), writer.written()));
    const info = (try read(&reader, .client)).version_information.?;
    // The first versions in order, and the Chosen Version in the last place kept.
    const kept = info.available_slice();
    try testing.expectEqual(constants.version_information_versions_max, kept.len);
    for (kept[0 .. kept.len - 1], 0..) |version, i| try testing.expectEqual(reserved_version + i, version);
    try testing.expectEqual(version_2, kept[kept.len - 1]);
    // The same list without the Chosen Version is refused, so the check read past what was kept.
    std.mem.writeInt(u32, body[body.len - @sizeOf(u32) ..][0..@sizeOf(u32)], reserved_version, .big);
    reader = Reader.init(try one(@intFromEnum(Id.version_information), &body));
    try testing.expectError(error.ParameterInvalid, read(&reader, .client));
}

/// Most octets one fuzz input carries: room for a few parameters and one connection ID.
const fuzz_input_len_max = 96;

/// Reads the input as a client's extension and as a server's. What is accepted keeps RFC 9000
/// §18.2's bounds, and written again it reads back the same.
fn fuzz_read(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const octets = input[0..smith.slice(&input)];
    for ([_]transport_parameters.Role{ .client, .server }) |sender| {
        var reader = Reader.init(octets);
        const parameters = read(&reader, sender) catch continue;
        try testing.expectEqual(octets.len, reader.offset);
        try expect_identifiers(octets, sender);
        try expect_bounds(&parameters);
        var writer = Writer.init(&test_buffer);
        try transport_parameters.write(&writer, &parameters, sender);
        var again = Reader.init(writer.written());
        try testing.expectEqualDeep(parameters, try read(&again, sender));
    }
}

/// The identifiers of RFC 9000 §18.2 and RFC 9368 §10.1, which `read` refuses to see twice (§7.4).
const known_id_max: u64 = @intFromEnum(Id.version_information);

/// The parameters RFC 9000 §18.2 gives a server alone.
const server_only_ids = [_]Id{ .original_destination_connection_id, .preferred_address, .retry_source_connection_id, .stateless_reset_token };

/// Fewest octets a parameter takes: an identifier and a length of one octet each (RFC 9000 §18).
const parameter_len_min = 2;

/// Walks an accepted extension (RFC 9000 §18): none of §18.2's identifiers twice (§7.4), and
/// from a client none that §18.2 gives a server alone.
fn expect_identifiers(octets: []const u8, sender: transport_parameters.Role) !void {
    var reader = Reader.init(octets);
    var seen: u32 = 0;
    // Bounded: every parameter takes at least two octets.
    for (0..octets.len / parameter_len_min + 1) |_| {
        if (reader.remaining_len() == 0) break;
        const id = (try wire.varint.decode(&reader)).value;
        try expect_shape(id, try reader.take(@intCast((try wire.varint.decode(&reader)).value)));
        if (sender == .client) {
            for (server_only_ids) |server_only| try testing.expect(id != @intFromEnum(server_only));
        }
        if (id > known_id_max) continue;
        const bit = @as(u32, 1) << @intCast(id);
        try testing.expect(seen & bit == 0);
        seen |= bit;
    }
    try testing.expectEqual(0, reader.remaining_len());
}

/// The shape RFC 9000 §18.2 gives each of its parameters' values: a token of 16 octets, an empty
/// value, a connection ID of at most 20 octets (§17.2), or one integer and nothing after it (§18).
fn expect_shape(id: u64, body: []const u8) !void {
    switch (id) {
        @intFromEnum(Id.stateless_reset_token) => try testing.expectEqual(transport_parameters.stateless_reset_token_len, body.len),
        @intFromEnum(Id.disable_active_migration) => try testing.expectEqual(0, body.len),
        @intFromEnum(Id.original_destination_connection_id),
        @intFromEnum(Id.initial_source_connection_id),
        @intFromEnum(Id.retry_source_connection_id),
        => try testing.expect(body.len <= constants.connection_id_len_max),
        @intFromEnum(Id.preferred_address) => {},
        @intFromEnum(Id.version_information) => try expect_versions(body),
        else => if (id <= known_id_max) {
            var integer_reader = Reader.init(body);
            _ = try wire.varint.decode(&integer_reader);
            try testing.expectEqual(0, integer_reader.remaining_len());
        },
    }
}

/// RFC 9368 §4's shape of Version Information: versions of four octets each, at least one, and
/// none of them zero.
fn expect_versions(body: []const u8) !void {
    try testing.expect(body.len >= @sizeOf(u32) and body.len % @sizeOf(u32) == 0);
    var reader = Reader.init(body);
    // Bounded by the octets: every turn takes four.
    while (reader.remaining_len() > 0) try testing.expect(try reader.read_int(u32) != 0);
}

/// The bounds RFC 9000 §18.2 states as values that are invalid, read again without `valid`.
fn expect_bounds(parameters: *const Parameters) !void {
    try testing.expect(parameters.max_udp_payload_size >= transport_parameters.max_udp_payload_size_min);
    try testing.expect(parameters.ack_delay_exponent <= transport_parameters.ack_delay_exponent_max);
    try testing.expect(parameters.max_ack_delay_ms < transport_parameters.max_ack_delay_ms_max);
    try testing.expect(parameters.active_connection_id_limit >= transport_parameters.active_connection_id_limit_min);
    try testing.expect(parameters.initial_max_streams_bidi <= constants.max_streams_max);
    try testing.expect(parameters.initial_max_streams_uni <= constants.max_streams_max);
}

test "fuzz: accepted transport parameters keep §18.2's bounds, and read back the same" {
    try testing.fuzz({}, fuzz_read, .{
        .corpus = &.{
            // max_udp_payload_size 1200 and 1199 (0x44b0, 0x44af), the least §18.2 admits and one
            // below it.
            core.fuzz.input("\x03\x02\x44\xb0"),
            core.fuzz.input("\x03\x02\x44\xaf"),
            // ack_delay_exponent 20 and 21; max_ack_delay 2^14 - 1 and 2^14.
            core.fuzz.input("\x0a\x01\x14"),
            core.fuzz.input("\x0a\x01\x15"),
            core.fuzz.input("\x0b\x02\x7f\xff"),
            core.fuzz.input("\x0b\x04\x80\x00\x40\x00"),
            // active_connection_id_limit 2 and 1.
            core.fuzz.input("\x0e\x01\x02"),
            core.fuzz.input("\x0e\x01\x01"),
            // initial_max_streams_bidi and _uni at 2^60, then one past it.
            core.fuzz.input("\x08\x08\xd0\x00\x00\x00\x00\x00\x00\x00"),
            core.fuzz.input("\x09\x08\xd0\x00\x00\x00\x00\x00\x00\x01"),
            // A connection ID of 20 octets and of 21, a stateless reset token of 16 and of 15.
            core.fuzz.input("\x0f\x14" ++ "\xaa" ** 20),
            core.fuzz.input("\x0f\x15" ++ "\xaa" ** 21),
            core.fuzz.input("\x02\x10" ++ "\x5a" ** 16),
            core.fuzz.input("\x02\x0f" ++ "\x5a" ** 15),
            // disable_active_migration empty and not, a preferred_address, and an unknown
            // parameter twice.
            core.fuzz.input("\x0c\x00"),
            core.fuzz.input("\x0c\x01\x00"),
            core.fuzz.input("\x0d\x01\x00"),
            core.fuzz.input("\x40\x99\x00\x40\x99\x00"),
            // initial_max_data twice, and one whose integer has an octet after it.
            core.fuzz.input("\x04\x01\x10\x04\x01\x10"),
            core.fuzz.input("\x04\x02\x10\x00"),
            // Version Information naming version 1 and listing it, listing nothing, listing a
            // zero, and ending two octets into a version (RFC 9368 §4).
            core.fuzz.input("\x11\x08\x00\x00\x00\x01\x00\x00\x00\x01"),
            core.fuzz.input("\x11\x04\x00\x00\x00\x01"),
            core.fuzz.input("\x11\x08\x00\x00\x00\x01\x00\x00\x00\x00"),
            core.fuzz.input("\x11\x06\x00\x00\x00\x01\x00\x00"),
        },
    });
    try core.fuzz.sweep(fuzz_read, null);
}
