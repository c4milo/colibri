//! The frame layer's tests (RFC 9000 §19), kept out of `frame.zig` and its three pieces so each
//! stays inside the 500-line limit. What they check is three things: every type round-trips
//! through the writer and the reader, every rule §19 states as a FRAME_ENCODING_ERROR refuses
//! the frame it names, and a frame cut anywhere is a truncation that consumes nothing.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");
const frame = @import("frame.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Frame = frame.Frame;
const testing = std.testing;

/// Where a test writes a frame before reading it back, and how much room it has: past the
/// longest frame these cases produce, which is a NEW_CONNECTION_ID with a 20-octet connection
/// ID. Test-only.
const buffer_len = 512;
var buffer: [buffer_len]u8 = @splat(0);

/// The values the round-trip cases carry. Test-only.
const token = "a token the server issued";
const reason = "because the peer said so";
const path_data = "\x01\x02\x03\x04\x05\x06\x07\x08".*;
const reset_token = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f".*;
const connection_id = "\xaa\xbb\xcc\xdd";
const stream_data = "stream octets";

/// The ranges of an ACK frame that acknowledges 100..100, 90..95 and 80..85. Written as the wire
/// carries them: a gap and a length per range, descending. Test-only.
const ack_range_octets = "\x03\x05\x03\x05";

/// The ACK frame the cases use: largest acknowledged 100, then two more ranges. Test-only.
const ack_largest = 100;
const ack_delay = 1234;
const ack_range_count = 2;
const ack_ect_0 = 3;
const ack_ect_1 = 0;
const ack_ecn_ce = 9;
const ack_ecn: frame.EcnCounts = .{ .ect_0 = ack_ect_0, .ect_1 = ack_ect_1, .ecn_ce = ack_ecn_ce };

fn ack_frame(ecn: ?frame.EcnCounts) Frame {
    return .{ .ack = .{
        .ranges = .{
            .largest_acknowledged = ack_largest,
            .first_range = 0,
            .octets = ack_range_octets,
            .count = ack_range_count,
        },
        .delay = ack_delay,
        .ecn = ecn,
    } };
}

/// Writes `value`, reads it back, and requires the octets and the frame to match. Test-only.
fn round_trip(value: Frame) !Frame {
    var writer = Writer.init(&buffer);
    try frame.write(&writer, value);
    const octets = writer.written();
    try testing.expect(octets.len > 0);
    var reader = Reader.init(octets);
    const read_back = try frame.read(&reader);
    // Every octet of the frame was consumed, and no more.
    try testing.expectEqual(octets.len, reader.offset);
    try testing.expectEqual(std.meta.activeTag(value), std.meta.activeTag(read_back));
    return read_back;
}

test "§19: every frame type is written and read back as itself" {
    const cases = [_]Frame{
        .{ .padding = .{ .len = 7 } },
        .ping,
        ack_frame(null),
        ack_frame(ack_ecn),
        .{ .reset_stream = .{ .stream_id = 4, .error_code = 0x1234, .final_size = 9000 } },
        .{ .stop_sending = .{ .stream_id = 8, .error_code = 7 } },
        .{ .crypto = .{ .offset = 4096, .data = stream_data } },
        .{ .new_token = .{ .token = token } },
        .{ .stream = .{ .stream_id = 3, .offset = 0, .data = stream_data, .fin = false, .has_length = true } },
        .{ .stream = .{ .stream_id = 3, .offset = 1 << 40, .data = stream_data, .fin = true, .has_length = true } },
        .{ .max_data = .{ .maximum = 1 << 30 } },
        .{ .max_stream_data = .{ .stream_id = 12, .maximum = 65_535 } },
        .{ .max_streams = .{ .directionality = .bidirectional, .maximum = 100 } },
        .{ .max_streams = .{ .directionality = .unidirectional, .maximum = constants.max_streams_max } },
        .{ .data_blocked = .{ .limit = 1 << 20 } },
        .{ .stream_data_blocked = .{ .stream_id = 16, .limit = 4096 } },
        .{ .streams_blocked = .{ .directionality = .unidirectional, .limit = 3 } },
        .{ .new_connection_id = .{
            .sequence_number = 7,
            .retire_prior_to = 3,
            .connection_id = connection_id,
            .stateless_reset_token = &reset_token,
        } },
        .{ .retire_connection_id = .{ .sequence_number = 5 } },
        .{ .path_challenge = .{ .data = &path_data } },
        .{ .path_response = .{ .data = &path_data } },
        .{ .connection_close = .{
            .layer = .transport,
            .error_code = frame.frame_encoding_error,
            .frame_type = constants.frame_stream_first,
            .reason = reason,
        } },
        .{ .connection_close = .{
            .layer = .application,
            .error_code = 0x1000,
            .frame_type = null,
            .reason = "",
        } },
        .handshake_done,
    };
    for (cases) |value| {
        const read_back = try round_trip(value);
        switch (value) {
            // The unions holding a slice or a pointer are compared field by field below.
            .ack, .crypto, .new_token, .stream, .path_challenge, .path_response, .new_connection_id, .connection_close => {},
            else => try testing.expectEqual(value, read_back),
        }
    }
}

test "§19.3: an ACK frame's ranges, delay and ECN counts survive the round trip" {
    const read_back = (try round_trip(ack_frame(ack_ecn))).ack;
    try testing.expectEqual(100, read_back.ranges.largest_acknowledged);
    try testing.expectEqual(1234, read_back.delay);
    try testing.expectEqual(ack_ecn, read_back.ecn.?);
    // RFC 9000 §19.3.1: the ranges descend, and the walk gives the same ones every time.
    for (0..2) |_| {
        var walk = read_back.ranges.iterator();
        try testing.expectEqual(frame.frame_ack.Range{ .smallest = 100, .largest = 100 }, walk.next().?);
        try testing.expectEqual(frame.frame_ack.Range{ .smallest = 90, .largest = 95 }, walk.next().?);
        try testing.expectEqual(frame.frame_ack.Range{ .smallest = 80, .largest = 85 }, walk.next().?);
        try testing.expectEqual(null, walk.next());
    }
    try testing.expectEqual(80, read_back.ranges.smallest_acknowledged());
    // An ACK frame without the counts is type 0x02 and reports none.
    const plain = (try round_trip(ack_frame(null))).ack;
    try testing.expectEqual(null, plain.ecn);
    var writer = Writer.init(&buffer);
    try frame.write(&writer, ack_frame(null));
    try testing.expectEqual(constants.frame_ack, writer.written()[0]);
}

test "§19.3.1: a range that would put a packet number below zero is refused" {
    // The first range reaches one packet below the largest acknowledged, which is 0.
    try testing.expectError(error.AckRangeBelowZero, read_octets("\x02\x00\x00\x00\x01"));
    // A gap that reaches below zero after the first range: largest 3, first range 0, gap 2.
    try testing.expectError(error.AckRangeBelowZero, read_octets("\x02\x03\x00\x01\x00\x02\x00"));
    // A range length that reaches below zero: largest 4, first 0, gap 0, length 3.
    try testing.expectError(error.AckRangeBelowZero, read_octets("\x02\x04\x00\x01\x00\x00\x03"));
    // The same shapes one packet higher are read.
    _ = try read_octets("\x02\x01\x00\x00\x01");
    _ = try read_octets("\x02\x04\x00\x01\x00\x02\x00");
    _ = try read_octets("\x02\x05\x00\x01\x00\x00\x03");
}

test "§19.3: a range count past the octets present is a truncation, not a long walk" {
    // A count of 2^62-1 with no ranges after it.
    try testing.expectError(error.Truncated, read_octets("\x02\x10\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00"));
}

test "§19.8: the three flags of a STREAM type say what the frame carries" {
    var writer = Writer.init(&buffer);
    const with_offset: Frame = .{ .stream = .{
        .stream_id = 3,
        .offset = 64,
        .data = stream_data,
        .fin = true,
        .has_length = true,
    } };
    try frame.write(&writer, with_offset);
    // RFC 9000 §19.8: OFF, LEN and FIN are all set.
    const flags = constants.stream_flag_off | constants.stream_flag_len | constants.stream_flag_fin;
    try testing.expectEqual(constants.frame_stream_first | flags, writer.written()[0]);
    const read_back = (try round_trip(with_offset)).stream;
    try testing.expectEqual(64, read_back.offset);
    try testing.expect(read_back.fin and read_back.has_length);
    try testing.expectEqualStrings(stream_data, read_back.data);

    // Without a Length the data runs to the end of the packet, so the frame is the last one.
    var reader = Reader.init("\x08\x03" ++ stream_data);
    const to_end = (try frame.read(&reader)).stream;
    try testing.expectEqualStrings(stream_data, to_end.data);
    try testing.expectEqual(0, to_end.offset);
    try testing.expect(!to_end.has_length and !to_end.fin);
    try testing.expectEqual(0, reader.remaining_len());
}

test "§19.8, §19.6: an offset and length past 2^62-1 together are refused" {
    // RFC 9000 §16: 2^62-1 in eight octets is every bit set, and 2^62-2 is one less.
    const offset_max = "\xff\xff\xff\xff\xff\xff\xff\xff";
    const offset_one_below = "\xff\xff\xff\xff\xff\xff\xff\xfe";
    // Offset 2^62-2 with one octet of data reaches 2^62-1, which is the largest permitted.
    _ = try read_octets("\x0e\x03" ++ offset_one_below ++ "\x01" ++ "x");
    try testing.expectError(error.StreamOffsetTooLarge, read_octets("\x0e\x03" ++ offset_max ++ "\x01" ++ "x"));
    // A CRYPTO frame shares the rule.
    try testing.expectError(error.StreamOffsetTooLarge, read_octets("\x06" ++ offset_max ++ "\x01" ++ "x"));
    _ = try read_octets("\x06" ++ offset_one_below ++ "\x01" ++ "x");
}

test "§19.1: a run of PADDING is one frame, and one octet of it is too" {
    var reader = Reader.init("\x00\x00\x00\x00\x01");
    const padding = (try frame.read(&reader)).padding;
    try testing.expectEqual(4, padding.len);
    // The PING after the run is the next frame.
    try testing.expectEqual(Frame.ping, try frame.read(&reader));
    try testing.expectEqual(0, reader.remaining_len());
    var one = Reader.init("\x00");
    try testing.expectEqual(1, (try frame.read(&one)).padding.len);
}

test "§19.7: a NEW_TOKEN frame with an empty token is refused" {
    try testing.expectError(error.TokenEmpty, read_octets("\x07\x00"));
    const read_back = (try round_trip(.{ .new_token = .{ .token = token } })).new_token;
    try testing.expectEqualStrings(token, read_back.token);
}

test "§19.11, §19.14: a stream limit above 2^60 is refused" {
    var writer = Writer.init(&buffer);
    try frame.write_type(&writer, constants.frame_max_streams_bidirectional);
    try wire.varint.encode(&writer, constants.max_streams_max + 1);
    try testing.expectError(error.StreamLimitTooLarge, read_octets(writer.written()));
    // STREAMS_BLOCKED carries the same rule.
    var blocked = Writer.init(&buffer);
    try frame.write_type(&blocked, constants.frame_streams_blocked_unidirectional);
    try wire.varint.encode(&blocked, constants.max_streams_max + 1);
    try testing.expectError(error.StreamLimitTooLarge, read_octets(blocked.written()));
}

test "§19.15: a NEW_CONNECTION_ID's length and Retire Prior To are checked" {
    const value: Frame = .{ .new_connection_id = .{
        .sequence_number = 7,
        .retire_prior_to = 3,
        .connection_id = connection_id,
        .stateless_reset_token = &reset_token,
    } };
    const read_back = (try round_trip(value)).new_connection_id;
    try testing.expectEqualSlices(u8, connection_id, read_back.connection_id);
    try testing.expectEqualSlices(u8, &reset_token, read_back.stateless_reset_token);
    // RFC 9000 §19.15: Retire Prior To above the Sequence Number is refused, and equal is read.
    try testing.expectError(error.RetirePriorToTooLarge, read_octets("\x18\x03\x04\x01\xaa" ++ reset_token));
    _ = try read_octets("\x18\x03\x03\x01\xaa" ++ reset_token);
    // A length of 0 or of 21 is refused; 1 and 20 are the extremes admitted.
    try testing.expectError(error.ConnectionIdLengthInvalid, read_octets("\x18\x01\x00\x00" ++ reset_token));
    const twenty_one = "\x18\x01\x00\x15" ++ ("\xcc" ** 21) ++ reset_token;
    try testing.expectError(error.ConnectionIdLengthInvalid, read_octets(twenty_one));
    _ = try read_octets("\x18\x01\x00\x14" ++ ("\xcc" ** 20) ++ reset_token);
}

test "§19.19: a transport close carries the frame type and an application close does not" {
    const transport: Frame = .{ .connection_close = .{
        .layer = .transport,
        .error_code = frame.frame_encoding_error,
        .frame_type = constants.frame_stream_first,
        .reason = reason,
    } };
    const read_transport = (try round_trip(transport)).connection_close;
    try testing.expectEqual(constants.frame_stream_first, read_transport.frame_type.?);
    try testing.expectEqualStrings(reason, read_transport.reason);

    const application: Frame = .{ .connection_close = .{
        .layer = .application,
        .error_code = 0x1000,
        .frame_type = null,
        .reason = "",
    } };
    const read_application = (try round_trip(application)).connection_close;
    try testing.expectEqual(null, read_application.frame_type);
    // RFC 9000 §19.19: the reason phrase may be zero length.
    try testing.expectEqual(0, read_application.reason.len);
}

test "§12.4: a frame of unknown type is refused, and every defined type is not" {
    for ([_]u64{ 0x1f, 0x20, 0x30, 0xff, 1 << 30 }) |unknown| {
        var writer = Writer.init(&buffer);
        try wire.varint.encode(&writer, unknown);
        try testing.expectError(error.TypeUnknown, read_octets(writer.written()));
    }
    // The last defined type is 0x1e, and the first unknown one is 0x1f.
    _ = try read_octets("\x1e");
}

test "§19: a frame cut anywhere is a truncation and consumes nothing" {
    const cases = [_]Frame{
        .{ .padding = .{ .len = 7 } },
        .ping,
        ack_frame(null),
        ack_frame(ack_ecn),
        .{ .reset_stream = .{ .stream_id = 4, .error_code = 0x1234, .final_size = 9000 } },
        .{ .stop_sending = .{ .stream_id = 8, .error_code = 7 } },
        .{ .crypto = .{ .offset = 4096, .data = stream_data } },
        .{ .new_token = .{ .token = token } },
        .{ .stream = .{ .stream_id = 3, .offset = 0, .data = stream_data, .fin = false, .has_length = true } },
        .{ .stream = .{ .stream_id = 3, .offset = 1 << 40, .data = stream_data, .fin = true, .has_length = true } },
        .{ .max_data = .{ .maximum = 1 << 30 } },
        .{ .max_stream_data = .{ .stream_id = 12, .maximum = 65_535 } },
        .{ .max_streams = .{ .directionality = .bidirectional, .maximum = 100 } },
        .{ .max_streams = .{ .directionality = .unidirectional, .maximum = constants.max_streams_max } },
        .{ .data_blocked = .{ .limit = 1 << 20 } },
        .{ .stream_data_blocked = .{ .stream_id = 16, .limit = 4096 } },
        .{ .streams_blocked = .{ .directionality = .unidirectional, .limit = 3 } },
        .{ .new_connection_id = .{
            .sequence_number = 7,
            .retire_prior_to = 3,
            .connection_id = connection_id,
            .stateless_reset_token = &reset_token,
        } },
        .{ .retire_connection_id = .{ .sequence_number = 5 } },
        .{ .path_challenge = .{ .data = &path_data } },
        .{ .path_response = .{ .data = &path_data } },
        .{ .connection_close = .{
            .layer = .transport,
            .error_code = frame.frame_encoding_error,
            .frame_type = constants.frame_stream_first,
            .reason = reason,
        } },
        .{ .connection_close = .{
            .layer = .application,
            .error_code = 0x1000,
            .frame_type = null,
            .reason = "",
        } },
        .handshake_done,
    };
    for (cases) |value| {
        var writer = Writer.init(&buffer);
        try frame.write(&writer, value);
        const whole = writer.written().len;
        // A PADDING run and a STREAM frame without a Length are complete at any length, because
        // both read to the end of what they are given.
        const runs_to_end = switch (value) {
            .padding => true,
            .stream => |stream| !stream.has_length,
            else => false,
        };
        if (runs_to_end) continue;
        for (1..whole) |cut| {
            var reader = Reader.init(buffer[0..cut]);
            try testing.expectError(error.Truncated, frame.read(&reader));
            try testing.expectEqual(0, reader.offset);
        }
    }
}

test "§13.2.1: ACK, PADDING and CONNECTION_CLOSE elicit no acknowledgment, and the rest do" {
    try testing.expect(!ack_frame(null).is_ack_eliciting());
    try testing.expect(!(Frame{ .padding = .{ .len = 1 } }).is_ack_eliciting());
    const close: Frame = .{ .connection_close = .{
        .layer = .application,
        .error_code = 0,
        .frame_type = null,
        .reason = "",
    } };
    try testing.expect(!close.is_ack_eliciting());
    try testing.expect((Frame{ .ping = {} }).is_ack_eliciting());
    try testing.expect((Frame{ .handshake_done = {} }).is_ack_eliciting());
    try testing.expect((Frame{ .max_data = .{ .maximum = 1 } }).is_ack_eliciting());
}

test "every refusal closes the connection with FRAME_ENCODING_ERROR" {
    const failures = [_]frame.Error{
        error.Truncated,                 error.TypeUnknown,
        error.AckRangeBelowZero,         error.StreamOffsetTooLarge,
        error.TokenEmpty,                error.StreamLimitTooLarge,
        error.ConnectionIdLengthInvalid, error.RetirePriorToTooLarge,
    };
    for (failures) |failure| {
        // RFC 9000 §20.1: FRAME_ENCODING_ERROR is 0x07.
        try testing.expectEqual(0x07, frame.connection_error_code(failure));
    }
}

/// Reads one frame from `octets`, for the cases a writer cannot produce. Test-only.
fn read_octets(octets: []const u8) frame.Error!Frame {
    var reader = Reader.init(octets);
    return frame.read(&reader);
}

test "§19: a frame that does not fit the buffer writes nothing at all" {
    const cases = [_]Frame{
        .{ .padding = .{ .len = 7 } },
        ack_frame(ack_ecn),
        .{ .crypto = .{ .offset = 4096, .data = stream_data } },
        .{ .stream = .{ .stream_id = 3, .offset = 64, .data = stream_data, .fin = true, .has_length = true } },
        .{ .new_token = .{ .token = token } },
        .{ .new_connection_id = .{
            .sequence_number = 7,
            .retire_prior_to = 3,
            .connection_id = connection_id,
            .stateless_reset_token = &reset_token,
        } },
        .{ .connection_close = .{
            .layer = .transport,
            .error_code = frame.frame_encoding_error,
            .frame_type = constants.frame_stream_first,
            .reason = reason,
        } },
        .{ .max_stream_data = .{ .stream_id = 12, .maximum = 65_535 } },
        .{ .path_response = .{ .data = &path_data } },
    };
    for (cases) |value| {
        var whole = Writer.init(&buffer);
        try frame.write(&whole, value);
        const written = whole.written().len;
        for (0..written) |room| {
            var writer = Writer.init(buffer[0..room]);
            try testing.expectError(error.NoSpaceLeft, frame.write(&writer, value));
            // Nothing of a refused frame reaches the buffer, so the caller may write another.
            try testing.expectEqual(0, writer.written().len);
        }
    }
}

test "RFC 9000 §12.4 Table 3: the handshake levels admit five frames and no others" {
    // Table 3's Pkts column, read for the three levels decision 20 leaves. PADDING and PING are
    // IH01, ACK and CRYPTO are IH_1, and CONNECTION_CLOSE of type 0x1c is "ih".
    const admitted = [_]frame.Frame{
        .{ .padding = .{ .len = 1 } },
        .ping,
        ack_frame(null),
        .{ .crypto = .{ .offset = 0, .data = &.{} } },
        transport_close,
    };
    for (admitted) |held| {
        try testing.expect(held.permitted_at(.initial));
        try testing.expect(held.permitted_at(.handshake));
    }

    // Everything else is the application level's. §12.5: "all other frame types MUST only be
    // sent in the application data packet number space."
    const refused = [_]frame.Frame{
        application_close,
        .handshake_done,
        .{ .new_token = .{ .token = &.{} } },
        .{ .max_data = .{ .maximum = 0 } },
        .{ .reset_stream = .{ .stream_id = 0, .error_code = 0, .final_size = 0 } },
        .{ .stop_sending = .{ .stream_id = 0, .error_code = 0 } },
        .{ .max_stream_data = .{ .stream_id = 0, .maximum = 0 } },
        .{ .max_streams = .{ .directionality = .bidirectional, .maximum = 0 } },
        .{ .data_blocked = .{ .limit = 0 } },
        .{ .stream_data_blocked = .{ .stream_id = 0, .limit = 0 } },
        .{ .streams_blocked = .{ .directionality = .bidirectional, .limit = 0 } },
        .{ .retire_connection_id = .{ .sequence_number = 0 } },
        .{ .path_challenge = .{ .data = &path_data } },
        .{ .path_response = .{ .data = &path_data } },
    };
    for (refused) |held| {
        try testing.expect(!held.permitted_at(.initial));
        try testing.expect(!held.permitted_at(.handshake));
    }

    // "Note that all frames can appear in 1-RTT packets."
    for (admitted) |held| try testing.expect(held.permitted_at(.application));
    for (refused) |held| try testing.expect(held.permitted_at(.application));
}

test "RFC 9000 §12.5: a CONNECTION_CLOSE is admitted by its layer, not its frame type" {
    // The two share a name and differ by one bit, and only the transport one may appear below
    // the application level. Reading the type rather than the layer would admit both.
    try testing.expect(transport_close.permitted_at(.initial));
    try testing.expect(!application_close.permitted_at(.initial));
    try testing.expect(!application_close.permitted_at(.handshake));
}

/// A CONNECTION_CLOSE of each layer (RFC 9000 §19.19). The codes are not what these tests read;
/// §12.5 turns on the layer alone.
const transport_close: frame.Frame = .{ .connection_close = .{
    .layer = .transport,
    .error_code = 0,
    .frame_type = null,
    .reason = &.{},
} };
const application_close: frame.Frame = .{ .connection_close = .{
    .layer = .application,
    .error_code = 0,
    .frame_type = null,
    .reason = &.{},
} };
