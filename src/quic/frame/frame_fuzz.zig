//! The fuzz property of the QUIC frame reader, and the sweep that runs it over every input of up
//! to two octets (decision 29, https://github.com/c4milo/colibri/issues/53). A peer's frames reach
//! `frame.read` once packet protection is removed, so every octet of a payload is hostile.
//!
//! The property reads a payload frame by frame, as a connection does, and checks three things.
//! A refusal consumes nothing. A frame that is read keeps every rule the writer asserts, so no
//! frame a peer sends can halt colibri when it is written again. And a frame is written with the
//! type it was read from and reads back as the frame that was read. The rules are read again here, without the reader's helpers.
//! Everything in this file is test-only.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");
const frame = @import("frame.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Frame = frame.Frame;
const AckRange = frame.frame_ack.Range;
const Smith = std.testing.Smith;
const testing = std.testing;

/// Most octets one fuzz input carries: past the longest fixed frame, a NEW_CONNECTION_ID with a
/// 20-octet connection ID, with room for a second frame after it.
const fuzz_input_len_max = 128;

/// Where a frame that was read is written again. A frame is never longer written than read, but
/// for PADDING, which is written one octet per octet read, so the input's bound is enough.
var fuzz_written: [fuzz_input_len_max]u8 = @splat(0);

fn fuzz_payload(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const payload = input[0..smith.slice(&input)];
    var reader = Reader.init(payload);
    // Bounded: every frame that is read consumes at least its type's octet.
    for (0..fuzz_input_len_max + 1) |_| {
        if (reader.remaining_len() == 0) return;
        const at_frame = reader;
        const read = frame.read(&reader) catch {
            // A refused frame consumes nothing, so the connection closes on what it was given.
            try testing.expectEqual(at_frame.offset, reader.offset);
            return;
        };
        try testing.expect(reader.offset > at_frame.offset);
        try expect_writable(read);
        try expect_round_trip(read, try type_at(at_frame));
    }
    unreachable;
}

/// The rules the writer asserts, which the reader must have checked on the peer's behalf.
fn expect_writable(read: Frame) !void {
    switch (read) {
        .padding => |padding| try testing.expect(padding.len > 0),
        .ack => |ack| try expect_ranges(ack.ranges),
        // RFC 9000 §19.8, §19.6: the offset and the length together stay at or below 2^62-1.
        .stream => |stream| try testing.expect(stream.offset + stream.data.len <= constants.stream_offset_max),
        .crypto => |crypto| try testing.expect(crypto.offset + crypto.data.len <= constants.stream_offset_max),
        // RFC 9000 §19.7: a NEW_TOKEN's token is never empty.
        .new_token => |new_token| try testing.expect(new_token.token.len > 0),
        // RFC 9000 §19.11, §19.14: a stream limit is 2^60 at most.
        .max_streams => |max| try testing.expect(max.maximum <= constants.max_streams_max),
        .streams_blocked => |blocked| try testing.expect(blocked.limit <= constants.max_streams_max),
        .new_connection_id => |new| {
            // RFC 9000 §19.15: Retire Prior To is at most the Sequence Number, and a connection
            // ID is 1 to 20 octets.
            try testing.expect(new.retire_prior_to <= new.sequence_number);
            try testing.expect(new.connection_id.len >= constants.connection_id_len_min);
            try testing.expect(new.connection_id.len <= constants.connection_id_len_max);
        },
        // RFC 9000 §19.19: a transport close names a frame type and an application close does not.
        .connection_close => |close| try testing.expectEqual(close.layer == .transport, close.frame_type != null),
        else => {},
    }
}

/// Walks an ACK frame's ranges, which the iterator does without checking: each range is ordered,
/// and each lies at least one packet number below the last (RFC 9000 §19.3.1).
fn expect_ranges(ranges: frame.AckRanges) !void {
    var walk = ranges.iterator();
    var previous: ?AckRange = null;
    var walked: u64 = 0;
    // Bounded by the count the frame carries, which the octets it was read from bound.
    for (0..fuzz_input_len_max + 1) |_| {
        const range = walk.next() orelse break;
        try testing.expect(range.smallest <= range.largest);
        if (previous) |last| try testing.expect(range.largest + 1 < last.smallest);
        previous = range;
        walked += 1;
    }
    try testing.expectEqual(ranges.count + 1, walked);
}

/// Writes `read` again and reads it back, which gives the same frame and consumes every octet.
/// The type written is the type read, but for a STREAM frame at offset 0: RFC 9000 §19.8 lets
/// its Offset go unwritten, and the writer clears the OFF bit.
fn expect_round_trip(read: Frame, read_type: u64) !void {
    var writer = Writer.init(&fuzz_written);
    try frame.write(&writer, read);
    const offset_dropped = read == .stream and read.stream.offset == 0;
    const expected_type = if (offset_dropped) read_type & ~constants.stream_flag_off else read_type;
    try testing.expectEqual(expected_type, try type_at(Reader.init(writer.written())));
    var reader = Reader.init(writer.written());
    const again = try frame.read(&reader);
    try testing.expectEqual(writer.written().len, reader.offset);
    try testing.expectEqualDeep(read, again);
}

/// The type of the frame at the reader's cursor (RFC 9000 §12.4).
fn type_at(at_frame: Reader) !u64 {
    var type_reader = at_frame;
    return (try wire.varint.decode(&type_reader)).value;
}

test "fuzz: a frame the reader accepts is one the writer writes, and reads back the same" {
    try testing.fuzz({}, fuzz_payload, .{
        .corpus = &.{
            // PING, then a run of PADDING.
            core.fuzz.input("\x01\x00\x00\x00"),
            // ACK with ECN: largest 100, delay 5, two ranges below the first, then the counts.
            core.fuzz.input("\x03\x40\x64\x05\x02\x00\x03\x05\x03\x05\x01\x02\x03"),
            // ACK ranges at the edge of zero (RFC 9000 §19.3.1): a first range reaching 0, a gap
            // reaching 0, a length reaching 0, and each of the three one past it.
            core.fuzz.input("\x02\x01\x00\x00\x01"),
            core.fuzz.input("\x02\x01\x00\x00\x02"),
            core.fuzz.input("\x02\x05\x00\x01\x00\x03\x00"),
            core.fuzz.input("\x02\x05\x00\x01\x00\x04\x00"),
            core.fuzz.input("\x02\x05\x00\x01\x00\x00\x03"),
            core.fuzz.input("\x02\x05\x00\x01\x00\x00\x04"),
            // STREAM with every flag: stream 4, offset 7, three octets, and the stream ends.
            core.fuzz.input("\x0f\x04\x07\x03abc"),
            // STREAM with no Length, which runs to the end of the payload.
            core.fuzz.input("\x08\x00rest of the payload"),
            // STREAM and CRYPTO ending at 2^62-1 (RFC 9000 §19.8, §19.6), then each one past it.
            core.fuzz.input("\x0e\x00\xff\xff\xff\xff\xff\xff\xff\xfe\x01a"),
            core.fuzz.input("\x0e\x00\xff\xff\xff\xff\xff\xff\xff\xff\x01a"),
            core.fuzz.input("\x06\xff\xff\xff\xff\xff\xff\xff\xfe\x01a"),
            core.fuzz.input("\x06\xff\xff\xff\xff\xff\xff\xff\xff\x01a"),
            // NEW_CONNECTION_ID: sequence 2, retire below 2, a 4-octet ID, a 16-octet token; then
            // retire below 3, an empty ID and a 21-octet ID, which RFC 9000 §19.15 refuses.
            core.fuzz.input("\x18\x02\x02\x04\xaa\xbb\xcc\xdd" ++ "\x10" ** 16),
            core.fuzz.input("\x18\x02\x03\x04\xaa\xbb\xcc\xdd" ++ "\x10" ** 16),
            core.fuzz.input("\x18\x02\x00\x00" ++ "\x10" ** 16),
            core.fuzz.input("\x18\x02\x00\x15" ++ "\xaa" ** 21 ++ "\x10" ** 16),
            // A transport CONNECTION_CLOSE naming a STREAM frame, with a reason.
            core.fuzz.input("\x1c\x07\x08\x03bad"),
            // An application CONNECTION_CLOSE, then HANDSHAKE_DONE.
            core.fuzz.input("\x1d\x00\x00\x1e"),
            // MAX_STREAMS and STREAMS_BLOCKED at 2^60, the most RFC 9000 §19.11 and §19.14 admit,
            // then one past it.
            core.fuzz.input("\x13\xd0\x00\x00\x00\x00\x00\x00\x00\x12\xd0\x00\x00\x00\x00\x00\x00\x01"),
            core.fuzz.input("\x16\xd0\x00\x00\x00\x00\x00\x00\x00\x17\xd0\x00\x00\x00\x00\x00\x00\x01"),
            // PATH_CHALLENGE, then a NEW_TOKEN of one octet, then one of none (RFC 9000 §19.7).
            core.fuzz.input("\x1a\x01\x02\x03\x04\x05\x06\x07\x08\x07\x01t\x07\x00"),
        },
    });
    try core.fuzz.sweep(fuzz_payload, null);
}
