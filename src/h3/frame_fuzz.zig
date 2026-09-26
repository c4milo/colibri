//! The fuzz property of the h3 frame reader, and the sweep that runs it over every input of up to
//! two octets (decision 29, https://github.com/c4milo/colibri/issues/53). Every octet of a control
//! stream and a request stream is a peer's, so the header and the payload readers take hostile
//! input.
//!
//! The property reads a header and, when the payload is one colibri reads whole, the payload. It
//! checks that a short header consumes nothing, that a whole payload is never `Truncated`, and
//! that what is accepted keeps RFC 9114 §7's rules, which it reads again here without the reader's
//! helpers. A payload that was accepted is written again and must read back the same. Everything
//! in this file is test-only.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const frame = @import("frame.zig");
const frame_write = @import("frame_write.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Smith = std.testing.Smith;
const testing = std.testing;
const varint = wire.varint;

/// Most octets one fuzz input carries: a header and a SETTINGS payload of several pairs.
const fuzz_input_len_max = 64;

/// Where an accepted payload is written again. Room for a header of two 8-octet varints, and a
/// SETTINGS payload of three settings at 8 octets each for its identifier and its value.
const fuzz_written_len_max = 64;
var fuzz_written: [fuzz_written_len_max]u8 = @splat(0);

fn fuzz_frame(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const octets = input[0..smith.slice(&input)];
    var reader = Reader.init(octets);
    const header = frame.read_header(&reader) catch |failure| {
        // RFC 9114 §7.1: a header whose octets have not all arrived is read again once they
        // have, so nothing is consumed.
        try testing.expectEqual(error.Truncated, failure);
        try testing.expectEqual(0, reader.offset);
        return;
    };
    if (header.is_streamed() or header.length > reader.remaining_len()) return;
    const payload = reader.take(@intCast(header.length)) catch unreachable;
    const read = frame.read_payload(header.frame_type, payload) catch |failure| {
        // The payload is whole, so a short field in it is H3_FRAME_ERROR (RFC 9114 §7.1). A
        // `Truncated` here would have the caller wait for octets that are not coming.
        try testing.expect(failure != error.Truncated);
        return;
    };
    try expect_rules(header.frame_type, payload, read);
    try expect_round_trip(read);
}

/// The rules of RFC 9114 §7.2 that an accepted payload keeps.
fn expect_rules(frame_type: u64, payload: []const u8, read: frame.Payload) !void {
    try testing.expectEqual(frame_type, type_of(read));
    switch (read) {
        // §7.2.3, §7.2.6, §7.2.7: the payload is one integer and nothing after it.
        .cancel_push, .goaway, .max_push_id => |value| try expect_single(payload, value),
        .settings => |settings| try expect_settings(payload, settings),
        .push_promise => |promise| {
            var promise_reader = Reader.init(payload);
            try testing.expectEqual(promise.push_id, (try varint.decode(&promise_reader)).value);
            try testing.expectEqualSlices(u8, promise_reader.peek_rest(), promise.field_section);
        },
        // §9: an unknown type is none of the types §7.2 defines.
        .unknown => |unknown| for (defined_types) |defined| try testing.expect(unknown != defined),
    }
}

/// The frame type a payload holds, which must be the type its header named.
fn type_of(read: frame.Payload) u64 {
    return switch (read) {
        .cancel_push => constants.frame_cancel_push,
        .settings => constants.frame_settings,
        .goaway => constants.frame_goaway,
        .max_push_id => constants.frame_max_push_id,
        .push_promise => constants.frame_push_promise,
        .unknown => |unknown| unknown,
    };
}

/// The frame types RFC 9114 §7.2 defines.
const defined_types = [_]u64{
    constants.frame_data,        constants.frame_headers,      constants.frame_cancel_push,
    constants.frame_settings,    constants.frame_push_promise, constants.frame_goaway,
    constants.frame_max_push_id,
};

fn expect_single(payload: []const u8, value: u64) !void {
    var single_reader = Reader.init(payload);
    try testing.expectEqual(value, (try varint.decode(&single_reader)).value);
    try testing.expectEqual(0, single_reader.remaining_len());
}

/// Walks the pairs of a SETTINGS payload (RFC 9114 §7.2.4): no HTTP/2 identifier, no known
/// identifier twice, and the value read is the value of its pair.
fn expect_settings(payload: []const u8, settings: frame.Settings) !void {
    try testing.expectEqual(null, settings.reserved);
    var pairs = Reader.init(payload);
    var known_count: [known_settings.len]u8 = @splat(0);
    // Bounded: every pair takes at least two octets.
    for (0..payload.len / pair_len_min + 1) |_| {
        if (pairs.remaining_len() == 0) break;
        const identifier = (try varint.decode(&pairs)).value;
        const value = (try varint.decode(&pairs)).value;
        for (constants.setting_reserved_http2) |held| try testing.expect(identifier != held);
        for (known_settings, 0..) |known, index| {
            if (identifier != known) continue;
            known_count[index] += 1;
            try testing.expectEqual(@as(?u64, value), value_of(settings, known));
        }
    }
    try testing.expectEqual(0, pairs.remaining_len());
    for (known_count) |count| try testing.expect(count <= 1);
}

/// Fewest octets a SETTINGS pair takes: an identifier and a value of one octet each (RFC 9114
/// §7.2.4).
const pair_len_min = 2;

/// The settings RFC 9114 §7.2.4.1 and RFC 9204 §5 define, which colibri keeps.
const known_settings = [_]u64{
    constants.setting_max_field_section_size,
    constants.setting_qpack_max_table_capacity,
    constants.setting_qpack_blocked_streams,
};

fn value_of(settings: frame.Settings, identifier: u64) ?u64 {
    return switch (identifier) {
        constants.setting_max_field_section_size => settings.max_field_section_size,
        constants.setting_qpack_max_table_capacity => settings.qpack_max_table_capacity,
        constants.setting_qpack_blocked_streams => settings.qpack_blocked_streams,
        else => unreachable,
    };
}

/// Writes an accepted payload again and reads it back, which gives the same payload. An unknown
/// type is left out: colibri writes only the reserved ones, and never what it read.
fn expect_round_trip(read: frame.Payload) !void {
    var writer = Writer.init(&fuzz_written);
    switch (read) {
        .cancel_push, .goaway, .max_push_id => |value| try frame_write.write_single(&writer, type_of(read), value),
        .settings => |settings| try frame_write.write_settings(&writer, settings),
        .push_promise => |promise| {
            try frame_write.write_push_promise_header(&writer, promise.push_id, promise.field_section.len);
            try writer.write_bytes(promise.field_section);
        },
        .unknown => return,
    }
    var reader = Reader.init(writer.written());
    const header = try frame.read_header(&reader);
    try testing.expectEqual(reader.remaining_len(), header.length);
    const again = try frame.read_payload(header.frame_type, reader.peek_rest());
    try testing.expectEqualDeep(read, again);
}

test "fuzz: a frame the reader accepts keeps RFC 9114 §7's rules, and reads back the same" {
    try testing.fuzz({}, fuzz_frame, .{
        .corpus = &.{
            // SETTINGS with every known setting, one in a two-octet varint, and an unknown one.
            core.fuzz.input("\x04\x0a\x06\x41\x00\x01\x05\x07\x10\x40\x99\x01"),
            // SETTINGS with a known setting twice, and with an HTTP/2 identifier (§7.2.4.1).
            core.fuzz.input("\x04\x04\x06\x01\x06\x02"),
            core.fuzz.input("\x04\x02\x02\x01"),
            // SETTINGS with one known setting alone, and with a pair cut after its identifier.
            core.fuzz.input("\x04\x02\x07\x10"),
            core.fuzz.input("\x04\x01\x06"),
            // GOAWAY of one integer, then one with an octet after it (§7.1).
            core.fuzz.input("\x07\x01\x08"),
            core.fuzz.input("\x07\x02\x08\x00"),
            // MAX_PUSH_ID and CANCEL_PUSH in two-octet varints, and one with its integer cut short.
            core.fuzz.input("\x0d\x02\x41\x00"),
            core.fuzz.input("\x03\x02\x41\x00"),
            core.fuzz.input("\x03\x01\x41"),
            // PUSH_PROMISE with a field section, and a reserved type with a payload (§9).
            core.fuzz.input("\x05\x04\x04\x00\x00\xd1"),
            core.fuzz.input("\x21\x03abc"),
            // A header whose length is cut short.
            core.fuzz.input("\x04\x41"),
        },
    });
    try core.fuzz.sweep(fuzz_frame, null);
}
