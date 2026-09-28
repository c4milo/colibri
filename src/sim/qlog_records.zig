//! The check that each qlog record a logged run takes reads back: one JSON text of a JSON text
//! sequence (RFC 7464 §2.2, RFC 8259), read with stdx's `TextReader` (decision 102 as amended),
//! that holds the members the drafts require of it. The QUIC checks and the h3 check pass
//! `Records.check` the records a log holds after each step, before they clear it.
//!
//! The members required are the ones the drafts' CDDL writes without a `?`: main schema §3 and §5
//! of the header, §7 of every event, and of the events colibri logs, quic-events §4.6, §5.5, §5.6,
//! §8.8 and §8.13, and h3-events §3.3, §3.5, §3.6 and §4.2.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");

const qlog = quic.qlog;
const TextReader = qlog.json.TextReader;
const Item = qlog.json.Item;
const Kind = qlog.json.Kind;
const quic_event = qlog.quic_event;
const h3_event = qlog.h3_event;

pub const Error = error{QlogRecordMalformed};

/// The members the check looks for, under the drafts' names. Any other name is `other`.
const Member = enum {
    file_schema,
    serialization_format,
    trace,
    event_schemas,
    time,
    name,
    data,
    header,
    packet_type,
    frames,
    frame,
    frame_type,
    new,
    stream_id,
    stream_type,
    other,
};

const Members = std.EnumSet(Member);

/// What the check keeps of one log from the records of one step to the next.
pub const Records = struct {
    /// Whether the log's first record, the QlogFileSeq header main schema §5 puts first, was read.
    header_read: bool = false,
    /// The time of the last event, in nanoseconds after the header's instant.
    time_ns: u64 = 0,
    /// Events read.
    events: u64 = 0,

    /// Reads each record of `octets`, which a log held, writing each name, string and number into
    /// `storage`, which must hold the longest of them.
    pub fn check(records: *Records, octets: []const u8, storage: []u8) Error!void {
        // stdx's scalar paths, as the simulator's writer takes: the items are the same for every
        // value (stdx's invariant 5).
        var reader = TextReader.init(octets, storage, .sequence, qlog.Features.none());
        // Bounded by the octets: each record takes more than one.
        for (0..octets.len + 1) |_| {
            if (!reader.next_text()) return;
            if (records.header_read) try records.read_event(&reader) else try records.read_header(&reader);
            const end = try next(&reader);
            // The decoder holds a text to one value (RFC 8259 §2), so the text ends with its object.
            assert(end == null);
        }
        unreachable;
    }

    /// Main schema §3 and §5: the header's file schema, serialization format and trace, whose
    /// event schemas §5.1 requires.
    fn read_header(records: *Records, reader: *TextReader) Error!void {
        try expect(reader, .begin_object);
        var found: Members = .initEmpty();
        // Bounded by the octets: each member takes more than one.
        for (0..reader.input.len) |_| {
            const member = try next_member(reader) orelse break;
            found.insert(member);
            if (member == .trace) try read_object_with(reader, .event_schemas) else try skip_value(reader);
        }
        if (!Members.initMany(&.{ .file_schema, .serialization_format, .trace }).subsetOf(found)) {
            return error.QlogRecordMalformed;
        }
        records.header_read = true;
    }

    /// Main schema §7: an event's time, name and data, with the members of `data` its name
    /// requires.
    fn read_event(records: *Records, reader: *TextReader) Error!void {
        try expect(reader, .begin_object);
        var found: Members = .initEmpty();
        var required: Members = .initEmpty();
        var data: Members = .initEmpty();
        // Bounded by the octets: each member takes more than one.
        for (0..reader.input.len) |_| {
            const member = try next_member(reader) orelse break;
            found.insert(member);
            switch (member) {
                .time => records.time_ns = try read_time(reader, records.time_ns),
                .name => required = required_of(try read_string(reader)),
                .data => data = try read_data(reader),
                else => try skip_value(reader),
            }
        }
        if (!Members.initMany(&.{ .time, .name, .data }).subsetOf(found)) return error.QlogRecordMalformed;
        if (!required.subsetOf(data)) return error.QlogRecordMalformed;
        records.events += 1;
    }
};

/// The members of `data` an event's CDDL writes without a `?`, for each event colibri logs that
/// has any.
fn required_of(event_name: []const u8) Members {
    const Required = struct { event_name: []const u8, members: []const Member };
    const table = [_]Required{
        // Quic-events §5.5 and §5.6.
        .{ .event_name = quic_event.name.packet_sent, .members = &.{.header} },
        .{ .event_name = quic_event.name.packet_received, .members = &.{.header} },
        // Quic-events §4.6.
        .{ .event_name = quic_event.name.connection_state_updated, .members = &.{.new} },
        // H3-events §3.3, §3.5 and §3.6.
        .{ .event_name = h3_event.name.stream_type_set, .members = &.{ .stream_id, .stream_type } },
        .{ .event_name = h3_event.name.frame_created, .members = &.{ .stream_id, .frame } },
        .{ .event_name = h3_event.name.frame_parsed, .members = &.{ .stream_id, .frame } },
    };
    // Bounded by the table.
    for (table) |entry| {
        if (std.mem.eql(u8, event_name, entry.event_name)) return .initMany(entry.members);
    }
    return .initEmpty();
}

/// Main schema §7.1: an event's time in milliseconds, which colibri writes with three digits of
/// fraction. §7.1 asks for strictly ascending times, and colibri logs several events at one
/// instant, so the check requires only that no event precede the one before it.
fn read_time(reader: *TextReader, previous_ns: u64) Error!u64 {
    const item = try next(reader) orelse return error.QlogRecordMalformed;
    const text = switch (item) {
        .number => |octets| octets,
        else => return error.QlogRecordMalformed,
    };
    var parts = std.mem.splitScalar(u8, text, '.');
    const integer = parts.first();
    const fraction = parts.next() orelse return error.QlogRecordMalformed;
    if (fraction.len != qlog.constants.millisecond_fraction_digits) return error.QlogRecordMalformed;
    const milliseconds = std.fmt.parseUnsigned(u64, integer, decimal_base) catch return error.QlogRecordMalformed;
    const microseconds = std.fmt.parseUnsigned(u64, fraction, decimal_base) catch return error.QlogRecordMalformed;
    const time_ns = milliseconds * qlog.constants.nanoseconds_per_millisecond +
        microseconds * qlog.constants.nanoseconds_per_microsecond;
    if (time_ns < previous_ns) return error.QlogRecordMalformed;
    return time_ns;
}

/// The base of the digits of a JSON number (RFC 8259 §6).
const decimal_base: u8 = 10;

/// An event's data, and the members it holds. A packet's header and each frame must hold their
/// type: quic-events §8.8 and §8.13, and h3-events §4.2.
fn read_data(reader: *TextReader) Error!Members {
    try expect(reader, .begin_object);
    var found: Members = .initEmpty();
    // Bounded by the octets: each member takes more than one.
    for (0..reader.input.len) |_| {
        const member = try next_member(reader) orelse return found;
        found.insert(member);
        switch (member) {
            .header => try read_object_with(reader, .packet_type),
            .frame => try read_object_with(reader, .frame_type),
            .frames => try read_frames(reader),
            else => try skip_value(reader),
        }
    }
    unreachable;
}

/// A packet's frames (quic-events §5.5), each an object with its `frame_type` (§8.13).
fn read_frames(reader: *TextReader) Error!void {
    try expect(reader, .begin_array);
    // Bounded by the octets: each frame takes more than one.
    for (0..reader.input.len) |_| {
        const item = try next(reader) orelse return error.QlogRecordMalformed;
        switch (item) {
            .end_array => return,
            .begin_object => try read_members_with(reader, .frame_type),
            else => return error.QlogRecordMalformed,
        }
    }
    unreachable;
}

/// An object that must hold `required`. Its other members are skipped.
fn read_object_with(reader: *TextReader, required: Member) Error!void {
    try expect(reader, .begin_object);
    try read_members_with(reader, required);
}

/// The members of an object already opened, which must include `required`.
fn read_members_with(reader: *TextReader, required: Member) Error!void {
    var found = false;
    // Bounded by the octets: each member takes more than one.
    for (0..reader.input.len) |_| {
        const member = try next_member(reader) orelse break;
        found = found or member == required;
        try skip_value(reader);
    }
    if (!found) return error.QlogRecordMalformed;
}

/// Reads past one value, whatever it holds.
fn skip_value(reader: *TextReader) Error!void {
    var depth: usize = 0;
    // Bounded by the octets: each item takes one at least.
    for (0..reader.input.len) |_| {
        const item = try next(reader) orelse return error.QlogRecordMalformed;
        switch (item) {
            .begin_object, .begin_array => depth += 1,
            // The decoder holds a text to RFC 8259's grammar, so no end comes before its start.
            .end_object, .end_array => depth -= 1,
            else => {},
        }
        if (depth == 0) return;
    }
    unreachable;
}

/// The next member's name of an object already opened, or null at the object's end.
fn next_member(reader: *TextReader) Error!?Member {
    const item = try next(reader) orelse return error.QlogRecordMalformed;
    return switch (item) {
        .end_object => null,
        .name => |octets| std.meta.stringToEnum(Member, octets) orelse .other,
        else => error.QlogRecordMalformed,
    };
}

fn read_string(reader: *TextReader) Error![]const u8 {
    const item = try next(reader) orelse return error.QlogRecordMalformed;
    return switch (item) {
        .string => |octets| octets,
        else => error.QlogRecordMalformed,
    };
}

fn expect(reader: *TextReader, kind: Kind) Error!void {
    const item = try next(reader) orelse return error.QlogRecordMalformed;
    if (std.meta.activeTag(item) != kind) return error.QlogRecordMalformed;
}

/// The next item, with the decoder's refusal of a text that is not JSON, or that the input cuts
/// short, reported as a malformed record.
fn next(reader: *TextReader) Error!?Item {
    return reader.next() catch error.QlogRecordMalformed;
}

const testing = std.testing;

/// Room for the records a test writes, and for the longest string of one. Test-only.
const test_log_len: usize = 2048;
const test_storage_len: usize = 256;

const test_schemas = [_][]const u8{ qlog.quic_event_schema, qlog.http3_event_schema };

/// A log started at instant 0, whose header the check reads first.
fn test_log(buffer: []u8) !qlog.Log {
    var log = qlog.Log.init(buffer, qlog.Features.none());
    try log.start(.{ .vantage_point = .client, .group_id = "odcid", .event_schemas = &test_schemas }, 0);
    return log;
}

/// Checks the header and then `records`, a test's own text.
fn check_after_header(records: []const u8) Error!Records {
    var buffer: [test_log_len]u8 = undefined;
    var log = test_log(&buffer) catch unreachable;
    var storage: [test_storage_len]u8 = undefined;
    var held: Records = .{};
    try held.check(log.bytes(), &storage);
    try held.check(records, &storage);
    return held;
}

test "a log's header and its events, as `qlog` writes them, read back" {
    var buffer: [test_log_len]u8 = undefined;
    var log = try test_log(&buffer);
    log.event(quic_event.name.connection_state_updated, 1_500_000, quic_event.ConnectionStateUpdated{ .new = .handshake_started });
    log.event(quic_event.name.packet_lost, 1_500_000, quic_event.PacketLost{ .header = .{ .packet_type = .initial, .packet_number = 0 } });
    log.event(h3_event.name.stream_type_set, 2_000_000, h3_event.StreamTypeSet{ .initiator = .local, .stream_id = 2, .stream_type = .control });
    var storage: [test_storage_len]u8 = undefined;
    var records: Records = .{};
    try records.check(log.bytes(), &storage);
    try testing.expectEqual(3, records.events);
    try testing.expectEqual(2_000_000, records.time_ns);
    // The next step's records go on from the last one.
    log.clear();
    log.event(quic_event.name.connection_state_updated, 2_000_000, quic_event.ConnectionStateUpdated{ .new = .handshake_complete });
    try records.check(log.bytes(), &storage);
    try testing.expectEqual(4, records.events);
}

test "a packet's frames and an h3 frame each hold their type" {
    const records = try check_after_header("\x1e{\"time\":0.001,\"name\":\"quic:packet_sent\",\"data\":{\"header\":" ++
        "{\"packet_type\":\"initial\"},\"frames\":[{\"frame_type\":\"ping\"},{\"frame_type\":\"padding\"}]}}\n" ++
        "\x1e{\"time\":0.002,\"name\":\"http3:frame_created\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"data\"}}}\n");
    try testing.expectEqual(2, records.events);
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"quic:packet_sent\"," ++
        "\"data\":{\"header\":{\"packet_type\":\"initial\"},\"frames\":[{\"frame_type\":\"ping\"},{\"length\":1}]}}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"http3:frame_parsed\"," ++
        "\"data\":{\"stream_id\":0,\"frame\":{\"length\":1}}}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"quic:packet_received\"," ++
        "\"data\":{\"header\":{\"packet_number\":1}}}\n"));
}

test "an event without a member its name requires is refused" {
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"quic:packet_sent\",\"data\":{}}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"quic:connection_state_updated\",\"data\":{\"old\":\"attempted\"}}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"http3:stream_type_set\",\"data\":{\"stream_id\":2}}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"quic:packet_lost\"}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"name\":\"quic:packet_lost\",\"data\":{}}\n"));
}

test "an event earlier than the one before it is refused" {
    _ = try check_after_header("\x1e{\"time\":2.500,\"name\":\"quic:packet_lost\",\"data\":{}}\n" ++
        "\x1e{\"time\":2.500,\"name\":\"quic:packet_lost\",\"data\":{}}\n");
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":2.500,\"name\":\"quic:packet_lost\",\"data\":{}}\n" ++
        "\x1e{\"time\":2.499,\"name\":\"quic:packet_lost\",\"data\":{}}\n"));
    // A time needs its three digits of fraction.
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":2,\"name\":\"quic:packet_lost\",\"data\":{}}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":2.5,\"name\":\"quic:packet_lost\",\"data\":{}}\n"));
}

test "a log that does not start with its header, or a record that is not JSON, is refused" {
    var storage: [test_storage_len]u8 = undefined;
    var records: Records = .{};
    try testing.expectError(error.QlogRecordMalformed, records.check("\x1e{\"time\":0.001,\"name\":\"quic:packet_lost\",\"data\":{}}\n", &storage));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e{\"time\":0.001,\"name\":\"quic:packet_lost\",\"data\":{}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("{\"time\":0.001,\"name\":\"quic:packet_lost\",\"data\":{}}\n"));
    try testing.expectError(error.QlogRecordMalformed, check_after_header("\x1e[]\n"));
}

test "a header without a member main schema §3 or §5 requires is refused" {
    var storage: [test_storage_len]u8 = undefined;
    var records: Records = .{};
    try records.check("\x1e{\"file_schema\":\"a\",\"serialization_format\":\"b\",\"trace\":{\"event_schemas\":[]}}\n", &storage);
    try testing.expect(records.header_read);
    records = .{};
    try testing.expectError(error.QlogRecordMalformed, records.check("\x1e{\"file_schema\":\"a\",\"serialization_format\":\"b\",\"trace\":{}}\n", &storage));
    records = .{};
    try testing.expectError(error.QlogRecordMalformed, records.check("\x1e{\"serialization_format\":\"b\",\"trace\":{\"event_schemas\":[]}}\n", &storage));
}
