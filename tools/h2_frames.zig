//! Runs the h2 frame vectors of http2jp/http2-frame-test-case against the h2 frame codec
//! (docs/design.md §8 step 4, decision 25).
//!
//! Run:   zig build h2-frames
//! Check: zig build test              # runs the same step
//! Test:  zig build test-tools
//!
//! Usage: h2_frames <http2-frame-test-case directory>
//!
//! Each JSON file under the directory's subdirectories is one case: a hex `wire`, and either a
//! `frame` naming the header fields and the payload fields the codec must produce, or an `error`
//! list of codes, one of which the codec must attach. For each case the tool reads the header
//! with `frame.read_header` and the rest with `frame.parse`. A wire whose Length is above
//! `frame_size_max`, or that has fewer octets than its Length promises, is refused by the tool
//! itself with FRAME_SIZE_ERROR, the way a connection refuses such a frame before parsing it
//! (RFC 9113 §4.2). Every other refusal is `frame.verdict` on the parse error.
//!
//! A normal case is also written back with the codec's writer and parsed again, and the fields
//! must be equal. When the case carries no padding the octets must be the same too; a padded
//! case's octets differ, because the corpus's padding octets are not zero and colibri writes zeros
//! (RFC 9113 §6.1).
//!
//! This tool is developer tooling: it allocates and reads the filesystem, which the library never
//! does. The JSON never reaches `src/`.
//!
//! Exit status: 0 when every case passed, 1 on the first failure, 2 on a usage error.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const assert = std.debug.assert;
const h2 = @import("h2");

const frame = h2.frame;
const constants = h2.constants;
const Reader = h2.core.Reader;
const Writer = h2.core.Writer;
const Value = std.json.Value;
const ObjectMap = std.json.ObjectMap;

/// The largest case file the tool reads.
const case_bytes_max = 1 << 20;

/// The longest wire a case holds, in octets, and the longest frame the tool writes back: the
/// header and the largest payload colibri accepts.
const wire_len_max = constants.frame_header_len + constants.frame_size_max;

const exit_failure: u8 = 1;
const exit_usage: u8 = 2;

const Failure = error{
    /// The JSON does not have the shape the README gives.
    CaseMalformed,
    /// A normal case was refused.
    Refused,
    /// A field the case lists differs from what the codec produced.
    FieldDiffers,
    /// An error case parsed.
    ErrorExpected,
    /// An error case was refused with a code the case does not list.
    CodeNotListed,
    /// An unpadded normal case written back gave different octets.
    RoundTripDiffers,
};

const Counts = struct {
    cases: u64 = 0,
    normal: u64 = 0,
    errors: u64 = 0,
    round_trips: u64 = 0,
};

/// Where the last failure was, for the one report a run prints.
const LastFailure = struct {
    field: []const u8 = "",
    code: ?u32 = null,
};

var last_failure: LastFailure = .{};

/// The decoded wire and the frame written back, placed outside any stack frame.
var wire_buffer: [wire_len_max]u8 = undefined;
var round_trip_buffer: [wire_len_max]u8 = undefined;
var settings_buffer: [constants.settings_per_frame_max]frame.Setting = undefined;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len != 2) {
        std.debug.print("usage: h2_frames <http2-frame-test-case directory>\n", .{});
        std.process.exit(exit_usage);
    }
    var counts: Counts = .{};
    run_directory(init.io, init.gpa, arguments[1], &counts) catch |failure| {
        std.debug.print("h2-frames: {s}\n", .{@errorName(failure)});
        std.process.exit(exit_failure);
    };
    std.debug.print(
        "h2-frames: cases={d} normal={d} errors={d} round_trips={d}\n",
        .{ counts.cases, counts.normal, counts.errors, counts.round_trips },
    );
}

fn run_directory(io: Io, gpa: Allocator, root_path: []const u8, counts: *Counts) !void {
    var root = try Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);
    var directories = root.iterate();
    while (try directories.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var directory = try root.openDir(io, entry.name, .{ .iterate = true });
        defer directory.close(io);
        try run_files(io, gpa, directory, entry.name, counts);
    }
}

fn run_files(io: Io, gpa: Allocator, directory: Io.Dir, name: []const u8, counts: *Counts) !void {
    var files = directory.iterate();
    while (try files.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const text = try directory.readFileAlloc(io, entry.name, arena, .limited(case_bytes_max));
        const case = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
        run_case(case, counts) catch |failure| {
            std.debug.print("h2-frames: {s}/{s}: {s}\n", .{ name, entry.name, @errorName(failure) });
            if (last_failure.field.len != 0) std.debug.print("  field: {s}\n", .{last_failure.field});
            if (last_failure.code) |code| std.debug.print("  code: {d}\n", .{code});
            return failure;
        };
    }
}

/// Runs one case: an error case must be refused with a listed code, a normal case must parse to
/// the fields it lists and round-trip.
fn run_case(case: Value, counts: *Counts) !void {
    last_failure = .{};
    if (case != .object) return error.CaseMalformed;
    const hex = try string_field(case.object, "wire");
    const wire = std.fmt.hexToBytes(&wire_buffer, hex) catch return error.CaseMalformed;
    const errors = case.object.get("error") orelse return error.CaseMalformed;
    const expected = case.object.get("frame") orelse return error.CaseMalformed;
    counts.cases += 1;
    if (errors == .array) {
        try run_error_case(wire, errors.array.items);
        counts.errors += 1;
    } else if (expected == .object) {
        try run_normal_case(wire, expected.object, counts);
        counts.normal += 1;
    } else {
        return error.CaseMalformed;
    }
}

const Decoded = struct {
    header: frame.Header,
    payload: frame.Payload,
};

const Outcome = union(enum) {
    decoded: Decoded,
    refused: frame.Verdict,
};

/// Reads the header and parses the payload of one wire, or the verdict a connection would reach.
fn decode(wire: []const u8) !Outcome {
    var reader = Reader.init(wire);
    const header = frame.read_header(&reader) catch return error.CaseMalformed;
    const rest = reader.take_rest();
    // RFC 9113 §4.2: a connection refuses a frame whose Length exceeds SETTINGS_MAX_FRAME_SIZE
    // with FRAME_SIZE_ERROR before it reads the payload, and a wire with fewer octets than its
    // Length promises is the corpus's frame too small for its mandatory data, the same error.
    if (header.length > constants.frame_size_max or rest.len < header.length) {
        return .{ .refused = .{ .kind = .connection, .code = constants.error_frame_size_error } };
    }
    if (rest.len > header.length) return error.CaseMalformed;
    const payload = frame.parse(header, rest) catch |failure| {
        return .{ .refused = frame.verdict(failure, @enumFromInt(header.type), header.stream_id) };
    };
    return .{ .decoded = .{ .header = header, .payload = payload } };
}

fn run_error_case(wire: []const u8, codes: []const Value) !void {
    const verdict = switch (try decode(wire)) {
        .decoded => return error.ErrorExpected,
        .refused => |verdict| verdict,
    };
    last_failure.code = verdict.code;
    for (codes) |code| {
        if (code == .integer and code.integer == verdict.code) return;
    }
    return error.CodeNotListed;
}

fn run_normal_case(wire: []const u8, expected: ObjectMap, counts: *Counts) !void {
    const decoded = switch (try decode(wire)) {
        .decoded => |decoded| decoded,
        .refused => |verdict| {
            last_failure.code = verdict.code;
            return error.Refused;
        },
    };
    const fields = (expected.get("frame_payload") orelse return error.CaseMalformed);
    if (fields != .object) return error.CaseMalformed;
    try expect_header(decoded.header, expected);
    try expect_payload(decoded.payload, fields.object);

    var writer = Writer.init(&round_trip_buffer);
    try write_back(&writer, decoded.header, decoded.payload);
    const again = switch (try decode(writer.written())) {
        .decoded => |again| again,
        .refused => |verdict| {
            last_failure.code = verdict.code;
            return error.Refused;
        },
    };
    try expect_header(again.header, expected);
    try expect_payload(again.payload, fields.object);
    if (!is_padded(fields.object) and !std.mem.eql(u8, wire, writer.written())) return error.RoundTripDiffers;
    counts.round_trips += 1;
}

/// Whether the case carries padding octets, which colibri writes back as zeros (RFC 9113 §6.1).
fn is_padded(fields: ObjectMap) bool {
    const padding = fields.get("padding") orelse return false;
    return padding == .string and padding.string.len != 0;
}

fn write_back(writer: *Writer, header: frame.Header, payload: frame.Payload) !void {
    const stream_id = header.stream_id;
    switch (payload) {
        .data => |data| try frame.write_data(writer, stream_id, data.data, data.end_stream, data.padding_len),
        .headers => |headers| try frame.write_headers(
            writer,
            stream_id,
            headers.fragment,
            headers.end_stream,
            headers.end_headers,
            headers.padding_len,
            headers.priority,
        ),
        .priority => |priority| try frame.write_priority(writer, stream_id, priority),
        .rst_stream => |reset| try frame.write_rst_stream(writer, stream_id, reset.error_code),
        .settings => |settings| try write_settings_back(writer, settings),
        .push_promise => |promise| try frame.write_push_promise(
            writer,
            stream_id,
            promise.promised_stream_id,
            promise.fragment,
            promise.end_headers,
            promise.padding_len,
        ),
        .ping => |ping| try frame.write_ping(writer, ping.opaque_data, ping.ack),
        .goaway => |goaway| try frame.write_goaway(writer, goaway.last_stream_id, goaway.error_code, goaway.debug_data),
        .window_update => |update| try frame.write_window_update(writer, stream_id, update.increment),
        .continuation => |continuation| try frame.write_continuation(
            writer,
            stream_id,
            continuation.fragment,
            continuation.end_headers,
        ),
        .unknown => return error.CaseMalformed,
    }
}

fn write_settings_back(writer: *Writer, settings: frame.Settings) !void {
    if (settings.ack) return frame.write_settings_ack(writer);
    var iterator = settings.iterator();
    var count: usize = 0;
    while (iterator.next()) |setting| : (count += 1) {
        assert(count < settings_buffer.len);
        settings_buffer[count] = setting;
    }
    try frame.write_settings(writer, settings_buffer[0..count]);
}

fn expect_header(header: frame.Header, expected: ObjectMap) !void {
    try expect_integer(expected, "length", header.length);
    try expect_integer(expected, "type", header.type);
    try expect_integer(expected, "flags", header.flags);
    try expect_integer(expected, "stream_identifier", header.stream_id);
}

fn expect_payload(payload: frame.Payload, fields: ObjectMap) !void {
    switch (payload) {
        .data => |data| {
            try expect_string(fields, "data", data.data);
            try expect_optional_integer(fields, "padding_length", data.padding_len);
        },
        .headers => |headers| {
            try expect_string(fields, "header_block_fragment", headers.fragment);
            try expect_optional_integer(fields, "padding_length", headers.padding_len);
            try expect_priority(fields, headers.priority);
        },
        .priority => |priority| try expect_priority(fields, priority),
        .rst_stream => |reset| try expect_integer(fields, "error_code", reset.error_code),
        .settings => |settings| try expect_settings(fields, settings),
        .push_promise => |promise| {
            try expect_integer(fields, "promised_stream_id", promise.promised_stream_id);
            try expect_string(fields, "header_block_fragment", promise.fragment);
            try expect_optional_integer(fields, "padding_length", promise.padding_len);
        },
        .ping => |ping| try expect_string(fields, "opaque_data", &ping.opaque_data),
        .goaway => |goaway| {
            try expect_integer(fields, "last_stream_id", goaway.last_stream_id);
            try expect_integer(fields, "error_code", goaway.error_code);
            try expect_string(fields, "additional_debug_data", goaway.debug_data);
        },
        .window_update => |update| try expect_integer(fields, "window_size_increment", update.increment),
        .continuation => |continuation| try expect_string(fields, "header_block_fragment", continuation.fragment),
        .unknown => return error.CaseMalformed,
    }
}

/// The priority fields, listed as null when the frame carries none. The corpus lists the weight
/// as the octet plus one, the way the deprecated scheme read it (RFC 9113 §5.3.2 keeps the field
/// and drops the arithmetic); colibri keeps the octet.
fn expect_priority(fields: ObjectMap, priority: ?frame.Priority) !void {
    const dependency = fields.get("stream_dependency") orelse return error.CaseMalformed;
    if (dependency == .null) {
        if (priority != null) return field_differs("stream_dependency");
        return;
    }
    const present = priority orelse return field_differs("stream_dependency");
    try expect_integer(fields, "stream_dependency", present.dependency);
    try expect_integer(fields, "weight", @as(u64, present.weight) + 1);
    const exclusive = fields.get("exclusive") orelse return error.CaseMalformed;
    if (exclusive != .bool) return error.CaseMalformed;
    if (exclusive.bool != present.exclusive) return field_differs("exclusive");
}

/// The settings, listed as `[[identifier, value], ...]` in order.
fn expect_settings(fields: ObjectMap, settings: frame.Settings) !void {
    const listed = fields.get("settings") orelse return error.CaseMalformed;
    if (listed != .array) return error.CaseMalformed;
    var iterator = settings.iterator();
    for (listed.array.items) |pair| {
        if (pair != .array or pair.array.items.len != 2) return error.CaseMalformed;
        const setting = iterator.next() orelse return field_differs("settings");
        if (integer_of(pair.array.items[0]) != setting.id) return field_differs("settings");
        if (integer_of(pair.array.items[1]) != setting.value) return field_differs("settings");
    }
    if (iterator.next() != null) return field_differs("settings");
}

fn field_differs(field: []const u8) Failure {
    last_failure.field = field;
    return error.FieldDiffers;
}

fn integer_of(value: Value) ?i64 {
    return if (value == .integer) value.integer else null;
}

fn string_field(object: ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.CaseMalformed;
    if (value != .string) return error.CaseMalformed;
    return value.string;
}

fn expect_integer(object: ObjectMap, key: []const u8, actual: u64) !void {
    const value = object.get(key) orelse return error.CaseMalformed;
    const listed = integer_of(value) orelse return error.CaseMalformed;
    if (listed != actual) return field_differs(key);
}

/// An integer the case may list as null, which the codec reports as 0.
fn expect_optional_integer(object: ObjectMap, key: []const u8, actual: u64) !void {
    const value = object.get(key) orelse return error.CaseMalformed;
    if (value == .null) {
        if (actual != 0) return field_differs(key);
        return;
    }
    return expect_integer(object, key, actual);
}

fn expect_string(object: ObjectMap, key: []const u8, actual: []const u8) !void {
    const listed = try string_field(object, key);
    if (!std.mem.eql(u8, listed, actual)) return field_differs(key);
}

const testing = std.testing;

fn parse_case(arena: Allocator, text: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, arena, text, .{});
}

test "a normal case must parse to its fields and round-trip, and an error case must be refused with a listed code" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var counts: Counts = .{};
    try run_case(try parse_case(arena,
        \\{"error": null, "wire": "0000050200000000090000000B07",
        \\ "frame": {"length": 5, "type": 2, "flags": 0, "stream_identifier": 9,
        \\  "frame_payload": {"stream_dependency": 11, "weight": 8, "exclusive": false, "padding_length": null, "padding": null}}}
    ), &counts);
    try run_case(try parse_case(arena,
        \\{"error": null, "wire": "0000140008000000020648656C6C6F2C20776F726C6421486F77647921",
        \\ "frame": {"length": 20, "type": 0, "flags": 8, "stream_identifier": 2,
        \\  "frame_payload": {"data": "Hello, world!", "padding_length": 6, "padding": "Howdy!"}}}
    ), &counts);
    try run_case(try parse_case(arena,
        \\{"error": [6], "wire": "000004060000000000AAAAAAAA", "frame": null}
    ), &counts);
    try testing.expectEqual(3, counts.cases);
    try testing.expectEqual(2, counts.normal);
    try testing.expectEqual(1, counts.errors);
    try testing.expectEqual(2, counts.round_trips);
}

test "a field that differs, a parse where an error is listed, and an unlisted code each fail" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var counts: Counts = .{};
    try testing.expectError(error.FieldDiffers, run_case(try parse_case(arena,
        \\{"error": null, "wire": "0000050200000000090000000B07",
        \\ "frame": {"length": 5, "type": 2, "flags": 0, "stream_identifier": 9,
        \\  "frame_payload": {"stream_dependency": 11, "weight": 7, "exclusive": false, "padding_length": null, "padding": null}}}
    ), &counts));
    try testing.expectEqualStrings("weight", last_failure.field);
    try testing.expectError(error.ErrorExpected, run_case(try parse_case(arena,
        \\{"error": [1], "wire": "0000050200000000090000000B07", "frame": null}
    ), &counts));
    try testing.expectError(error.CodeNotListed, run_case(try parse_case(arena,
        \\{"error": [1], "wire": "000004060000000000AAAAAAAA", "frame": null}
    ), &counts));
    try testing.expectEqual(constants.error_frame_size_error, last_failure.code.?);
    try testing.expectError(error.Refused, run_case(try parse_case(arena,
        \\{"error": null, "wire": "000004060000000000AAAAAAAA",
        \\ "frame": {"length": 4, "type": 6, "flags": 0, "stream_identifier": 0, "frame_payload": {"opaque_data": "AAAA"}}}
    ), &counts));
}

test "each header field the case lists is compared: a wrong length, type, flags or stream identifier fails" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var counts: Counts = .{};
    const header_fields = [_][]const u8{ "length", "type", "flags", "stream_identifier" };
    const cases = [_][]const u8{
        \\{"error": null, "wire": "0000050200000000090000000B07",
        \\ "frame": {"length": 4, "type": 2, "flags": 0, "stream_identifier": 9,
        \\  "frame_payload": {"stream_dependency": 11, "weight": 8, "exclusive": false, "padding_length": null, "padding": null}}}
        ,
        \\{"error": null, "wire": "0000050200000000090000000B07",
        \\ "frame": {"length": 5, "type": 1, "flags": 0, "stream_identifier": 9,
        \\  "frame_payload": {"stream_dependency": 11, "weight": 8, "exclusive": false, "padding_length": null, "padding": null}}}
        ,
        \\{"error": null, "wire": "0000050200000000090000000B07",
        \\ "frame": {"length": 5, "type": 2, "flags": 1, "stream_identifier": 9,
        \\  "frame_payload": {"stream_dependency": 11, "weight": 8, "exclusive": false, "padding_length": null, "padding": null}}}
        ,
        \\{"error": null, "wire": "0000050200000000090000000B07",
        \\ "frame": {"length": 5, "type": 2, "flags": 0, "stream_identifier": 8,
        \\  "frame_payload": {"stream_dependency": 11, "weight": 8, "exclusive": false, "padding_length": null, "padding": null}}}
        ,
    };
    for (cases, header_fields) |case, field| {
        try testing.expectError(error.FieldDiffers, run_case(try parse_case(arena, case), &counts));
        try testing.expectEqualStrings(field, last_failure.field);
    }
}

test "a wire shorter than its Length, or longer than frame_size_max, is refused as FRAME_SIZE_ERROR (RFC 9113 §4.2)" {
    const short = try decode("\x00\x80\x00\x00\x08\x00\x00\x00\x02\x06Hello, world!howdy!");
    try testing.expectEqual(frame.Verdict{ .kind = .connection, .code = constants.error_frame_size_error }, short.refused);
    const promised = try decode("\x00\x00\x02\x08\x00\x00\x00\x00\x01\x55");
    try testing.expectEqual(constants.error_frame_size_error, promised.refused.code);
    try testing.expectError(error.CaseMalformed, decode("\x00\x00\x00\x08\x00\x00\x00\x00\x01\x55"));
}
