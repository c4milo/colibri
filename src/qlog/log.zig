//! A qlog log in a buffer the caller owns (decision 102). It holds the QlogFileSeq header of main
//! schema §5 and one record per event (§7), each a JSON text between RS and LF (RFC 7464 §2.2),
//! which is how main schema §11.2 writes a log as JSON Text Sequences.
//!
//! colibri never writes a log out. The caller takes the records with `bytes`, writes them where it
//! wants, and calls `clear`. An event that does not fit in what is left is dropped whole and
//! counted in `dropped`: a log never fails the connection that writes it.
const std = @import("std");
const assert = std.debug.assert;
const TextWriter = @import("json").TextWriter;
const Features = @import("codec").Features;
const constants = @import("constants.zig");
const member = @import("member.zig");

pub const Error = member.Error;

/// The file schema of a log written as JSON Text Sequences (main schema §5).
pub const file_schema = "urn:ietf:params:qlog:file:sequential";

/// Its media type (main schema §11.2).
pub const serialization_format = "application/qlog+json-seq";

/// The vantage points colibri's endpoints take (main schema §6).
pub const VantagePoint = enum { client, server };

/// What the header record says about the trace (main schema §5.1).
pub const Trace = struct {
    vantage_point: VantagePoint,
    /// The original destination connection ID, the group ID quic-events §1.1 recommends. Written
    /// as a hexstring.
    group_id: []const u8,
    /// The URIs of the event schemas the events belong to (main schema §8).
    event_schemas: []const []const u8,
};

pub const Log = struct {
    buffer: []u8,
    /// The CPU features stdx's JSON writer may use, which the caller chose (decision 102 as
    /// amended). The records are the same octets for every value (stdx's invariant 5).
    features: Features,
    /// Octets of whole records, from the start of `buffer`, that the caller has not taken.
    len: usize = 0,
    /// Events dropped because they did not fit.
    dropped: u64 = 0,
    /// The instant of the header. Each event's time runs from it.
    start_ns: u64 = 0,
    started: bool = false,

    /// A log over `buffer`, written with `features`: `Features.detect()`, what the CPU has, or
    /// `Features.target()`, what the build target guarantees. colibri never asks the CPU itself.
    pub fn init(buffer: []u8, features: Features) Log {
        assert(buffer.len >= constants.log_len_min);
        return .{ .buffer = buffer, .features = features };
    }

    /// Writes the header record, which main schema §5 puts first, and starts the clock of the
    /// trace at `now_ns`. The times are relative to an unknown epoch on a monotonic clock
    /// (main schema §7.1), because colibri's instants are the caller's and name no calendar.
    pub fn start(log: *Log, trace: Trace, now_ns: u64) Error!void {
        assert(!log.started);
        assert(trace.event_schemas.len > 0);
        var text = TextWriter.init(log.buffer[log.len..], .sequence, log.features);
        try text.begin_object();
        try member.string(&text, "file_schema", file_schema);
        try member.string(&text, "serialization_format", serialization_format);
        try text.name("trace");
        try write_trace(&text, trace);
        try text.end_object();
        log.len += text.written().len;
        log.start_ns = now_ns;
        log.started = true;
    }

    /// Writes one event named `name` at `now_ns`, whose data `data.write(text)` writes as the
    /// members of the `data` object (main schema §7), or drops it whole when it does not fit.
    pub fn event(log: *Log, name: []const u8, now_ns: u64, data: anytype) void {
        log.event_on_tuple(0, name, now_ns, data);
    }

    /// Writes one event as `event` does, on tuple number `tuple`, which the event's `tuple` names
    /// (main schema §7.2). Tuple 0 is a connection's first, the default quic-events §4.7 gives an
    /// event that names none, so it is left out.
    pub fn event_on_tuple(log: *Log, tuple: u32, name: []const u8, now_ns: u64, data: anytype) void {
        assert(log.started);
        assert(now_ns >= log.start_ns);
        const time_ns = now_ns - log.start_ns;
        const len = write_event(log.buffer[log.len..], log.features, tuple, name, time_ns, data) catch {
            log.dropped += 1;
            return;
        };
        log.len += len;
        assert(log.len <= log.buffer.len);
    }

    /// The records the caller has not taken yet.
    pub fn bytes(log: *const Log) []const u8 {
        assert(log.len <= log.buffer.len);
        return log.buffer[0..log.len];
    }

    /// Frees the buffer after the caller took `bytes`.
    pub fn clear(log: *Log) void {
        assert(log.len <= log.buffer.len);
        log.len = 0;
    }
};

/// Main schema §5.1's TraceSeq, with the common fields of §7.5 that every event shares.
fn write_trace(text: *TextWriter, trace: Trace) Error!void {
    try text.begin_object();
    try text.name("common_fields");
    try text.begin_object();
    try member.hex(text, "group_id", trace.group_id);
    try member.string(text, "time_format", "relative_to_epoch");
    try text.name("reference_time");
    try text.begin_object();
    // Main schema §7.1: a monotonic clock's epoch MUST be "unknown".
    try member.string(text, "clock_type", "monotonic");
    try member.string(text, "epoch", "unknown");
    try text.end_object();
    try text.end_object();
    try text.name("vantage_point");
    try text.begin_object();
    try member.string(text, "type", @tagName(trace.vantage_point));
    try text.end_object();
    try text.name("event_schemas");
    try text.begin_array();
    // Bounded by the caller's list.
    for (trace.event_schemas) |schema| try text.string(schema);
    try text.end_array();
    try text.end_object();
}

/// One event record into `buffer`, and its length. Nothing is committed until it all fit, so a
/// failed record leaves only scratch past the log's length.
fn write_event(buffer: []u8, features: Features, tuple: u32, name: []const u8, time_ns: u64, data: anytype) Error!usize {
    var text = TextWriter.init(buffer, .sequence, features);
    try text.begin_object();
    try member.milliseconds(&text, "time", time_ns);
    try member.string(&text, "name", name);
    if (tuple != 0) {
        var digits: [constants.tuple_id_len_max]u8 = undefined;
        try member.string(&text, "tuple", member.tuple_id(&digits, tuple));
    }
    try text.name("data");
    try text.begin_object();
    try data.write(&text);
    try text.end_object();
    try text.end_object();
    return text.written().len;
}

const testing = std.testing;

const Marker = struct {
    message: []const u8,

    pub fn write(marker: Marker, text: *TextWriter) Error!void {
        try member.string(text, "message", marker.message);
    }
};

const test_schemas = [_][]const u8{"urn:ietf:params:qlog:events:quic-13"};

fn test_trace(group_id: []const u8) Trace {
    return .{ .vantage_point = .server, .group_id = group_id, .event_schemas = &test_schemas };
}

test "the header record is a QlogFileSeq between RS and LF" {
    var buffer: [constants.log_len_min]u8 = undefined;
    var log = Log.init(&buffer, Features.none());
    try log.start(test_trace(&.{ 0xab, 0x01 }), 7);
    try testing.expectEqualStrings("\x1e{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"," ++
        "\"serialization_format\":\"application/qlog+json-seq\",\"trace\":{\"common_fields\":" ++
        "{\"group_id\":\"ab01\",\"time_format\":\"relative_to_epoch\",\"reference_time\":" ++
        "{\"clock_type\":\"monotonic\",\"epoch\":\"unknown\"}},\"vantage_point\":{\"type\":\"server\"}," ++
        "\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-13\"]}}\n", log.bytes());
}

test "an event record carries its time from the header's instant, its name and its data" {
    var buffer: [constants.log_len_min]u8 = undefined;
    var log = Log.init(&buffer, Features.none());
    try log.start(test_trace(&.{ 0xab, 0x01 }), 1_000_000);
    log.clear();
    log.event("loglevel:info", 3_500_000, Marker{ .message = "hello" });
    try testing.expectEqualStrings("\x1e{\"time\":2.500,\"name\":\"loglevel:info\",\"data\":{\"message\":\"hello\"}}\n", log.bytes());
    try testing.expectEqual(0, log.dropped);
}

test "an event that does not fit is dropped whole, and the next one that fits is written" {
    var buffer: [constants.log_len_min]u8 = undefined;
    var log = Log.init(&buffer, Features.none());
    try log.start(test_trace(&.{ 0xab, 0x01 }), 0);
    const filler: [constants.log_len_min]u8 = @splat('x');
    const kept = log.len;
    log.event("loglevel:info", 0, Marker{ .message = &filler });
    try testing.expectEqual(1, log.dropped);
    try testing.expectEqual(kept, log.len);
    log.event("loglevel:info", 0, Marker{ .message = "fits" });
    try testing.expectEqual(1, log.dropped);
    try testing.expect(std.mem.endsWith(u8, log.bytes(), "{\"message\":\"fits\"}}\n"));
}

test "an event on a later tuple names it, and one on the first names none" {
    var buffer: [constants.log_len_min]u8 = undefined;
    var log = Log.init(&buffer, Features.none());
    try log.start(test_trace(&.{ 0xab, 0x01 }), 0);
    log.clear();
    log.event_on_tuple(2, "loglevel:info", 0, Marker{ .message = "moved" });
    try testing.expectEqualStrings("\x1e{\"time\":0.000,\"name\":\"loglevel:info\",\"tuple\":\"2\",\"data\":{\"message\":\"moved\"}}\n", log.bytes());
    log.clear();
    log.event_on_tuple(0, "loglevel:info", 0, Marker{ .message = "first" });
    try testing.expectEqualStrings("\x1e{\"time\":0.000,\"name\":\"loglevel:info\",\"data\":{\"message\":\"first\"}}\n", log.bytes());
}
