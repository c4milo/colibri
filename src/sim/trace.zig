//! `Trace`, the per-seed record of every abstract transition a run takes, in the version 1 format
//! of design §6.6:
//!
//!     colibri-sim-trace version=1 check=<check> seed=0x<16 hex digits>
//!     <record> <key>=<value> ...
//!     end records=<count> outcome=<outcome>
//!
//! The trace is written into a `core.Writer` over storage the caller owns, never to a file. A run
//! prints it when a seed fails, and a check compares two runs of one seed byte for byte. Each record
//! is built whole in a `Record` and then written all at once, so a trace that runs out of room
//! ends at a whole line and the error says so.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

const Writer = core.Writer;

pub const Error = core.writer.Error;

/// The words of the first and last lines.
const header_word = "colibri-sim-trace";
const end_word = "end";

/// The record every chunk boundary writes, which `write_chunk_independent` leaves out.
pub const feed_record = "feed";

/// Calls to a line splitter past a trace's octet count: a trace of n octets holds at most n + 1
/// pieces between its newlines, and one more call finds the end, so a bound of n plus this is
/// never the reason a loop over the lines stops.
const split_calls_past_len = 2;

/// The field of the last line that gives how the run ended.
const outcome_field = " outcome=";

pub const Trace = struct {
    output: *Writer,
    /// Records written between the first line and the last.
    records: u64,

    /// Writes the first line: the version, the check and the seed.
    pub fn begin(output: *Writer, check: []const u8, seed: u64) Error!Trace {
        assert(check.len > 0 and check.len <= constants.check_name_len_max);
        assert(is_word(check));
        try output.print("{s} version={d} check={s} seed=0x{x:0>16}\n", .{
            header_word,
            constants.trace_version,
            check,
            seed,
        });
        return .{ .output = output, .records = 0 };
    }

    /// A record named `name`, empty of fields, to be filled and then passed to `write`.
    pub fn record(trace: *const Trace, name: []const u8) Error!Record {
        _ = trace;
        assert(name.len > 0);
        assert(is_key(name));
        assert(!std.mem.eql(u8, name, end_word));
        var line: Record = .{ .line = @splat(0), .len = 0 };
        try line.append("{s}", .{name});
        return line;
    }

    /// Writes a filled record as one line, all of it or none.
    pub fn write(trace: *Trace, line: *const Record) Error!void {
        assert(line.len > 0 and line.len < constants.trace_record_len_max);
        const text = line.line[0..line.len];
        if (text.len + 1 > trace.output.remaining_len()) return error.NoSpaceLeft;
        trace.output.write_bytes(text) catch unreachable;
        trace.output.write_byte('\n') catch unreachable;
        trace.records += 1;
    }

    /// Writes the last line: the count of records and how the run ended.
    pub fn end(trace: *Trace, outcome: []const u8) Error!void {
        assert(outcome.len > 0);
        assert(is_word(outcome));
        const arguments = .{ end_word, trace.records, outcome };
        try trace.output.print("{s} records={d} outcome={s}\n", arguments);
    }
};

/// One line under construction. It holds at most `trace_record_len_max` octets, its newline
/// included, and a field that does not fit fails the record rather than cutting it.
pub const Record = struct {
    line: [constants.trace_record_len_max]u8,
    len: u32,

    /// An unsigned integer, in decimal.
    pub fn number(line: *Record, key: []const u8, value: u64) Error!void {
        assert(is_key(key));
        try line.append(" {s}={d}", .{ key, value });
    }

    /// Octets, in lowercase hexadecimal with no prefix. No octets is an empty value.
    pub fn octets(line: *Record, key: []const u8, value: []const u8) Error!void {
        assert(is_key(key));
        try line.append(" {s}={x}", .{ key, value });
    }

    /// A word: an error name, an outcome, a coding.
    pub fn word(line: *Record, key: []const u8, value: []const u8) Error!void {
        assert(is_key(key));
        assert(value.len > 0);
        assert(is_word(value));
        try line.append(" {s}={s}", .{ key, value });
    }

    fn append(line: *Record, comptime format: []const u8, arguments: anytype) Error!void {
        // One octet stays free for the newline `Trace.write` adds.
        var writer = Writer.init(line.line[0 .. constants.trace_record_len_max - 1]);
        writer.offset = line.len;
        try writer.print(format, arguments);
        line.len = @intCast(writer.offset);
        assert(line.len < constants.trace_record_len_max);
    }
};

/// Writes the part of `text`, a trace, that does not depend on how the stream was chunked
/// (design §6.6): every line but the `feed` records, with the last line's record count left out,
/// since the count includes them.
pub fn write_chunk_independent(text: []const u8, output: *Writer) Error!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    for (0..text.len + split_calls_past_len) |_| {
        const line = lines.next() orelse return;
        if (line.len == 0 or is_record(line, feed_record)) continue;
        if (is_record(line, end_word)) {
            const outcome = std.mem.indexOf(u8, line, outcome_field) orelse line.len;
            try output.write_bytes(end_word);
            try output.write_bytes(line[outcome..]);
        } else {
            try output.write_bytes(line);
        }
        try output.write_byte('\n');
    }
    unreachable;
}

/// How many records of `text`, a trace, are named `name`.
pub fn count_records(text: []const u8, name: []const u8) u64 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var count: u64 = 0;
    for (0..text.len + split_calls_past_len) |_| {
        const line = lines.next() orelse return count;
        if (is_record(line, name)) count += 1;
    }
    unreachable;
}

fn is_record(line: []const u8, name: []const u8) bool {
    return std.mem.startsWith(u8, line, name) and line.len > name.len and line[name.len] == ' ';
}

/// A key: lowercase letters, digits and underscores (design §6.6).
fn is_key(text: []const u8) bool {
    for (text) |octet| {
        const allowed = std.ascii.isLower(octet) or std.ascii.isDigit(octet) or octet == '_';
        if (!allowed) return false;
    }
    return text.len > 0;
}

/// A value holding no space and no line break.
fn is_word(text: []const u8) bool {
    for (text) |octet| {
        if (!std.ascii.isPrint(octet) or octet == ' ') return false;
    }
    return true;
}

const testing = std.testing;

/// Octets of trace the tests write into. Test-only.
const test_trace_len_max = 1024;

test "a trace is its first line, one line per record, and a last line that counts them" {
    var buffer: [test_trace_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    var trace = try Trace.begin(&output, "chunk", 0xc0ffee);
    var feed = try trace.record(feed_record);
    try feed.number("at_ns", 1500);
    try feed.number("len", 3);
    try trace.write(&feed);
    var accept = try trace.record("accept");
    try accept.number("offset", 0);
    try accept.octets("text", "\x00\xab");
    try accept.octets("empty", "");
    try accept.word("coding", "huffman");
    try trace.write(&accept);
    try trace.end("pass");
    try testing.expectEqualStrings(
        \\colibri-sim-trace version=1 check=chunk seed=0x0000000000c0ffee
        \\feed at_ns=1500 len=3
        \\accept offset=0 text=00ab empty= coding=huffman
        \\end records=2 outcome=pass
        \\
    , output.written());
    try testing.expectEqual(2, trace.records);
}

test "a record too long for its line fails whole and leaves the line as it was" {
    var buffer: [test_trace_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    const trace = try Trace.begin(&output, "chunk", 0);
    var line = try trace.record("accept");
    const long: [constants.trace_record_len_max / 2]u8 = @splat(0xab);
    try testing.expectError(error.NoSpaceLeft, line.octets("text", &long));
    try testing.expectEqualStrings("accept", line.line[0..line.len]);
    const fits: [constants.trace_record_len_max / 2 - "accept text=".len]u8 = @splat('a');
    try line.octets("text", fits[0 .. fits.len / 2]);
    try testing.expect(line.len < constants.trace_record_len_max);
}

test "a record keeps its last octet for the newline" {
    var buffer: [test_trace_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    const trace = try Trace.begin(&output, "chunk", 0);
    var line = try trace.record("a");
    // " u=x" would end the line at `trace_record_len_max` octets, leaving none for the newline.
    const value: [constants.trace_record_len_max - "a t= u=x".len]u8 = @splat('v');
    try line.word("t", &value);
    try testing.expectError(error.NoSpaceLeft, line.word("u", "x"));
}

test "a trace out of room keeps whole lines and counts only what it wrote" {
    const first_line = "colibri-sim-trace version=1 check=chunk seed=0x0000000000000000\n";
    // Room for one record and its newline, then for a second record but not its newline.
    var buffer: [first_line.len + "feed len=1\n".len + "feed len=1".len]u8 = @splat(0);
    var output = Writer.init(&buffer);
    var trace = try Trace.begin(&output, "chunk", 0);
    var fits = try trace.record("feed");
    try fits.number("len", 1);
    try trace.write(&fits);
    const offset = output.offset;
    try testing.expectError(error.NoSpaceLeft, trace.write(&fits));
    try testing.expectEqual(offset, output.offset);
    try testing.expectEqual(1, trace.records);
    try testing.expectError(error.NoSpaceLeft, trace.end("pass"));
}

test "records are counted by name, at a word boundary" {
    const text = "feed a=1\nfeeding a=2\nfeed a=3\nend records=3 outcome=pass\n";
    try testing.expectEqual(2, count_records(text, "feed"));
    try testing.expectEqual(1, count_records(text, "feeding"));
    try testing.expectEqual(0, count_records("", "feed"));
    try testing.expectEqual(0, count_records("\n\n", "feed"));
}

test "the chunk-independent part of an empty trace is empty" {
    var buffer: [test_trace_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try write_chunk_independent("", &output);
    try write_chunk_independent("\n", &output);
    try testing.expectEqual(0, output.offset);
}

test "the chunk-independent part keeps every line but feeds, and the outcome without the count" {
    var buffer: [test_trace_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try write_chunk_independent(
        \\colibri-sim-trace version=1 check=chunk seed=0x0000000000000001
        \\feed at_ns=0 len=1 held=1
        \\accept offset=0 len=1 value=5
        \\feeding offset=1
        \\feed at_ns=7 len=2 held=2
        \\reject offset=1 error=IntegerTooLong
        \\end records=4 outcome=rejected
        \\
    , &output);
    try testing.expectEqualStrings(
        \\colibri-sim-trace version=1 check=chunk seed=0x0000000000000001
        \\accept offset=0 len=1 value=5
        \\feeding offset=1
        \\reject offset=1 error=IntegerTooLong
        \\end outcome=rejected
        \\
    , output.written());
}
