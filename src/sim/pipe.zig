//! The byte pipe (design §4.1, §10): the harness plays the caller of a parser, handing it a stream
//! in chunks whose boundaries and delays the seed chooses.
//!
//! A real caller reads what its socket returned, hands colibri the octets it holds, and keeps what
//! colibri did not consume for the next call. The pipe does the same over a stream fixed before the
//! run. It holds the octets from the first one not yet consumed to the last one fed, and after each
//! chunk it offers them to the subject until the subject asks for more. Holding them is slicing the
//! stream, not copying it, so a subject that read past what it was offered would fail the slice's
//! bounds check.
//!
//! A subject is any type with two declarations:
//!
//! - `fn step(subject: *Subject, held: []const u8) Step`: what the subject did with the octets the
//!   caller holds. It consumes a whole value or nothing.
//! - `fn describe(subject: *const Subject, line: *trace.Record) trace.Error!void`: the fields of the
//!   value `step` last accepted.
//!
//! Each chunk writes a `feed` record, each value an `accept` record, and a refusal a `reject`
//! record, and the run ends with an `end` record naming the `Outcome` (design §6.6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const Random = @import("random.zig").Random;
const Clock = @import("clock.zig").Clock;
const trace_module = @import("trace.zig");

const Trace = trace_module.Trace;

/// What a subject did with the octets the caller holds.
pub const Step = union(enum) {
    /// The octets held are a prefix of a value: the caller must feed more before asking again.
    need_more,
    /// A whole value of this many octets, the first ones held, was consumed.
    accept: usize,
    /// The first octets held are refused, for this reason.
    reject: anyerror,
};

/// How a run ended.
pub const Outcome = enum {
    /// Every octet of the stream was consumed by an accepted value.
    pass,
    /// The subject refused a value.
    rejected,
    /// The stream ended inside a value.
    truncated,
};

/// How the stream is cut into chunks.
pub const Schedule = union(enum) {
    /// The whole stream in one chunk, at instant 0.
    one_piece,
    /// Chunks of 1 to `chunk_len_max` octets, each after a delay of 0 to `chunk_delay_ns_max`,
    /// both drawn from this generator.
    seeded: *Random,
};

/// Feeds `stream` to `subject` on `schedule`, writing every transition to `trace` and ending it.
/// The only error is a trace out of room, which ends the run before its `end` record.
pub fn run(
    comptime Subject: type,
    subject: *Subject,
    stream: []const u8,
    schedule: Schedule,
    clock: *Clock,
    trace: *Trace,
) trace_module.Error!Outcome {
    comptime assert(@hasDecl(Subject, "step") and @hasDecl(Subject, "describe"));
    var pipe: Pipe = .{ .stream = stream };
    // Every chunk carries at least one octet, so a stream of n octets takes at most n chunks.
    for (0..stream.len) |_| {
        if (pipe.fed == stream.len) break;
        try pipe.feed(schedule, clock, trace);
        if (try pipe.drain(Subject, subject, trace) == .rejected) return finish(trace, .rejected);
    } else assert(pipe.fed == stream.len);
    const outcome: Outcome = if (pipe.consumed == stream.len) .pass else .truncated;
    return finish(trace, outcome);
}

fn finish(trace: *Trace, outcome: Outcome) trace_module.Error!Outcome {
    try trace.end(@tagName(outcome));
    return outcome;
}

const Drained = enum { need_more, rejected };

const Pipe = struct {
    stream: []const u8,
    /// Octets of the stream handed to the caller so far.
    fed: usize = 0,
    /// Octets of the stream the subject consumed so far.
    consumed: usize = 0,

    fn feed(pipe: *Pipe, schedule: Schedule, clock: *Clock, trace: *Trace) trace_module.Error!void {
        const remaining = pipe.stream.len - pipe.fed;
        assert(remaining > 0);
        var len = remaining;
        switch (schedule) {
            .one_piece => {},
            .seeded => |random| {
                len = random.between(1, @min(constants.chunk_len_max, remaining));
                clock.advance(random.between(0, constants.chunk_delay_ns_max));
            },
        }
        pipe.fed += len;
        assert(pipe.consumed <= pipe.fed and pipe.fed <= pipe.stream.len);
        var line = try trace.record(trace_module.feed_record);
        try line.number("at_ns", clock.now_ns);
        try line.number("len", len);
        try line.number("held", pipe.fed - pipe.consumed);
        try trace.write(&line);
    }

    /// Offers the held octets to the subject until it asks for more or refuses them.
    fn drain(
        pipe: *Pipe,
        comptime Subject: type,
        subject: *Subject,
        trace: *Trace,
    ) trace_module.Error!Drained {
        // Every accepted value consumes at least one octet, so n held octets take at most n
        // accepts, and one more step finds the held octets empty or short.
        for (0..pipe.fed - pipe.consumed + 1) |_| {
            const held = pipe.stream[pipe.consumed..pipe.fed];
            if (held.len == 0) return .need_more;
            switch (subject.step(held)) {
                .need_more => return .need_more,
                .accept => |len| try pipe.accept(Subject, subject, len, trace),
                .reject => |reason| {
                    try pipe.reject(reason, trace);
                    return .rejected;
                },
            }
        }
        unreachable;
    }

    fn accept(
        pipe: *Pipe,
        comptime Subject: type,
        subject: *Subject,
        len: usize,
        trace: *Trace,
    ) trace_module.Error!void {
        assert(len > 0);
        assert(len <= pipe.fed - pipe.consumed);
        var line = try trace.record("accept");
        try line.number("offset", pipe.consumed);
        try line.number("len", len);
        try subject.describe(&line);
        try trace.write(&line);
        pipe.consumed += len;
    }

    fn reject(pipe: *const Pipe, reason: anyerror, trace: *Trace) trace_module.Error!void {
        var line = try trace.record("reject");
        try line.number("offset", pipe.consumed);
        try line.word("error", @errorName(reason));
        try trace.write(&line);
    }
};

const testing = std.testing;
const Writer = core.Writer;

/// A value of the toy format: one octet giving a length, then that many octets. A length of 255
/// is refused. It stands in for a real decoder so the pipe is tested with no protocol module.
const LengthPrefixed = struct {
    const refused_len = std.math.maxInt(u8);
    last: []const u8 = "",

    pub fn step(subject: *LengthPrefixed, held: []const u8) Step {
        var reader = core.Reader.init(held);
        const len = reader.read_byte() catch return .need_more;
        if (len == refused_len) return .{ .reject = error.LengthRefused };
        subject.last = reader.take(len) catch return .need_more;
        return .{ .accept = reader.offset };
    }

    pub fn describe(
        subject: *const LengthPrefixed,
        line: *trace_module.Record,
    ) trace_module.Error!void {
        try line.octets("value", subject.last);
    }
};

/// Octets of trace a test run writes into. Test-only.
const test_trace_len_max = 8192;

const TestRun = struct {
    buffer: [test_trace_len_max]u8 = @splat(0),
    output: Writer = Writer.init(&.{}),
    outcome: Outcome = .pass,

    fn start(test_run: *TestRun, stream: []const u8, schedule: Schedule, seed: u64) !void {
        test_run.output = Writer.init(&test_run.buffer);
        var subject: LengthPrefixed = .{};
        var clock = Clock.init();
        var trace = try Trace.begin(&test_run.output, "pipe", seed);
        test_run.outcome = try run(LengthPrefixed, &subject, stream, schedule, &clock, &trace);
    }

    fn text(test_run: *const TestRun) []const u8 {
        return test_run.output.written();
    }
};

const three_values = "\x02ab\x00\x05hello";

test "one piece: every value accepted, in order, with its offset" {
    var one: TestRun = .{};
    try one.start(three_values, .one_piece, 0);
    try testing.expectEqual(.pass, one.outcome);
    try testing.expectEqualStrings(
        \\colibri-sim-trace version=1 check=pipe seed=0x0000000000000000
        \\feed at_ns=0 len=10 held=10
        \\accept offset=0 len=3 value=6162
        \\accept offset=3 len=1 value=
        \\accept offset=4 len=6 value=68656c6c6f
        \\end records=4 outcome=pass
        \\
    , one.text());
}

test "a seed replays byte for byte, and without feeds matches the run in one piece" {
    var one: TestRun = .{};
    try one.start(three_values, .one_piece, 0);
    var whole_buffer: [test_trace_len_max]u8 = @splat(0);
    var whole = Writer.init(&whole_buffer);
    try trace_module.write_chunk_independent(one.text(), &whole);
    for (0..constants.check_seeds_default) |seed| {
        var first_random = Random.init(seed);
        var second_random = Random.init(seed);
        var first: TestRun = .{};
        var second: TestRun = .{};
        try first.start(three_values, .{ .seeded = &first_random }, 0);
        try second.start(three_values, .{ .seeded = &second_random }, 0);
        try testing.expectEqualStrings(first.text(), second.text());
        try testing.expectEqual(first_random.draws, second_random.draws);
        var chunked_buffer: [test_trace_len_max]u8 = @splat(0);
        var chunked = Writer.init(&chunked_buffer);
        try trace_module.write_chunk_independent(first.text(), &chunked);
        try testing.expectEqualStrings(whole.written(), chunked.written());
    }
}

test "a refusal ends the run with the offset of the refused value" {
    var one: TestRun = .{};
    try one.start("\x01a\xff\x01b", .one_piece, 0);
    try testing.expectEqual(.rejected, one.outcome);
    try testing.expectEqualStrings(
        \\colibri-sim-trace version=1 check=pipe seed=0x0000000000000000
        \\feed at_ns=0 len=5 held=5
        \\accept offset=0 len=2 value=61
        \\reject offset=2 error=LengthRefused
        \\end records=3 outcome=rejected
        \\
    , one.text());
}

test "a stream that ends inside a value is truncated, and an empty stream passes" {
    var short: TestRun = .{};
    try short.start("\x01a\x03bc", .one_piece, 0);
    try testing.expectEqual(.truncated, short.outcome);
    var empty: TestRun = .{};
    try empty.start("", .one_piece, 0);
    try testing.expectEqual(.pass, empty.outcome);
    try testing.expectEqualStrings(
        \\colibri-sim-trace version=1 check=pipe seed=0x0000000000000000
        \\end records=0 outcome=pass
        \\
    , empty.text());
}

/// A stream longer than `chunk_len_max`, so a seed can cut a chunk at its longest.
const repeated_values = three_values ** repeats;
const repeats = 4;

/// The fewest values a chunk must carry for the test to see a caller drain more than one.
const values_in_one_chunk = 2;

/// The base trace numbers are written in (design §6.6).
const decimal_radix = 10;

/// What a seeded trace shows about its chunks, read back from its `feed` and `accept` records.
const Reading = struct {
    cuts: [repeated_values.len + 1]bool = @splat(false),
    fed: u64 = 0,
    consumed: u64 = 0,
    at_ns: u64 = 0,
    chunk_len_longest: u64 = 0,
    delayed: bool = false,
    accepts_since_feed: u32 = 0,
    two_values_in_one_chunk: bool = false,

    fn read(reading: *Reading, text: []const u8) !void {
        reading.fed = 0;
        reading.consumed = 0;
        reading.at_ns = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        for (0..text.len) |_| {
            const line = lines.next() orelse return;
            if (std.mem.startsWith(u8, line, "feed ")) try reading.feed(line);
            if (std.mem.startsWith(u8, line, "accept ")) try reading.accept(line);
        }
    }

    fn feed(reading: *Reading, line: []const u8) !void {
        const len = try field(line, "len");
        const at_ns = try field(line, "at_ns");
        try testing.expect(at_ns >= reading.at_ns);
        try testing.expect(at_ns - reading.at_ns <= constants.chunk_delay_ns_max);
        reading.delayed = reading.delayed or at_ns > reading.at_ns;
        reading.at_ns = at_ns;
        try testing.expect(len >= 1 and len <= constants.chunk_len_max);
        reading.chunk_len_longest = @max(reading.chunk_len_longest, len);
        reading.fed += len;
        reading.cuts[reading.fed] = true;
        try testing.expectEqual(reading.fed - reading.consumed, try field(line, "held"));
        reading.accepts_since_feed = 0;
    }

    fn accept(reading: *Reading, line: []const u8) !void {
        try testing.expectEqual(reading.consumed, try field(line, "offset"));
        reading.consumed += try field(line, "len");
        reading.accepts_since_feed += 1;
        reading.two_values_in_one_chunk = reading.two_values_in_one_chunk or
            reading.accepts_since_feed >= values_in_one_chunk;
    }

    fn field(line: []const u8, key: []const u8) !u64 {
        var fields = std.mem.splitScalar(u8, line, ' ');
        for (0..line.len) |_| {
            const piece = fields.next() orelse return error.TestUnexpectedResult;
            if (piece.len > key.len and std.mem.startsWith(u8, piece, key) and piece[key.len] == '=') {
                return std.fmt.parseInt(u64, piece[key.len + 1 ..], decimal_radix);
            }
        }
        return error.TestUnexpectedResult;
    }
};

test "seeds cut at every boundary, reach the longest chunk, delay, and hold what they say" {
    var reading: Reading = .{};
    for (0..constants.check_seeds_default) |seed| {
        var random = Random.init(seed);
        var seeded: TestRun = .{};
        try seeded.start(repeated_values, .{ .seeded = &random }, seed);
        try testing.expectEqual(.pass, seeded.outcome);
        try reading.read(seeded.text());
        try testing.expectEqual(repeated_values.len, reading.fed);
    }
    for (reading.cuts[1..]) |cut| try testing.expect(cut);
    try testing.expectEqual(constants.chunk_len_max, reading.chunk_len_longest);
    try testing.expect(reading.delayed);
    try testing.expect(reading.two_values_in_one_chunk);
}
