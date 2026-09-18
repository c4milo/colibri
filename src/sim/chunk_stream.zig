//! The stream the chunk check feeds (design §8 step 2) and the subject that decodes it with the
//! step 1 decoders of `wire`.
//!
//! A seed draws a `Plan`: 1 to `chunk_check_values_max` values, each a QUIC variable-length
//! integer, a prefixed integer or a string literal, with the prefix size, high bits, coding and
//! value drawn too. One seed in `chunk_check_refusal_one_in` then appends one encoding the decoders
//! refuse. `write` encodes the plan into a stream, and `Subject` decodes the stream in plan order,
//! the way a protocol parser knows which field comes next.
//!
//! A decoder that finds too few octets returns `error.Truncated` and consumes nothing, which the
//! subject reports as `need_more`. Every other error is a refusal.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const sim = @import("sim");

const Reader = core.Reader;
const Writer = core.Writer;
const Random = sim.Random;
const constants = sim.constants;
const wire_constants = wire.constants;

pub const Format = enum { varint, prefixed_integer, string_literal };

/// The encodings a seed can append after its values, each refused by a step 1 decoder.
pub const Refusal = enum {
    /// A prefixed integer whose continuation octets run past `integer_len_max`.
    integer_too_long,
    /// A Huffman string literal whose data holds EOS.
    huffman_eos_in_data,
    /// A Huffman string literal whose padding is not the high bits of EOS.
    huffman_padding_not_eos,
};

pub const Value = struct {
    format: Format,
    /// A varint's encoded length, which may be longer than its value needs (RFC 9000 §16).
    encoded_len: u8 = 0,
    prefix_size: u4 = 0,
    high_bits: u8 = 0,
    integer: u64 = 0,
    coding: wire.string_literal.Coding = .raw,
    text: [constants.chunk_check_text_len_max]u8 = @splat(0),
    text_len: u8 = 0,
};

pub const Plan = struct {
    values: [constants.chunk_check_values_max]Value,
    count: u32,
    refusal: ?Refusal,

    /// Draws a plan from `random`.
    pub fn draw(random: *Random) Plan {
        var plan: Plan = .{
            .values = @splat(.{ .format = .varint }),
            .count = @intCast(random.between(1, constants.chunk_check_values_max)),
            .refusal = null,
        };
        for (plan.values[0..plan.count]) |*value| value.* = draw_value(random);
        if (random.below(constants.chunk_check_refusal_one_in) == 0) {
            const refusals = std.enums.values(Refusal);
            plan.refusal = refusals[random.below(refusals.len)];
        }
        assert(plan.count >= 1 and plan.count <= constants.chunk_check_values_max);
        return plan;
    }

    /// Encodes every value, then the refusal, into `output`.
    pub fn write(plan: *const Plan, output: *Writer) core.writer.Error!void {
        for (plan.values[0..plan.count]) |*value| try write_value(value, output);
        if (plan.refusal) |refusal| try write_refusal(refusal, output);
    }
};

fn draw_value(random: *Random) Value {
    const formats = std.enums.values(Format);
    var value: Value = .{ .format = formats[random.below(formats.len)] };
    switch (value.format) {
        .varint => {
            const lens = wire_constants.varint_lens;
            value.encoded_len = lens[random.below(lens.len)];
            value.integer = random.between(0, varint_value_max(value.encoded_len));
        },
        .prefixed_integer => {
            value.prefix_size = draw_prefix_size(random, wire_constants.integer_prefix_bits_min);
            value.high_bits = draw_high_bits(random, value.prefix_size);
            value.integer = draw_integer(random);
        },
        .string_literal => {
            value.prefix_size = draw_prefix_size(random, wire_constants.string_prefix_bits_min);
            value.high_bits = draw_high_bits(random, value.prefix_size);
            const codings = std.enums.values(wire.string_literal.Coding);
            value.coding = codings[random.below(codings.len)];
            value.text_len = @intCast(random.between(0, constants.chunk_check_text_len_max));
            for (value.text[0..value.text_len]) |*octet| octet.* = @truncate(random.next());
        },
    }
    return value;
}

fn draw_prefix_size(random: *Random, min: u4) u4 {
    return @intCast(random.between(min, wire_constants.integer_prefix_bits_max));
}

/// Octet bits above the prefix, drawn: the bits a representation's type flags would occupy.
fn draw_high_bits(random: *Random, prefix_size: u4) u8 {
    const prefix_mask: u8 = @intCast((@as(u16, 1) << prefix_size) - 1);
    const drawn: u8 = @truncate(random.next());
    return drawn & ~prefix_mask;
}

/// A value of a drawn bit width from 0 to 62, so short and long encodings are both common.
fn draw_integer(random: *Random) u64 {
    const width_max = @bitSizeOf(u64) - @clz(wire_constants.integer_value_max);
    const width = random.between(0, width_max);
    if (width == 0) return 0;
    return random.next() >> @intCast(@bitSizeOf(u64) - width);
}

/// The largest value `encoded_len` octets of a QUIC variable-length integer carry (RFC 9000 §16).
fn varint_value_max(encoded_len: u8) u64 {
    const value_bits = @as(u8, @bitSizeOf(u8)) * encoded_len - wire_constants.varint_length_bits;
    return (@as(u64, 1) << @intCast(value_bits)) - 1;
}

fn write_value(value: *const Value, output: *Writer) core.writer.Error!void {
    switch (value.format) {
        .varint => try wire.varint.encode_with_len(output, value.integer, value.encoded_len),
        .prefixed_integer => switch (value.prefix_size) {
            inline wire_constants.integer_prefix_bits_min...wire_constants.integer_prefix_bits_max,
            => |size| try wire.prefixed_integer.encode(
                size,
                output,
                value.high_bits,
                value.integer,
            ),
            else => unreachable,
        },
        .string_literal => switch (value.prefix_size) {
            inline wire_constants.string_prefix_bits_min...wire_constants.integer_prefix_bits_max,
            => |size| try wire.string_literal.encode(
                size,
                output,
                value.high_bits,
                value.text[0..value.text_len],
                value.coding,
            ),
            else => unreachable,
        },
    }
}

/// The continuation flag of a prefixed integer's octet, and the H flag of a string literal at
/// prefix size 8 (RFC 7541 §5.1, §5.2).
const continuation_flag = 0x80;
const huffman_flag = 0x80;

/// Octets of all-ones Huffman data: 32 bits, which hold the 30-bit EOS code (RFC 7541 Appendix B).
const eos_data_len = 4;

/// The octets of each refusal, all at prefix size 8. The integer's first octet has every prefix
/// bit set, and every continuation octet `integer_len_max` allows keeps the continuation flag, so
/// no octet ends it. The Huffman literals set H and give their data length: data holding EOS, and
/// one zero octet, whose five-bit `0` code leaves three zero bits of padding.
const integer_too_long = [_]u8{std.math.maxInt(u8)} ++
    [_]u8{continuation_flag} ** (wire_constants.integer_len_max - 1);
const huffman_eos_in_data = [_]u8{huffman_flag | eos_data_len} ++
    [_]u8{std.math.maxInt(u8)} ** eos_data_len;
const huffman_padding_not_eos = [_]u8{ huffman_flag | 1, 0 };

fn write_refusal(refusal: Refusal, output: *Writer) core.writer.Error!void {
    try output.write_bytes(switch (refusal) {
        .integer_too_long => &integer_too_long,
        .huffman_eos_in_data => &huffman_eos_in_data,
        .huffman_padding_not_eos => &huffman_padding_not_eos,
    });
}

/// The prefix size every refusal is decoded at.
const refusal_prefix_size = wire_constants.integer_prefix_bits_max;

/// Decodes a plan's stream in plan order, for `sim.pipe.run`.
pub const Subject = struct {
    plan: *const Plan,
    /// The values accepted so far; the next one is `plan.values[accepted]`.
    accepted: u32 = 0,
    last: Value = .{ .format = .varint },
    decoded: [constants.chunk_check_text_len_max]u8 = @splat(0),

    pub fn step(subject: *Subject, held: []const u8) sim.pipe.Step {
        var reader = Reader.init(held);
        const result = if (subject.accepted < subject.plan.count)
            subject.decode_value(&subject.plan.values[subject.accepted], &reader)
        else
            decode_refusal(&reader);
        result catch |failure| switch (failure) {
            error.Truncated => return .need_more,
            else => return .{ .reject = failure },
        };
        assert(reader.offset > 0);
        subject.accepted += 1;
        return .{ .accept = reader.offset };
    }

    pub fn describe(subject: *const Subject, line: *sim.trace.Record) sim.trace.Error!void {
        const value = &subject.last;
        try line.word("format", @tagName(value.format));
        if (value.format != .varint) try line.number("prefix_size", value.prefix_size);
        switch (value.format) {
            .varint, .prefixed_integer => try line.number("value", value.integer),
            .string_literal => {
                try line.word("coding", @tagName(value.coding));
                try line.octets("text", value.text[0..value.text_len]);
            },
        }
    }

    fn decode_value(subject: *Subject, planned: *const Value, reader: *Reader) anyerror!void {
        subject.last = .{ .format = planned.format, .prefix_size = planned.prefix_size };
        switch (planned.format) {
            .varint => subject.last.integer = (try wire.varint.decode(reader)).value,
            .prefixed_integer => {
                subject.last.integer = try decode_integer(planned.prefix_size, reader);
            },
            .string_literal => try subject.decode_string(planned.prefix_size, reader),
        }
    }

    fn decode_string(subject: *Subject, prefix_size: u4, reader: *Reader) anyerror!void {
        var output = Writer.init(&subject.decoded);
        const decoded = switch (prefix_size) {
            inline wire_constants.string_prefix_bits_min...wire_constants.integer_prefix_bits_max,
            => |size| try wire.string_literal.decode(size, reader, &output),
            else => unreachable,
        };
        subject.last.coding = decoded.coding;
        subject.last.text_len = @intCast(output.offset);
        @memcpy(subject.last.text[0..output.offset], output.written());
    }
};

fn decode_integer(prefix_size: u4, reader: *Reader) anyerror!u64 {
    return switch (prefix_size) {
        inline wire_constants.integer_prefix_bits_min...wire_constants.integer_prefix_bits_max,
        => |size| try wire.prefixed_integer.decode(size, reader),
        else => unreachable,
    };
}

/// A refusal is either a prefixed integer or a string literal, told apart by its first octet: the
/// integer's low bits are all set, which no refusal literal's length is.
fn decode_refusal(reader: *Reader) anyerror!void {
    const first = try reader.peek_byte();
    if (first == std.math.maxInt(u8)) {
        _ = try decode_integer(refusal_prefix_size, reader);
        return;
    }
    var buffer: [constants.chunk_check_text_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    _ = try wire.string_literal.decode(refusal_prefix_size, reader, &output);
}

comptime {
    // The longest value: a Huffman literal of the longest text at 30 bits a symbol, after a
    // length prefix of at most two octets at the smallest prefix.
    const huffman_len_max = std.math.divCeil(
        u32,
        constants.chunk_check_text_len_max * wire_constants.huffman_code_bits_max,
        @bitSizeOf(u8),
    ) catch unreachable;
    assert(huffman_len_max + wire_constants.integer_len_max <= constants.chunk_check_value_len_max);
    assert(integer_too_long.len <= constants.chunk_check_value_len_max);
}

const testing = std.testing;

fn expect_refused(refusal: Refusal, expected: anyerror) !void {
    var buffer: [constants.chunk_check_value_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try write_refusal(refusal, &output);
    var reader = Reader.init(output.written());
    try testing.expectError(expected, decode_refusal(&reader));
    // One octet short, the same encoding is only truncated.
    var short = Reader.init(output.written()[0 .. output.offset - 1]);
    try testing.expectError(error.Truncated, decode_refusal(&short));
}

test "each refusal is refused by its decoder, and is only truncated one octet short" {
    try expect_refused(.integer_too_long, error.IntegerTooLong);
    try expect_refused(.huffman_eos_in_data, error.HuffmanEosInData);
    try expect_refused(.huffman_padding_not_eos, error.HuffmanPaddingNotEos);
}

test "a drawn plan's stream decodes in one piece to the values drawn" {
    for (0..constants.check_seeds_default) |seed| {
        var random = Random.init(seed);
        const plan = Plan.draw(&random);
        var buffer: [constants.chunk_check_stream_len_max]u8 = @splat(0);
        var output = Writer.init(&buffer);
        try plan.write(&output);
        var subject: Subject = .{ .plan = &plan };
        var held = output.written();
        for (plan.values[0..plan.count]) |*planned| {
            const len = subject.step(held).accept;
            try testing.expectEqual(planned.format, subject.last.format);
            try testing.expectEqual(planned.integer, subject.last.integer);
            try testing.expectEqualSlices(
                u8,
                planned.text[0..planned.text_len],
                subject.last.text[0..subject.last.text_len],
            );
            held = held[len..];
        }
        if (plan.refusal == null) try testing.expectEqual(0, held.len);
        if (plan.refusal != null) try testing.expect(subject.step(held) == .reject);
    }
}
