//! The Huffman decoder of `huffman.zig`, which reads twelve bits at a time. Split from
//! `huffman.zig` for length.
//!
//! The decoder holds the next bits of input in a 64-bit buffer, the oldest at the top, and moves
//! up to eight octets into it at a time. A comptime table, `window`, gives for each value of the
//! top twelve bits the symbols whose codes those bits hold whole, and the bits the codes take. The
//! shortest code is five bits, so twelve bits hold two codes at most. A code longer than twelve
//! bits is read one bit at a time, through `huffman.Partial`.
//!
//! A read of the table writes two octets, and the second is scratch when one code is whole. When
//! the output has room for the most octets the input can decode to, and one more, a read writes
//! into that room with no check of its own. Otherwise each symbol goes through the writer's
//! checked `write_byte`.
//!
//! The three errors keep their order (invariant 7). EOS is thirty bits, longer than the window, so
//! the read of a long code finds it when its last bit is read. The two padding checks read the bits
//! that are left when the input ends.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const huffman = @import("huffman.zig");

const Writer = core.Writer;
const DecodeError = huffman.DecodeError;

/// The bits one read of the table takes, and the values they can hold.
const window_bits = 12;
const window_len = 1 << window_bits;
const Index = std.meta.Int(.unsigned, window_bits);

/// The input bits the decoder holds, and the octets one refill reads.
const Bits = u64;
const Shift = std.math.Log2Int(Bits);
const refill_octets = @sizeOf(Bits);

/// The most codes the window holds whole: the symbols one read writes.
const read_symbols_max = 2;

comptime {
    // Twelve bits hold two codes at most, so an entry holds two symbols.
    assert((read_symbols_max + 1) * constants.protocol.huffman_code_bits_min > window_bits);
    // EOS never fits in the window, so only the read of a long code finds it.
    assert(constants.protocol.huffman_code_bits_max > window_bits);
    // A refill leaves fewer than eight bits free, which holds the longest code.
    assert(@bitSizeOf(Bits) - (@bitSizeOf(u8) - 1) >= constants.protocol.huffman_code_bits_max);
}

/// What one read of the table completes.
const Entry = packed struct(u32) {
    /// The first symbol, and the second, which is scratch when `count` is 1.
    first: u8,
    second: u8,
    /// The bits of the codes `count` names, or `long` when the first code is longer than the
    /// window.
    bits: u8,
    /// The codes the window holds whole: 0, 1 or 2.
    count: u2,
    /// The bits of the first code.
    first_bits: u4,
    unused: u2 = 0,
};

/// `Entry.bits` for a first code longer than the window. It is more than the buffer holds, so the
/// one check of a read sends it to the slow path.
const long: u8 = std.math.maxInt(u8);

comptime {
    assert(long > @bitSizeOf(Bits));
    assert(window_bits <= std.math.maxInt(u4));
}

const window: [window_len]Entry = build_window();

/// Branches the comptime build may take: 4,096 values of twelve bits each, with room to spare.
const window_eval_branch_quota = 1_000_000;

fn build_window() [window_len]Entry {
    @setEvalBranchQuota(window_eval_branch_quota);
    var result: [window_len]Entry = undefined;
    for (&result, 0..) |*entry, value| {
        entry.* = .{ .first = 0, .second = 0, .bits = long, .count = 0, .first_bits = 0 };
        var partial: huffman.Partial = .{};
        for (0..window_bits) |index| {
            const bit: u1 = @truncate(value >> @intCast(window_bits - 1 - index));
            const symbol = partial.push(bit) orelse continue;
            assert(symbol != constants.protocol.huffman_eos_symbol);
            if (entry.count == 0) {
                entry.first = @intCast(symbol);
                entry.first_bits = @intCast(index + 1);
            } else {
                entry.second = @intCast(symbol);
            }
            entry.count += 1;
            entry.bits = @intCast(index + 1);
        }
        // A read takes five bits or more, which bounds the reads of the decoder's loop.
        assert(entry.bits >= constants.protocol.huffman_code_bits_min);
    }
    return result;
}

/// Decodes all of `encoded` into `output`, as `huffman.decode` does.
pub fn decode(encoded: []const u8, output: *Writer) DecodeError!void {
    // A read writes two octets: room for the most symbols the input holds, and one octet more.
    const room_len = huffman.decoded_len_max(encoded.len) + 1;
    if (output.writable_slice_greedy(room_len)) |free| {
        var room: Room = .{ .free = free.ptr };
        try read(Room, &room, encoded);
        assert(room.count < room_len);
        output.advance(room.count);
    } else |_| {
        try decode_checked(encoded, output);
    }
}

/// `decode` when the room is short. Out of line, so the common path keeps its registers.
noinline fn decode_checked(encoded: []const u8, output: *Writer) DecodeError!void {
    var checked: Checked = .{ .cursor = output.* };
    try read(Checked, &checked, encoded);
    output.* = checked.cursor;
}

/// Where the symbols go when the room holds every one the input can decode to, and one octet
/// more. `decode` checked that room once, so a write here checks nothing.
const Room = struct {
    free: [*]u8,
    count: usize = 0,

    inline fn write_entry(room: *Room, entry: Entry) Writer.Error!void {
        // `first` is the low octet of the entry and `second` the next, so one store of sixteen
        // bits, least significant first, writes both in order.
        const pair: u16 = @truncate(@as(u32, @bitCast(entry)));
        std.mem.writeInt(u16, room.free[room.count..][0..read_symbols_max], pair, .little);
        room.count +%= entry.count;
    }

    inline fn write_symbol(room: *Room, symbol: u8) Writer.Error!void {
        room.free[room.count] = symbol;
        room.count +%= 1;
    }
};

/// Where the symbols go otherwise: through the checked writes of a copy of the writer.
const Checked = struct {
    cursor: Writer,

    inline fn write_entry(checked: *Checked, entry: Entry) Writer.Error!void {
        try checked.cursor.write_byte(entry.first);
        if (entry.count == read_symbols_max) try checked.cursor.write_byte(entry.second);
    }

    inline fn write_symbol(checked: *Checked, symbol: u8) Writer.Error!void {
        try checked.cursor.write_byte(symbol);
    }
};

/// Decodes all of `encoded` into `sink`, a `Room` or a `Checked`.
inline fn read(comptime Sink: type, sink: *Sink, encoded: []const u8) DecodeError!void {
    var input: Input = .{ .encoded = encoded };
    input.refill();
    // Each pass after the reads below writes a symbol, moves an octet or more into the buffer, or
    // ends the input.
    const passes_max = huffman.decoded_len_max(encoded.len) + encoded.len + 1;
    const ended = for (0..passes_max) |_| {
        var entry = window[input.top()];
        // Each read takes five bits or more of the fewer than 64 held, so the reads end.
        while (entry.bits <= input.available) : (entry = window[input.top()]) {
            try sink.write_entry(entry);
            input.consume(entry.bits);
        }
        if (entry.count == 0) {
            @branchHint(.unlikely);
            const long_read = try read_long_code(input);
            input = long_read.input;
            try sink.write_symbol(long_read.symbol orelse break true);
            continue;
        }
        if (input.position < encoded.len) {
            input.refill();
            continue;
        }
        // The input has ended, and the window holds fewer bits than its codes take.
        if (entry.first_bits > input.available) break true;
        try sink.write_symbol(entry.first);
        input.consume(entry.first_bits);
    } else false;
    assert(ended);
    // RFC 7541 §5.2: padding strictly longer than 7 bits is a decoding error.
    if (input.available > constants.protocol.huffman_padding_bits_max) return error.HuffmanPaddingTooLong;
    // RFC 7541 §5.2: padding that is not the most significant bits of EOS is a decoding error.
    if (!input.left_all_ones()) return error.HuffmanPaddingNotEos;
}

/// The input, and the bits of it the decoder holds.
const Input = struct {
    encoded: []const u8,
    /// The next bits of input, the oldest at the top. The bits past `available` are 0, or input
    /// that a later refill counts again.
    bits: Bits = 0,
    /// The top bits of `bits` that are input not yet read. Fewer than 64.
    available: u32 = 0,
    /// The octets of `encoded` counted in `available` or read.
    position: usize = 0,

    /// The value of the top bits, which indexes `window`.
    inline fn top(input: *const Input) Index {
        return @truncate(input.bits >> (@bitSizeOf(Bits) - window_bits));
    }

    /// Reads `bit_count` bits, which the caller found in `available`.
    inline fn consume(input: *Input, bit_count: u32) void {
        // `bit_count` is at most the longest code, so the shift is less than 64.
        input.bits <<= @as(Shift, @truncate(bit_count));
        input.available -%= bit_count;
    }

    /// Moves whole octets of input into `bits`, until fewer than eight bits are free or the input
    /// ends.
    inline fn refill(input: *Input) void {
        const left = input.encoded.len - input.position;
        const word: Bits = if (left >= refill_octets)
            std.mem.readInt(Bits, input.encoded[input.position..][0..refill_octets], .big)
        else if (input.encoded.len >= refill_octets and left > 0)
            last_word(input.encoded, left)
        else
            short_word(input.encoded[input.position..]);
        input.bits |= word >> @as(Shift, @truncate(input.available));
        const taken = @min((@bitSizeOf(Bits) - 1 - input.available) / @bitSizeOf(u8), left);
        input.position += taken;
        input.available += @intCast(taken * @bitSizeOf(u8));
        assert(input.available < @bitSizeOf(Bits));
    }

    /// Whether every bit left is 1: the most significant bits of EOS.
    fn left_all_ones(input: *const Input) bool {
        assert(input.available <= constants.protocol.huffman_padding_bits_max);
        const ones = ~(~@as(Bits, 0) >> @as(Shift, @truncate(input.available)));
        return input.bits & ones == ones;
    }
};

/// What the read of a long code leaves: the input after it, and its symbol, or null when the input
/// ends inside the code, which leaves its bits to the padding checks.
const LongRead = struct {
    input: Input,
    symbol: ?u8,
};

/// Reads a code longer than the window one bit at a time. The input goes in and out by value, so
/// the decoder's loop keeps it in registers: a long code is rare, and the call costs only it.
noinline fn read_long_code(start: Input) DecodeError!LongRead {
    var input = start;
    if (input.position < input.encoded.len) input.refill();
    var partial: huffman.Partial = .{};
    // Bounded by the bits held: unless the input has ended, they hold the longest code.
    for (0..input.available) |index| {
        const bit: u1 = @truncate(input.bits >> @as(Shift, @truncate(@bitSizeOf(Bits) - 1 - index)));
        const symbol = partial.push(bit) orelse continue;
        // RFC 7541 §5.2: a Huffman-encoded string literal containing EOS is a decoding error.
        if (symbol == constants.protocol.huffman_eos_symbol) return error.HuffmanEosInData;
        input.consume(@intCast(index + 1));
        return .{ .input = input, .symbol = @intCast(symbol) };
    }
    return .{ .input = input, .symbol = null };
}

/// The last eight octets of `encoded`, moved up so that its `left` unread octets are at the top.
fn last_word(encoded: []const u8, left: usize) Bits {
    assert(left > 0 and left < refill_octets and encoded.len >= refill_octets);
    const word = std.mem.readInt(Bits, encoded[encoded.len - refill_octets ..][0..refill_octets], .big);
    return word << @as(Shift, @truncate((refill_octets - left) * @bitSizeOf(u8)));
}

/// The octets of `rest`, fewer than eight, at the top of a word.
fn short_word(rest: []const u8) Bits {
    assert(rest.len < refill_octets);
    var word: Bits = 0;
    for (rest, 0..) |octet, index| {
        word |= @as(Bits, octet) << @as(Shift, @truncate((refill_octets - 1 - index) * @bitSizeOf(u8)));
    }
    return word;
}

const testing = std.testing;
const table = @import("huffman_table.zig");

test "RFC 7541 Appendix B: a read completes both codes when the window holds two, and none when the first is long" {
    for (table.codes[0 .. std.math.maxInt(u8) + 1], 0..) |first, first_symbol| {
        // The first code at the top of the window.
        if (first.bit_count > window_bits) {
            const top_bits: Index = @truncate(first.code >> @intCast(first.bit_count - window_bits));
            try testing.expectEqual(0, window[top_bits].count);
            try testing.expectEqual(long, window[top_bits].bits);
            continue;
        }
        const first_value: u32 = first.code << @intCast(window_bits - first.bit_count);
        for (table.codes[0 .. std.math.maxInt(u8) + 1], 0..) |second, second_symbol| {
            if (first.bit_count + second.bit_count > window_bits) continue;
            const value: Index = @intCast(first_value | second.code << @intCast(window_bits - first.bit_count - second.bit_count));
            const entry = window[value];
            try testing.expectEqual(read_symbols_max, entry.count);
            try testing.expectEqual(first_symbol, entry.first);
            try testing.expectEqual(second_symbol, entry.second);
            try testing.expectEqual(first.bit_count, entry.first_bits);
            try testing.expectEqual(first.bit_count + second.bit_count, entry.bits);
        }
    }
}

test {
    _ = @import("huffman_decode_test.zig");
}
