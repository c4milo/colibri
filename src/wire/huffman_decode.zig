//! The Huffman decoder of `huffman.zig`, four bits a step. Split from `huffman.zig` for length.
//!
//! The code of RFC 7541 Appendix B is a binary tree with 257 leaves and 256 internal nodes. Each
//! internal node is a state: the bits read since the last symbol. A comptime table gives, for each
//! state and each four bits that follow, the state they end in and the symbol they complete, if
//! any. The shortest code is five bits, so four bits complete one symbol at most. The table holds
//! what `huffman.decode_by_bits` works out one bit at a time, and the tests compare the two.
//!
//! The three errors keep their order (invariant 7). An EOS symbol is found when its last bit is
//! read, inside the loop, and the two padding checks read the final state's depth and whether its
//! bits are all ones.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const table = @import("huffman_table.zig");
const huffman = @import("huffman.zig");

const Writer = core.Writer;
const DecodeError = huffman.DecodeError;

/// The bits one step reads, and the values they can take.
const step_bits = 4;
const step_values = 1 << step_bits;
const step_mask: u8 = step_values - 1;

/// Internal nodes of the code tree: one fewer than its leaves. The root, state 0, is where each
/// symbol starts.
const state_count = constants.protocol.huffman_symbol_count - 1;
const State = u8;
const root: State = 0;

comptime {
    assert(state_count == std.math.maxInt(State) + 1);
    // Four bits complete one symbol at most.
    assert(constants.protocol.huffman_code_bits_min > step_bits);
    assert(@bitSizeOf(u8) % step_bits == 0);
}

/// What one step does from a state.
const Step = struct {
    /// The state the step's bits end in.
    next: State,
    /// The symbol they complete, when `emits`.
    symbol: u8,
    emits: bool,
    /// The bits complete EOS, which RFC 7541 §5.2 refuses inside the data.
    eos: bool,
};

/// The machine: each state's steps, its depth in bits, and whether every bit since the last symbol
/// is set, which the padding checks read.
const Machine = struct {
    steps: [state_count][step_values]Step,
    depth: [state_count]u8,
    all_ones: [state_count]bool,
};

const machine: Machine = build_machine();

/// Branches the comptime build may take: a tree of 257 codes of up to thirty bits, and 4,096 steps
/// of four bits each, with room to spare.
const machine_eval_branch_quota = 400_000;

/// The children of each internal node: one for a 0 bit and one for a 1 bit.
const branches = 2;

/// A child in the tree: an internal node, or a leaf that holds a symbol.
const Child = union(enum) { node: u16, leaf: u16, none };

fn build_machine() Machine {
    @setEvalBranchQuota(machine_eval_branch_quota);
    var children: [state_count][branches]Child = @splat(.{ .none, .none });
    var result: Machine = .{ .steps = undefined, .depth = @splat(0), .all_ones = @splat(true) };
    var nodes: u16 = 1;
    for (table.codes, 0..) |row, symbol| {
        var node: u16 = root;
        for (0..row.bit_count) |index| {
            const bit: u1 = @truncate(row.code >> @intCast(row.bit_count - 1 - index));
            if (index + 1 == row.bit_count) {
                assert(children[node][bit] == .none);
                children[node][bit] = .{ .leaf = @intCast(symbol) };
                break;
            }
            if (children[node][bit] == .none) {
                children[node][bit] = .{ .node = nodes };
                result.depth[nodes] = result.depth[node] + 1;
                result.all_ones[nodes] = result.all_ones[node] and bit == 1;
                nodes += 1;
            }
            node = children[node][bit].node;
        }
    }
    // Kraft equality: every internal node was made, and each has two children.
    assert(nodes == state_count);
    for (&result.steps, 0..) |*steps, state| {
        for (steps, 0..) |*entry, value| entry.* = walk(&children, @intCast(state), @intCast(value));
    }
    return result;
}

/// The step from `state` over the four bits of `value`, most significant first.
fn walk(children: *const [state_count][branches]Child, state: State, value: u8) Step {
    var result: Step = .{ .next = state, .symbol = 0, .emits = false, .eos = false };
    var node: u16 = state;
    for (0..step_bits) |index| {
        const bit: u1 = @truncate(value >> @intCast(step_bits - 1 - index));
        switch (children[node][bit]) {
            .node => |child| node = child,
            .leaf => |symbol| {
                if (symbol == constants.protocol.huffman_eos_symbol) {
                    result.eos = true;
                    return result;
                }
                result.symbol = @intCast(symbol);
                result.emits = true;
                node = root;
            },
            .none => unreachable,
        }
    }
    result.next = @intCast(node);
    return result;
}

/// Decodes all of `encoded` into `output`, as `huffman.decode` does.
pub fn decode(encoded: []const u8, output: *Writer) DecodeError!void {
    var cursor = output.*;
    var state: State = root;
    for (encoded) |octet| {
        state = try step(state, octet >> step_bits, &cursor);
        state = try step(state, octet & step_mask, &cursor);
    }
    // RFC 7541 §5.2: padding strictly longer than 7 bits is a decoding error.
    if (machine.depth[state] > constants.protocol.huffman_padding_bits_max) return error.HuffmanPaddingTooLong;
    // RFC 7541 §5.2: padding that is not the most significant bits of EOS is a decoding error.
    if (!machine.all_ones[state]) return error.HuffmanPaddingNotEos;
    output.* = cursor;
}

/// One step of four bits from `state`, which writes the symbol it completes.
inline fn step(state: State, value: u8, cursor: *Writer) DecodeError!State {
    const next = machine.steps[state][value];
    // RFC 7541 §5.2: a Huffman-encoded string literal containing EOS is a decoding error.
    if (next.eos) return error.HuffmanEosInData;
    if (next.emits) try cursor.write_byte(next.symbol);
    return next.next;
}

test {
    _ = @import("huffman_decode_test.zig");
}
