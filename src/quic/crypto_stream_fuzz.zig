//! The fuzz property of the CRYPTO window (decision 29), and the sweep that runs it over every
//! input of up to two octets. The input is a script of frames and reads. The property runs it on a
//! `CryptoStream` and on a model that keeps every offset of the flow with a bit for each octet that
//! arrived, and after each step the window must read what the model reads. Everything in this
//! file is test-only.
const std = @import("std");
const core = @import("core");
const constants = @import("constants.zig");
const crypto_stream = @import("crypto_stream.zig");

const Smith = std.testing.Smith;
const testing = std.testing;

/// One step of the script: a kind octet and two octets of an offset or a count.
const step_octets = 3;
const steps_max = 48;
const fuzz_input_len = step_octets * steps_max;
/// The most octets one frame of the script carries.
const frame_len_max = 128;
/// How far past the base a frame may start, so that some frames end past the window, and how far
/// below it, so that some carry octets already read.
const reach_past = constants.crypto_buffer_len + frame_len_max;
const reach_below = frame_len_max;
/// The flow the model keeps: enough for every step to read a whole window.
const flow_len = steps_max * (constants.crypto_buffer_len + frame_len_max);

var fuzz_stream: crypto_stream.CryptoStream align(@alignOf(crypto_stream.CryptoStream)) = undefined;
const ModelPresent = std.StaticBitSet(flow_len);
var model_present: ModelPresent align(@alignOf(ModelPresent)) = .initEmpty();
var frame_octets: [frame_len_max]u8 = undefined;

/// The octet at `offset` of the peer's flow, so that the model needs no copy of what was sent.
fn octet_at(offset: u64) u8 {
    return @truncate(offset *% octet_stride +% octet_start);
}
const octet_stride: u64 = 7;
const octet_start: u64 = 3;

fn fuzz_window(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len]u8 = @splat(0);
    const len = smith.slice(&input);
    fuzz_stream.init();
    model_present = .initEmpty();
    var base: u64 = 0;
    var index: usize = 0;
    // Bounded by the input, which holds at most `steps_max` steps.
    while (index + step_octets <= len) : (index += step_octets) {
        const step = input[index..][0..step_octets];
        const amount = std.mem.readInt(u16, step[1..step_octets], .little);
        if (step[0] & 1 == 0) {
            try receive(base, step[0] >> 1, amount);
        } else {
            const read = amount % (fuzz_stream.readable().len + 1);
            fuzz_stream.consume(read);
            base += read;
        }
        try expect_model(base);
    }
}

/// Delivers one frame to the window and to the model.
fn receive(base: u64, len_input: u8, start_input: u16) !void {
    const start = (base + start_input % (reach_past + reach_below)) -| reach_below;
    const len = len_input % frame_len_max;
    for (frame_octets[0..len], 0..) |*octet, index| octet.* = octet_at(start + index);
    const end = start + len;
    fuzz_stream.receive(start, frame_octets[0..len]) catch |failure| {
        // RFC 9000 §7.5: past the window is CRYPTO_BUFFER_EXCEEDED, and nothing else is refused.
        try testing.expectEqual(error.CryptoBufferExceeded, failure);
        try testing.expect(len > 0 and end > base and end > base + constants.crypto_buffer_len);
        return;
    };
    try testing.expect(len == 0 or end <= base or end <= base + constants.crypto_buffer_len);
    if (len == 0 or end <= base) return;
    model_present.setRangeValue(.{ .start = @intCast(@max(start, base)), .end = @intCast(end) }, true);
}

/// The window reads the octets from `base` up to the model's first gap, and no more.
fn expect_model(base: u64) !void {
    try testing.expectEqual(base, fuzz_stream.consumed_len());
    var run: usize = 0;
    // Bounded by the window.
    while (run < constants.crypto_buffer_len and model_present.isSet(@intCast(base + run))) run += 1;
    const readable = fuzz_stream.readable();
    try testing.expectEqual(run, readable.len);
    for (readable, 0..) |octet, index| try testing.expectEqual(octet_at(base + index), octet);
}

test "fuzz: the CRYPTO window reads what a model of the whole flow reads, step by step" {
    try testing.fuzz({}, fuzz_window, .{
        .corpus = &.{
            // A frame past a gap, the gap filled, and a read of all of it.
            core.fuzz.input("\x14\x8a\x00" ++ "\x14\x80\x00" ++ "\x01\xff\xff"),
            // A read that leaves octets past a gap, then a frame at the window's far end, which
            // moves them down.
            core.fuzz.input("\x10\x80\x00" ++ "\x10\x90\x00" ++ "\x01\x04\x00" ++ "\x02\x7f\x10" ++ "\x7e\x84\x00"),
            // A frame past the window, and one that carries octets already read.
            core.fuzz.input("\x0a\xff\x10" ++ "\x08\x80\x00" ++ "\x01\x08\x00" ++ "\x10\x00\x00"),
        },
    });
    try core.fuzz.sweep(fuzz_window, null);
}

test "the CRYPTO window property holds over a long script of every kind of step" {
    // The sweep runs scripts of no step, so this pass runs scripts that the octets of a counter
    // build: each step depends on the step count and on the steps before it.
    var input: [fuzz_input_len]u8 = undefined;
    for (0..script_count) |script| {
        for (&input, 0..) |*octet, index| octet.* = @truncate((index + 1) *% (script + 1) *% 2654435761 >> 7);
        var entry: [length_octets + fuzz_input_len]u8 = undefined;
        // `Smith` reads a slice's length as 4 octets, little-endian (`core.fuzz`).
        std.mem.writeInt(u32, entry[0..length_octets], fuzz_input_len, .little);
        @memcpy(entry[length_octets..], &input);
        var smith: Smith = .{ .in = &entry };
        try fuzz_window({}, &smith);
    }
}

/// The scripts the long pass runs, and the octets `Smith` reads for a slice's length.
const script_count = 512;
const length_octets = @sizeOf(u32);
