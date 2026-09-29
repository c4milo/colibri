//! A record's tokens, gathered and handed to stdx's `TextWriter` many at a call (`write_items`,
//! stdx's decision 33), which writes the same octets as a call per token, faster (decision 102 as
//! amended). It has `TextWriter`'s calls, so the event writers name it as they named that.
//!
//! **Every octet is copied as it is added.** A name's, a string's or a hex string's octets go into
//! the batch's own buffer, so a writer may pass octets that die when it returns, such as a string
//! it formatted on its stack. Octets longer than the buffer are written at once instead, after what
//! was gathered before them.
const std = @import("std");
const assert = std.debug.assert;
const json = @import("json");
const Features = @import("codec").Features;
const constants = @import("constants.zig");

const Item = json.Encoder.Item;
const Token = json.Token;

pub const Error = json.EncodeError || error{NoSpaceLeft};

pub const Batch = struct {
    text: json.TextWriter,
    items: [constants.batch_items_max]Item,
    len: usize,
    /// The copies of the gathered items' octets, `octets_len` of them.
    octets: [constants.batch_octets_len]u8,
    octets_len: usize,

    pub fn init(output: []u8, framing: json.Framing, features: Features) Batch {
        return .{
            .text = json.TextWriter.init(output, framing, features),
            .items = undefined,
            .len = 0,
            .octets = undefined,
            .octets_len = 0,
        };
    }

    pub fn begin_object(batch: *Batch) Error!void {
        try batch.add(.begin_object);
    }

    pub fn end_object(batch: *Batch) Error!void {
        try batch.add(.end_object);
    }

    pub fn begin_array(batch: *Batch) Error!void {
        try batch.add(.begin_array);
    }

    pub fn end_array(batch: *Batch) Error!void {
        try batch.add(.end_array);
    }

    /// A member's name, `octets` in UTF-8 (RFC 8259 §4).
    pub fn name(batch: *Batch, octets: []const u8) Error!void {
        try batch.add_octets(.{ .name = .last }, octets);
    }

    /// A string of `octets`, in UTF-8 (RFC 8259 §7).
    pub fn string(batch: *Batch, octets: []const u8) Error!void {
        try batch.add_octets(.{ .string = .last }, octets);
    }

    /// A string of two lowercase hex digits for each of `octets`.
    pub fn hex(batch: *Batch, octets: []const u8) Error!void {
        try batch.add_octets(.{ .hex = .last }, octets);
    }

    pub fn unsigned(batch: *Batch, value: u64) Error!void {
        try batch.add(.{ .unsigned = value });
    }

    pub fn decimal(batch: *Batch, value: json.Decimal) Error!void {
        try batch.add(.{ .decimal = value });
    }

    pub fn boolean(batch: *Batch, value: bool) Error!void {
        try batch.add(.{ .boolean = value });
    }

    /// The text, once its last token is gathered: what is left is written first.
    pub fn written(batch: *Batch) Error![]const u8 {
        try batch.flush();
        return batch.text.written();
    }

    /// Hands every gathered item to `write_items`, and frees the items and their copies.
    fn flush(batch: *Batch) Error!void {
        if (batch.len == 0) return;
        try batch.text.write_items(batch.items[0..batch.len]);
        batch.len = 0;
        batch.octets_len = 0;
    }

    /// Gathers a token that takes no octets, first writing the items when every one is taken.
    fn add(batch: *Batch, token: Token) Error!void {
        if (batch.len == batch.items.len) try batch.flush();
        batch.items[batch.len] = .{ .token = token };
        batch.len += 1;
    }

    /// Gathers a token with a copy of `octets`. Octets longer than the buffer are written at once,
    /// after the items gathered before them, while the caller still holds them.
    fn add_octets(batch: *Batch, token: Token, octets: []const u8) Error!void {
        if (octets.len > batch.octets.len) {
            try batch.flush();
            return batch.text.write_items(&.{.{ .token = token, .octets = octets }});
        }
        if (batch.len == batch.items.len or batch.octets.len - batch.octets_len < octets.len) try batch.flush();
        const copy = batch.octets[batch.octets_len..][0..octets.len];
        @memcpy(copy, octets);
        batch.octets_len += octets.len;
        batch.items[batch.len] = .{ .token = token, .octets = copy };
        batch.len += 1;
        assert(batch.octets_len <= batch.octets.len);
    }
};

const testing = std.testing;

/// Room for the longest text a test writes. Test-only.
const test_output_len: usize = 8192;

/// A string long enough that the members' copies fill the batch's buffer more than once. Test-only.
const test_value = "a string long enough to fill the buffer";

/// A record written one token a call, which a batch must match octet for octet. Test-only.
fn one_token_a_call(output: []u8, count: usize) ![]const u8 {
    var text = json.TextWriter.init(output, .sequence, Features.none());
    try text.begin_object();
    try text.name("items");
    try text.begin_array();
    // Bounded by the test's count.
    for (0..count) |index| {
        try text.begin_object();
        try text.name("n");
        try text.unsigned(index);
        try text.name("s");
        try text.string(test_value);
        try text.end_object();
    }
    try text.end_array();
    try text.end_object();
    return text.written();
}

fn batched(output: []u8, count: usize) ![]const u8 {
    var batch = Batch.init(output, .sequence, Features.none());
    try batch.begin_object();
    try batch.name("items");
    try batch.begin_array();
    // Bounded by the test's count.
    for (0..count) |index| {
        try batch.begin_object();
        try batch.name("n");
        try batch.unsigned(index);
        try batch.name("s");
        try batch.string(test_value);
        try batch.end_object();
    }
    try batch.end_array();
    try batch.end_object();
    return batch.written();
}

test "a batch writes what a call per token writes, across more items than one write takes" {
    var expected_output: [test_output_len]u8 = undefined;
    var output: [test_output_len]u8 = undefined;
    // Six tokens a member, and more copied octets than the buffer holds, so the batch writes in
    // several calls, when its items run out and when its buffer does.
    const count = constants.batch_items_max;
    comptime std.debug.assert(count * test_value.len > constants.batch_octets_len);
    try testing.expectEqualStrings(try one_token_a_call(&expected_output, count), try batched(&output, count));
}

/// Adds a string this function formats on its own stack, which is gone once it returns.
fn add_formatted(batch: *Batch, value: u32) !void {
    var digits: [constants.tuple_id_len_max]u8 = undefined;
    try batch.string(std.fmt.bufPrint(&digits, "{d}", .{value}) catch unreachable);
}

/// Writes over the stack the last call left, so octets a batch pointed at would read wrong.
fn scribble() u8 {
    var junk: [constants.batch_octets_len]u8 = undefined;
    @memset(&junk, 'x');
    std.mem.doNotOptimizeAway(&junk);
    return junk[junk.len - 1];
}

test "octets that die when their writer returns are written as they were added" {
    var output: [test_output_len]u8 = undefined;
    var batch = Batch.init(&output, .sequence, Features.none());
    try batch.begin_array();
    try add_formatted(&batch, 4_294_967_295);
    _ = scribble();
    try batch.end_array();
    try testing.expectEqualStrings("\x1e[\"4294967295\"]\n", try batch.written());
}

test "octets longer than the buffer are written at once, after what came before" {
    var output: [test_output_len]u8 = undefined;
    var batch = Batch.init(&output, .sequence, Features.none());
    const long: [constants.batch_octets_len + 1]u8 = @splat('a');
    try batch.begin_array();
    try batch.string("first");
    try batch.string(&long);
    try batch.string("last");
    try batch.end_array();
    const text = try batch.written();
    try testing.expect(std.mem.startsWith(u8, text, "\x1e[\"first\",\"aaaa"));
    try testing.expect(std.mem.endsWith(u8, text, "a\",\"last\"]\n"));
    try testing.expectEqual("\x1e[".len + "\"first\",".len + "\"".len + long.len + "\",".len + "\"last\"]\n".len, text.len);
}

test "a record that does not fit fails with NoSpaceLeft" {
    var output: [test_output_len]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, batched(output[0..16], 2));
}
