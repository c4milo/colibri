//! The QPACK encoder of RFC 9204. Part of design §8 step 11.
//!
//! **Decision 76 shapes it.** `write_section` decides every field line first, writing each insert
//! to the encoder stream as it goes, and `encoder_plan.zig` makes those decisions. It then writes
//! §4.5.1's prefix and the lines, with the Base at the insert count, so no line needs a post-Base
//! index. It references an entry the decoder has not acknowledged only when the stream may block
//! under the peer's `SETTINGS_QPACK_BLOCKED_STREAMS`, and it inserts only when the entries it
//! evicts are evictable (§2.1.1).
//!
//! **Until `on_settings`, it uses no dynamic table.** RFC 9204 §3.2.3: the maximum table capacity
//! is 0 until the encoder processes a SETTINGS frame. A static-only encoder is conformant against
//! every decoder, needs no encoder stream, and never blocks a stream, so it is complete on its own.
//!
//! A field line the caller marks never indexed is a literal carrying the N bit and is never put
//! in the table, which is §7.1.3's protection for a value compression must not put at risk.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const wire = @import("wire");
const constants = @import("constants.zig");
const representation = @import("representation.zig");
const representation_write = @import("representation_write.zig");
const instruction = @import("instruction.zig");
const insert_count = @import("insert_count.zig");
const dynamic_table = @import("dynamic_table.zig");
const encoder_state = @import("encoder_state.zig");
const encoder_plan = @import("encoder_plan.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const FieldSection = http.field_section.FieldSection;
const Representation = representation.Representation;

pub const Error = core.writer.Error;

pub const DecoderStreamError = error{
    /// RFC 9204 §6's QPACK_DECODER_STREAM_ERROR: the encoder could not interpret an instruction
    /// on the decoder stream. `encoder_state.zig` names the rules that produce it.
    DecoderStreamError,
};

/// When a string is Huffman coded (RFC 9204 §4.1.2). `when_shorter` is what §7.2 leaves an
/// implementation to decide: coding a string that does not shrink costs octets and cycles.
pub const HuffmanUse = enum { never, always, when_shorter };

/// What the encoder may do with one field line (decision 76).
pub const Indexing = enum {
    /// The line may be inserted into the dynamic table, and referenced there.
    may_insert,
    /// The line may reference an entry already in a table, but is not inserted.
    no_insert,
    /// The line MUST be a literal and MUST carry the `N` bit, so no intermediary puts it in a
    /// table on a later hop (§4.5.4, §7.1.3).
    never_indexed,
};

/// The two QPACK settings the peer's decoder advertised (RFC 9204 §5), both zero by default.
pub const Settings = struct {
    /// §3.2.3's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
    max_table_capacity: u64 = 0,
    /// §2.1.2's `SETTINGS_QPACK_BLOCKED_STREAMS`.
    blocked_streams: u64 = 0,
};

pub const Encoder = struct {
    huffman: HuffmanUse,
    peer: Settings,
    /// The table as the decoder will hold it once it has read the encoder stream so far.
    table: dynamic_table.DynamicTable,
    state: encoder_state.EncoderState,
    /// Whether Set Dynamic Table Capacity has gone out (decision 76).
    capacity_sent: bool,
    plan: encoder_plan.Plan,

    pub fn init(encoder: *Encoder, huffman: HuffmanUse) void {
        encoder.huffman = huffman;
        encoder.peer = .{};
        encoder.table.init(0);
        encoder.state.init(0);
        encoder.capacity_sent = false;
    }

    /// The peer's two settings, from the one SETTINGS frame it sends (RFC 9204 §5). A capacity
    /// above `dynamic_table_capacity_max` is used only up to it (§3.2.3 lets an encoder use less).
    pub fn on_settings(encoder: *Encoder, peer: Settings) void {
        assert(!encoder.capacity_sent);
        encoder.peer = peer;
        encoder.table.init(encoder.capacity());
        encoder.state.init(peer.blocked_streams);
    }

    /// The capacity the encoder uses: the peer's maximum, or colibri's, whichever is lower.
    pub fn capacity(encoder: *const Encoder) u64 {
        return @min(encoder.peer.max_table_capacity, constants.dynamic_table_capacity_max);
    }

    /// Writes a whole encoded field section for stream `stream_id` into `output`, and any
    /// encoder instructions it needs into `encoder_stream`. `indexing` gives each line's choice,
    /// or is empty to let every line be inserted. `encoder_stream`'s room is the flow-control
    /// credit the caller has for it (§2.1.3).
    ///
    /// The section is written whole or not at all. What `encoder_stream` gained is owed either
    /// way: those entries are in the encoder's table, and the decoder must receive them too.
    pub fn write_section(
        encoder: *Encoder,
        stream_id: u64,
        output: *Writer,
        encoder_stream: *Writer,
        section: *const FieldSection,
        indexing: []const Indexing,
    ) Error!void {
        assert(indexing.len == 0 or indexing.len == section.len());
        const plan = &encoder.plan;
        plan.start(encoder_plan.usage(encoder, stream_id));
        for (0..section.len()) |index| {
            const line = section.get(@intCast(index));
            const choice = if (indexing.len == 0) Indexing.may_insert else indexing[index];
            encoder_plan.decide(encoder, line.name, line.value, choice, encoder_stream);
        }
        // Decision 76: every insert is in, so the Base is the insert count, and every reference
        // is below it.
        const base = encoder.table.insert_count();
        var cursor = output.*;
        try representation.write_prefix(&cursor, encoder.prefix(base));
        for (plan.lines[0..plan.len], 0..) |planned, index| {
            const line = section.get(@intCast(index));
            try representation_write.write(&cursor, encoder.representation_of(planned, base, line.name, line.value));
        }
        output.* = cursor;
        // RFC 9204 §2.1.1: the encoder tracks each section that references the dynamic table
        // until the decoder acknowledges it. `usage` allowed a reference only with room to.
        const smallest = plan.smallest orelse return;
        encoder.state.on_section_sent(stream_id, plan.required, smallest) catch unreachable;
    }

    /// Reads every whole instruction on the decoder stream (RFC 9204 §4.4), and leaves a partial
    /// one unread for the caller to present again with more.
    pub fn read_decoder_stream(encoder: *Encoder, reader: *Reader) DecoderStreamError!void {
        // Bounded by the octets the caller gave, since every instruction consumes at least one.
        while (reader.remaining_len() > 0) {
            const held = instruction.read_decoder(reader) catch |failure| switch (failure) {
                error.Truncated => return,
                // An integer longer or larger than colibri reads (RFC 9204 §7.4).
                else => return error.DecoderStreamError,
            };
            // RFC 9204 §4.4.1 and §4.4.3: an acknowledgment for a stream with nothing outstanding,
            // or an Increment of zero or past the inserts, is QPACK_DECODER_STREAM_ERROR.
            encoder.apply(held) catch return error.DecoderStreamError;
        }
    }

    fn apply(encoder: *Encoder, held: instruction.Decoder) encoder_state.Error!void {
        switch (held) {
            .section_acknowledgment => |stream_id| try encoder.state.on_section_acknowledgment(stream_id),
            .stream_cancellation => |stream_id| encoder.state.on_stream_cancellation(stream_id),
            .insert_count_increment => |increment| try encoder.state.on_insert_count_increment(increment, encoder.table.insert_count()),
        }
    }

    /// RFC 9204 §4.5.1: the prefix of a section whose Base is `base`.
    fn prefix(encoder: *const Encoder, base: u64) representation.Prefix {
        const required = encoder.plan.required;
        if (required == 0) return representation.Prefix.static_only;
        assert(required <= base);
        // §4.5.1.1: `MaxEntries` is the decoder's maximum capacity over 32, the peer's setting
        // and not the capacity this encoder chose.
        const max_entries = encoder.peer.max_table_capacity / constants.entry_overhead_len;
        return .{
            .encoded_insert_count = insert_count.encode(required, max_entries),
            // §4.5.1.2: a Base at or above the Required Insert Count has a Sign bit of 0.
            .sign = false,
            .delta_base = base - required,
        };
    }

    /// The representation of one planned line (RFC 9204 §4.5), with its dynamic references
    /// relative to `base` (§3.2.5).
    fn representation_of(encoder: *const Encoder, planned: encoder_plan.Planned, base: u64, name: []const u8, value: []const u8) Representation {
        const never_indexed = planned.never_indexed;
        return switch (planned.choice) {
            .static_line => |index| .{ .indexed = .{ .table = .static, .index = index } },
            .dynamic_line => |absolute| .{ .indexed = .{ .table = .dynamic, .index = base - 1 - absolute } },
            .static_name => |index| .{ .literal_name_reference = .{
                .never_indexed = never_indexed,
                .table = .static,
                .name_index = index,
                .value = value,
                .value_coding = encoder.coding(value),
            } },
            .dynamic_name => |absolute| .{ .literal_name_reference = .{
                .never_indexed = never_indexed,
                .table = .dynamic,
                .name_index = base - 1 - absolute,
                .value = value,
                .value_coding = encoder.coding(value),
            } },
            .literal => .{ .literal = .{
                .never_indexed = never_indexed,
                .name = name,
                .name_coding = encoder.coding(name),
                .value = value,
                .value_coding = encoder.coding(value),
            } },
        };
    }

    pub fn coding(encoder: *const Encoder, octets: []const u8) representation.Coding {
        return switch (encoder.huffman) {
            .never => .raw,
            .always => .huffman,
            // RFC 9204 §7.2: coding a string that does not shrink spends octets to save none.
            .when_shorter => if (wire.huffman.encoded_len(octets) < octets.len) .huffman else .raw,
        };
    }
};

test {
    _ = @import("encoder_test.zig");
}
