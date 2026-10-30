//! The HPACK encoder: field lines in, one field block out (RFC 7541 §3, §6).
//!
//! An `Encoder` is one endpoint's encoding context (§2.2): a dynamic table that mirrors the
//! peer's decoder, and the limit the peer set on it, which in h2 is the peer's
//! `SETTINGS_HEADER_TABLE_SIZE`. A block is written as `begin_block`, then one `write_field` per
//! line, into a `core.Writer` the caller owns. Each call writes all of its octets or none.
//!
//! The strategy is the one RFC 7541 Appendix C's examples follow, and the tests hold the encoder
//! to those examples byte for byte:
//!
//! - a line found whole in either table is an indexed field (§6.1), the static table's index
//!   preferred because a line the static table holds is never inserted into the mirror;
//! - otherwise a literal, with the name by index when either table holds it (§6.2), and with
//!   incremental indexing (§6.2.1) unless the caller asked for another representation or the
//!   entry would not fit the table at all, in which case indexing it would only empty the table
//!   (§4.4);
//! - a string is Huffman-coded as `huffman` says: always, as the RFC's examples do; never; or only
//!   when that is strictly shorter, as nghttp2 does.
//!
//! A block's inserts change the mirror as the block is written, and the peer's table only when
//! the peer decodes it. So a block the caller abandons after an insert leaves the mirror ahead of
//! the peer (decision 132). The next block then opens with a size update to 0, which empties the
//! peer's table, and one to the capacity, and the mirror empties with it (RFC 7541 §4.2, §6.3).
//!
//! The capacity the encoder declares is the smaller of the peer's limit and
//! `dynamic_table_capacity_max` (§4.2 lets an encoder use less than the limit). A change is
//! signalled at the start of the next block, with the smallest capacity of the interval first and
//! the final one second when it differs from the capacity last declared (§4.2), and the mirror is resized as each is written,
//! which is when the peer's decoder resizes.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const static_table = @import("static_table.zig");
const encoder_string = @import("encoder_string.zig");
const dynamic_table = @import("dynamic_table.zig");

const Writer = core.Writer;
const DynamicTable = dynamic_table.DynamicTable;
const Match = dynamic_table.Match;
const prefixed_integer = wire.prefixed_integer;
const string_literal = wire.string_literal;
const entry_size = wire.table_size.entry_size;

pub const Error = core.writer.Error;

/// How a line may be represented. `incremental` lets the encoder index it; `without_indexing`
/// keeps it out of the table; `never_indexed` also tells every intermediary to do the same
/// (RFC 7541 §6.2.3, §7.1.3).
pub const Indexing = enum { incremental, without_indexing, never_indexed };

/// When a string is Huffman-coded (RFC 7541 §5.2 leaves the choice to the encoder).
pub const HuffmanUse = enum { never, always, when_shorter };

pub const Encoder = struct {
    table: DynamicTable,
    /// The limit the peer set (RFC 7541 §4.2, §6.3).
    capacity_limit: u64,
    /// The capacity this encoder has chosen under the limit, declared at the next block's start.
    chosen: u64,
    /// The capacity last declared to the peer: what its decoder's table holds now.
    declared: u64,
    /// The smallest capacity chosen since the last declaration (RFC 7541 §4.2).
    chosen_min: u64,
    huffman: HuffmanUse,
    /// The block since the last `commit_block` inserted into the mirror.
    inserted_uncommitted: bool,
    /// A block was abandoned after an insert, so the next block empties both tables first.
    empty_owed: bool,

    /// An encoder whose table's capacity and limit are both `capacity`: the protocol's initial
    /// value, 4,096 in h2 (RFC 9113 §6.5.2).
    pub fn init(encoder: *Encoder, capacity: u64, huffman: HuffmanUse) void {
        assert(capacity <= constants.limits.dynamic_table_capacity_max);
        encoder.table.init(capacity);
        encoder.capacity_limit = capacity;
        encoder.chosen = capacity;
        encoder.declared = capacity;
        encoder.chosen_min = capacity;
        encoder.huffman = huffman;
        encoder.inserted_uncommitted = false;
        encoder.empty_owed = false;
    }

    /// The peer changed its limit and this endpoint has acknowledged it.
    pub fn set_capacity_limit(encoder: *Encoder, limit: u64) void {
        encoder.capacity_limit = limit;
        encoder.chosen = @min(limit, constants.limits.dynamic_table_capacity_max);
        encoder.chosen_min = @min(encoder.chosen_min, encoder.chosen);
        assert(encoder.chosen <= encoder.capacity_limit);
    }

    /// Opens a block: writes the size updates a capacity change owes (RFC 7541 §4.2), or nothing.
    /// The capacity is not declared until `commit_block`, because a block the caller abandons
    /// never reaches the peer and owes its updates again. After a block abandoned with an insert,
    /// it writes the two updates that empty both tables (decision 132).
    pub fn begin_block(encoder: *Encoder, output: *Writer) Error!void {
        // Decision 132: the block before this one was abandoned after an insert.
        if (encoder.inserted_uncommitted) encoder.empty_owed = true;
        var cursor = output.*;
        if (encoder.empty_owed) {
            // RFC 7541 §6.3: a size update to 0 evicts every entry of the peer's table, and the
            // second one sets the capacity. §4.2 allows two updates at a block's start.
            try write_size_update(&cursor, 0);
            try write_size_update(&cursor, encoder.chosen);
        } else {
            // RFC 7541 §4.2: the smallest maximum of the interval first, then the final one.
            if (encoder.chosen_min < encoder.declared and encoder.chosen_min < encoder.chosen) {
                try write_size_update(&cursor, encoder.chosen_min);
            }
            if (encoder.chosen != encoder.declared) try write_size_update(&cursor, encoder.chosen);
        }
        output.* = cursor;
        if (encoder.empty_owed) encoder.table.resize(0);
        encoder.table.resize(encoder.chosen_min);
        encoder.table.resize(encoder.chosen);
    }

    /// Declares the block the caller finished: the capacity its size updates named is what the
    /// peer's decoder holds from here on (RFC 7541 §4.2). A caller that abandons a block never
    /// calls this, so the next block writes the same updates again and the two tables stay the
    /// same size.
    pub fn commit_block(encoder: *Encoder) void {
        encoder.declared = encoder.chosen;
        encoder.chosen_min = encoder.chosen;
        encoder.inserted_uncommitted = false;
        encoder.empty_owed = false;
        assert(encoder.table.capacity == encoder.declared);
    }

    /// Writes one field line in the representation `indexing` allows.
    pub fn write_field(
        encoder: *Encoder,
        output: *Writer,
        name: []const u8,
        value: []const u8,
        indexing: Indexing,
    ) Error!void {
        assert(name.len <= constants.limits.name_len_max and value.len <= constants.limits.value_len_max);
        var cursor = output.*;
        const match = encoder.find(name, value);
        if (indexing != .never_indexed) {
            if (match.exact) |index| {
                // RFC 7541 §6.1: a line both tables hold is sent as its index.
                try prefixed_integer.encode(constants.protocol.indexed_prefix_bits, &cursor, constants.protocol.indexed_pattern, index);
                output.* = cursor;
                return;
            }
        }
        // RFC 7541 §4.4: an entry larger than the capacity would only empty the table.
        const fits = entry_size(name.len, value.len) <= encoder.table.capacity;
        const kind: Indexing = if (indexing == .incremental and !fits) .without_indexing else indexing;
        const name_index = match.name orelse 0;
        switch (kind) {
            .incremental => try prefixed_integer.encode(
                constants.protocol.incremental_prefix_bits,
                &cursor,
                constants.protocol.incremental_pattern,
                name_index,
            ),
            .without_indexing => try prefixed_integer.encode(
                constants.protocol.literal_prefix_bits,
                &cursor,
                constants.protocol.without_indexing_pattern,
                name_index,
            ),
            .never_indexed => try prefixed_integer.encode(
                constants.protocol.literal_prefix_bits,
                &cursor,
                constants.protocol.never_indexed_pattern,
                name_index,
            ),
        }
        if (name_index == 0) try encoder.write_string(&cursor, name);
        try encoder.write_string(&cursor, value);
        output.* = cursor;
        if (kind == .incremental) {
            encoder.table.insert(name, value);
            encoder.inserted_uncommitted = true;
        }
    }

    /// The indices of the fused address space (RFC 7541 §2.3.3) holding the line and its name.
    /// The static table's index is preferred for both: it is the lower one, and a line the static
    /// table holds is never in the mirror, since this encoder indexes it instead of inserting it.
    fn find(encoder: *const Encoder, name: []const u8, value: []const u8) Match {
        const static = find_static(name, value);
        const dynamic = encoder.table.find(name, value);
        var match: Match = static;
        if (match.exact == null) {
            if (dynamic.exact) |index| match.exact = index + constants.protocol.static_table_len;
        }
        if (match.name == null) {
            if (dynamic.name) |index| match.name = index + constants.protocol.static_table_len;
        }
        return match;
    }

    fn write_string(encoder: *const Encoder, output: *Writer, octets: []const u8) Error!void {
        const coding: string_literal.Coding = switch (encoder.huffman) {
            .never => .raw,
            .always => .huffman,
            .when_shorter => return encoder_string.write_shorter(output, octets),
        };
        try string_literal.encode(constants.protocol.string_prefix_bits, output, 0, octets, coding);
    }
};

/// A size update (RFC 7541 §6.3).
fn write_size_update(output: *Writer, capacity: u64) Error!void {
    try prefixed_integer.encode(constants.protocol.size_update_prefix_bits, output, constants.protocol.size_update_pattern, capacity);
}

/// The lowest static indices holding the line and its name (RFC 7541 Appendix A). The name finds
/// its run of entries through `static_names`, which compares it only with names of its length, and
/// the value is compared within the run alone.
pub fn find_static(name: []const u8, value: []const u8) Match {
    const run = static_names.get(name) orelse return .{};
    const match: Match = .{ .name = run.first };
    // Bounded by the run, at most the table's 61 entries.
    for (static_table.entries[run.first - 1 ..][0..run.len], run.first..) |entry, index| {
        if (std.mem.eql(u8, entry.value, value)) return .{ .exact = @intCast(index), .name = run.first };
    }
    return match;
}

/// The entries of the static table that share one name: the index of the first, and how many.
const Run = struct {
    first: u32,
    len: u32,
};

/// Each name of the static table and its run, computed when colibri is built ("Precompute what
/// cannot change", CLAUDE.md). The table is one list of names in the order Appendix A gives, so
/// each name's entries are adjacent, which the build checks.
const static_names = std.StaticStringMap(Run).initComptime(static_runs());

fn static_runs() [static_names_len]struct { []const u8, Run } {
    @setEvalBranchQuota(static_quota);
    var runs: [static_names_len]struct { []const u8, Run } = undefined;
    var len: usize = 0;
    for (static_table.entries, 1..) |entry, index| {
        if (len > 0 and std.mem.eql(u8, runs[len - 1][0], entry.name)) {
            runs[len - 1][1].len += 1;
            continue;
        }
        for (runs[0..len]) |earlier| {
            // A name whose entries were not adjacent would find its first run alone.
            if (std.mem.eql(u8, earlier[0], entry.name)) @compileError("a static table name's entries are not adjacent");
        }
        runs[len] = .{ entry.name, .{ .first = index, .len = 1 } };
        len += 1;
    }
    assert(len == static_names_len);
    return runs;
}

/// The distinct names of the static table.
const static_names_len: usize = count: {
    @setEvalBranchQuota(static_quota);
    var len: usize = 0;
    for (static_table.entries, 0..) |entry, index| {
        if (index == 0 or !std.mem.eql(u8, static_table.entries[index - 1].name, entry.name)) len += 1;
    }
    break :count len;
};

/// The evaluation the build spends comparing the table's names with one another.
const static_quota: u32 = 100_000;

test {
    _ = @import("encoder_test.zig");
}
