//! How the QPACK encoder decides each field line of a section, before any is written (decision
//! 76). Part of design §8 step 11.
//!
//! Each line becomes one of five choices: a static line or name, a dynamic line or name, or a
//! literal. A dynamic choice names an absolute index (§3.2.4), which `encoder.zig` turns into a
//! relative one once the Base is known. Deciding may insert the line, writing the instruction to
//! the encoder stream. Two rules keep every reference safe:
//! - RFC 9204 §2.1.2: an entry at or above the Known Received Count is referenced only when the
//!   stream may block, since the decoder may not have it yet. A line inserted on a stream that may
//!   not block is written as a literal, and the entry serves later sections once acknowledged.
//! - §2.1.1: an insert evicts only entries whose insertion is acknowledged and which no
//!   unacknowledged section references, this one included.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const instruction = @import("instruction.zig");
const static_table = @import("static_table.zig");
const encoder_module = @import("encoder.zig");

const Writer = core.Writer;
const Encoder = encoder_module.Encoder;
const Indexing = encoder_module.Indexing;
const entry_size = wire.table_size.entry_size;

/// How one field line will be written (RFC 9204 §4.5).
pub const Choice = union(enum) {
    /// §4.5.2 with the T bit set: a static index.
    static_line: u64,
    /// §4.5.2 with the T bit clear: an absolute index into the dynamic table.
    dynamic_line: u64,
    /// §4.5.4 with the T bit set: a static name and a literal value.
    static_name: u64,
    /// §4.5.4 with the T bit clear: a dynamic name, as an absolute index, and a literal value.
    dynamic_name: u64,
    /// §4.5.6: a literal name and value.
    literal,
};

pub const Planned = struct {
    choice: Choice,
    never_indexed: bool = false,
};

/// What a section may do with the dynamic table.
pub const Usage = struct {
    /// Whether it may reference the dynamic table at all.
    dynamic: bool = false,
    /// Whether it may reference entries the decoder has not acknowledged, which is what an
    /// insert it references is.
    may_block: bool = false,
};

/// The lines of the section being written, decided before any is written.
pub const Plan = struct {
    lines: [core.constants.field_count_max]Planned,
    len: u32,
    usage: Usage,
    /// RFC 9204 §2.1.2: one more than the largest absolute index referenced, or zero.
    required: u64,
    /// The smallest absolute index referenced, or null when none is. No insert in this section
    /// may evict it (§2.1.1).
    smallest: ?u64,

    pub fn start(plan: *Plan, usage_now: Usage) void {
        plan.len = 0;
        plan.usage = usage_now;
        plan.required = 0;
        plan.smallest = null;
    }

    fn add(plan: *Plan, planned: Planned) void {
        assert(plan.len < plan.lines.len);
        plan.lines[plan.len] = planned;
        plan.len += 1;
    }

    fn reference(plan: *Plan, choice: Choice, absolute: u64) void {
        assert(plan.usage.dynamic);
        plan.required = @max(plan.required, absolute + 1);
        plan.smallest = @min(plan.smallest orelse absolute, absolute);
        plan.add(.{ .choice = choice });
    }
};

/// What a section on `stream_id` may do with the dynamic table (decision 76).
pub fn usage(encoder: *const Encoder, stream_id: u64) Usage {
    // colibri's bound: a section with dynamic references needs a record until acknowledged.
    if (!encoder.state.has_room()) return .{};
    // §2.1.2: the encoder MUST hold the number of streams that could block to the peer's limit.
    const may_block = encoder.state.may_send(stream_id, encoder.state.known_received + 1);
    return .{ .dynamic = true, .may_block = may_block };
}

/// Decides one field line, inserting it when decision 76 allows.
pub fn decide(encoder: *Encoder, name: []const u8, value: []const u8, indexing: Indexing, encoder_stream: *Writer) void {
    const plan = &encoder.plan;
    const static = find_static(name, value);
    if (indexing == .never_indexed) {
        // §7.1.3: a literal carrying the N bit, naming at most a static name. An index carries
        // no N bit, so even a line the static table holds whole is a literal here.
        return plan.add(.{ .choice = static_name_or_literal(static.name), .never_indexed = true });
    }
    // §4.5.2: a line the static table holds whole is its index, which never blocks.
    if (static.exact) |index| return plan.add(.{ .choice = .{ .static_line = index } });
    if (plan.usage.dynamic) {
        if (decide_dynamic(encoder, name, value, indexing, static.name, encoder_stream)) return;
    }
    plan.add(.{ .choice = static_name_or_literal(static.name) });
}

fn static_name_or_literal(static_name: ?u64) Choice {
    return if (static_name) |index| .{ .static_name = index } else .literal;
}

/// Plans the line against the dynamic table, and answers whether it did.
fn decide_dynamic(encoder: *Encoder, name: []const u8, value: []const u8, indexing: Indexing, static_name: ?u64, encoder_stream: *Writer) bool {
    const found = encoder.table.find(name, value);
    if (found.exact) |absolute| {
        if (referenceable(encoder, absolute)) {
            encoder.plan.reference(.{ .dynamic_line = absolute }, absolute);
            return true;
        }
    } else if (indexing == .may_insert) {
        if (insert_line(encoder, name, value, static_name, encoder_stream)) return true;
    }
    // A static name is as short as a dynamic one and never blocks.
    if (static_name != null) return false;
    return reference_name(encoder, found.name);
}

/// Inserts the line, and references the entry when the stream may block. Decision 76: a stream
/// that may not block writes the line as a literal, and the entry serves later sections once the
/// decoder acknowledges it.
fn insert_line(encoder: *Encoder, name: []const u8, value: []const u8, static_name: ?u64, encoder_stream: *Writer) bool {
    const absolute = insert(encoder, name, value, static_name, encoder_stream) orelse return false;
    if (!encoder.plan.usage.may_block) return false;
    encoder.plan.reference(.{ .dynamic_line = absolute }, absolute);
    return true;
}

/// References the newest entry holding the name, when it is still in the table and safe to
/// reference.
fn reference_name(encoder: *Encoder, found_name: ?u64) bool {
    const absolute = found_name orelse return false;
    // An insert for this line may have evicted it.
    if (encoder.table.get_absolute(absolute) == null) return false;
    if (!referenceable(encoder, absolute)) return false;
    encoder.plan.reference(.{ .dynamic_name = absolute }, absolute);
    return true;
}

/// RFC 9204 §2.1.2: an entry the decoder has acknowledged never blocks, and any other entry may
/// be referenced only when the stream may block.
fn referenceable(encoder: *const Encoder, absolute: u64) bool {
    return absolute < encoder.state.known_received or encoder.plan.usage.may_block;
}

/// Inserts the line and returns its absolute index, or null when decision 76 does not allow it:
/// the entry is too large, making room would evict an entry that is not evictable, or the
/// instructions do not fit the encoder stream.
fn insert(encoder: *Encoder, name: []const u8, value: []const u8, static_name: ?u64, encoder_stream: *Writer) ?u64 {
    const capacity = encoder.capacity();
    const size = entry_size(name.len, value.len);
    // Decision 76: one line takes at most the capacity over `insert_size_divisor`. With RFC 9204
    // §3.2.3's maximum of zero, nothing fits and nothing is ever inserted.
    if (size > capacity / constants.insert_size_divisor) return null;
    if (!room_for(encoder, size, capacity)) return null;
    var cursor = encoder_stream.*;
    // RFC 9204 §3.2.2: the table's capacity starts at zero, and the encoder sets it before it
    // inserts the first entry.
    if (!encoder.capacity_sent) instruction.write_encoder(&cursor, .{ .set_capacity = capacity }) catch return null;
    const held: instruction.Encoder = if (static_name) |index| .{ .insert_name_reference = .{
        .table = .static,
        .name_index = index,
        .value = value,
        .value_coding = encoder.coding(value),
    } } else .{ .insert_literal = .{
        .name = name,
        .name_coding = encoder.coding(name),
        .value = value,
        .value_coding = encoder.coding(value),
    } };
    // RFC 9204 §2.1.3: an instruction is written only when the credit covers all of it.
    instruction.write_encoder(&cursor, held) catch return null;
    encoder_stream.* = cursor;
    if (!encoder.capacity_sent) {
        encoder.table.set_capacity(capacity) catch unreachable;
        encoder.capacity_sent = true;
    }
    encoder.table.insert(name, value) catch unreachable;
    return encoder.table.insert_count() - 1;
}

/// Whether an entry of `size` fits once the oldest entries are evicted, evicting none that
/// RFC 9204 §2.1.1 keeps.
fn room_for(encoder: *const Encoder, size: u64, capacity: u64) bool {
    const table = &encoder.table;
    const held = if (encoder.capacity_sent) table.size else 0;
    var free = capacity - held;
    const floor = lowest_reference(encoder);
    var absolute = table.dropped;
    // Bounded by the live entries: §3.2.2 evicts from the oldest end, one entry at a time.
    while (free < size) : (absolute += 1) {
        if (absolute >= table.inserted) return false;
        // §2.1.1: an entry is not evictable until its insertion is acknowledged.
        if (absolute >= encoder.state.known_received) return false;
        // §2.1.1: nor while an unacknowledged section references it.
        if (floor) |lowest| if (absolute >= lowest) return false;
        const entry = table.get_absolute(absolute).?;
        free += entry_size(entry.name.len, entry.value.len);
    }
    return true;
}

/// The smallest absolute index an unacknowledged section references, this one included.
fn lowest_reference(encoder: *const Encoder) ?u64 {
    const outstanding = encoder.state.referenced_floor();
    const here = encoder.plan.smallest;
    if (outstanding == null) return here;
    if (here == null) return outstanding;
    return @min(outstanding.?, here.?);
}

/// The static indices holding the field line and its name (RFC 9204 Appendix A).
const Match = struct {
    exact: ?u64 = null,
    name: ?u64 = null,
};

/// The lowest static index holding the whole line, and the lowest holding its name. Appendix A
/// orders the entries so the commonest field lines take the fewest octets, and the lowest index
/// is the shortest to encode, so the first match of each is the one to take.
fn find_static(name: []const u8, value: []const u8) Match {
    var match: Match = .{};
    // Bounded by Appendix A's entry count, which is a named limit.
    for (static_table.entries, 0..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (match.name == null) match.name = index;
        if (std.mem.eql(u8, entry.value, value)) {
            match.exact = index;
            return match;
        }
    }
    return match;
}
