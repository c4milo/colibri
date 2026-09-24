//! The QPACK decoder of RFC 9204. Part of design §8 step 11.
//!
//! It reads §4.5.1's field section prefix and then one representation per field line, resolves
//! each against the static table (Appendix A) or the dynamic table (§3.2), and appends the result
//! to a field section the caller owns. `decoder_table.zig` applies the encoder stream to the
//! dynamic table, and `decoder_stream.zig` writes the instructions the decoder owes.
//!
//! **Decision 74 shapes the rest.** A section that needs entries not yet received blocks its
//! stream (§2.2.1). The decoder records the stream and returns `blocked`, the caller keeps the
//! octets, and `ready_stream` names the stream once the entries have arrived. The decoder queues
//! the Section Acknowledgments and Stream Cancellations it owes, and a full queue stops the
//! reading rather than drop one.
//!
//! A decoder that advertises a `SETTINGS_QPACK_MAX_TABLE_CAPACITY` of zero, §5's default, permits
//! no dynamic table. Every Required Insert Count but zero is then refused, nothing blocks, and
//! nothing is owed.
//!
//! A literal's decoded octets are written into a buffer the caller owns (decision 35), and the
//! field section copies each line into its own storage as it is appended. The dynamic table does
//! not change while a section is read, so its entries are appended from where they are.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("constants.zig");
const representation = @import("representation.zig");
const static_table = @import("static_table.zig");
const dynamic_table = @import("dynamic_table.zig");
const insert_count = @import("insert_count.zig");
const decoder_table = @import("decoder_table.zig");
const decoder_stream = @import("decoder_stream.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const FieldSection = http.field_section.FieldSection;
const Representation = representation.Representation;

pub const Error = representation.Error || http.field_section.AppendError || error{
    /// RFC 9204 §6's QPACK_DECOMPRESSION_FAILED: the decoder cannot interpret the field section
    /// and cannot continue decoding it. §2.2.3 names the references that produce it, §3.1 the
    /// static index, §2.1.2 the blocked stream too many, and §4.5.1 the prefixes.
    DecompressionFailed,
    /// RFC 9204 §7.4: a name or value longer than colibri accepts (`field_name_len_max`,
    /// `field_value_len_max`), which §7.4 makes a stream error of QPACK_DECOMPRESSION_FAILED.
    FieldTooLong,
    /// RFC 9204 §6's QPACK_ENCODER_STREAM_ERROR: an encoder instruction the decoder cannot
    /// interpret. `decoder_table.zig` names each rule that produces it.
    EncoderStreamError,
};

/// What RFC 9204 §6 has HTTP/3 send for an error from here.
pub fn error_code(failure: Error) u64 {
    return switch (failure) {
        error.EncoderStreamError => constants.error_encoder_stream,
        // Everything else is a failure to interpret one field section.
        else => constants.error_decompression_failed,
    };
}

/// The two settings a decoder advertises (RFC 9204 §5), both zero by default.
pub const Settings = struct {
    /// §3.2.3's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, at most `dynamic_table_capacity_max`.
    max_table_capacity: u64 = 0,
    /// §2.1.2's `SETTINGS_QPACK_BLOCKED_STREAMS`, at most `blocked_streams_max`.
    blocked_streams: u64 = 0,
};

/// What `read_section` did.
pub const Outcome = enum {
    /// The section is in the caller's field section, and its octets are consumed.
    decoded,
    /// RFC 9204 §2.2.1: the section needs entries not yet received. Nothing is consumed, and the
    /// caller asks again once `ready_stream` names the stream.
    blocked,
    /// The queue of owed instructions is full. Nothing is consumed, and the caller writes the
    /// decoder stream before it asks again (decision 74).
    owes_instructions,
    /// The list of blocked streams is full, and some of them can now be decoded. Nothing is
    /// consumed, and the caller reads those first, as `ready_stream` names them (decision 74).
    read_ready_first,
};

/// What `abandon_stream` did.
pub const Abandoned = enum { cancelled, owes_instructions };

/// A field section on a stream, named by the insert count it needs (RFC 9204 §4.5.1.1).
pub const Section = struct {
    stream_id: u64,
    required_insert_count: u64,
};

/// One instruction the decoder owes the encoder (RFC 9204 §4.4) and has not written yet. The
/// third, §4.4.3's Insert Count Increment, is worked out when the decoder writes.
pub const Owed = union(enum) {
    section_acknowledgment: Section,
    stream_cancellation: u64,
};

pub const Decoder = struct {
    settings: Settings,
    table: dynamic_table.DynamicTable,
    /// The streams whose section waits for entries (RFC 9204 §2.2.1), in the order they blocked.
    blocked: [constants.blocked_streams_max]Section,
    blocked_len: usize,
    /// The instructions owed, oldest first.
    owed: [constants.decoder_instructions_owed_max]Owed,
    owed_len: usize,
    /// RFC 9204 §2.1.4's Known Received Count, as the encoder holds it once every instruction
    /// written so far has arrived.
    known_received: u64,
    /// Where an encoder instruction's strings are decoded before the table copies them.
    scratch: [constants.encoder_instruction_len_max]u8,

    pub fn init(decoder: *Decoder, settings: Settings) void {
        assert(settings.max_table_capacity <= constants.dynamic_table_capacity_max);
        assert(settings.blocked_streams <= constants.blocked_streams_max);
        decoder.settings = settings;
        decoder.table.init(settings.max_table_capacity);
        decoder.blocked_len = 0;
        decoder.owed_len = 0;
        decoder.known_received = 0;
    }

    /// Reads a whole encoded field section from stream `stream_id` into `section`, with the
    /// names and values it decodes written into `strings`.
    pub fn read_section(
        decoder: *Decoder,
        stream_id: u64,
        reader: *Reader,
        strings: *Writer,
        section: *FieldSection,
    ) Error!Outcome {
        if (decoder.owed_len == decoder.owed.len) return .owes_instructions;
        var cursor = reader.*;
        const prefix = try representation.read_prefix(&cursor);
        const inserted = decoder.table.insert_count();
        // RFC 9204 §4.5.1.1: a value no conformant encoder could produce is refused.
        const required = insert_count.decode(prefix.encoded_insert_count, inserted, decoder.table.max_entries()) catch
            return Error.DecompressionFailed;
        // RFC 9204 §2.2.1: a section that needs entries not yet received blocks its stream.
        if (required > inserted) return decoder.block(stream_id, required);
        // RFC 9204 §4.5.1.2: a Sign bit of 1 at or above the Required Insert Count is invalid.
        const base = prefix.base(required) catch return Error.DecompressionFailed;
        const reach = try decoder.read_lines(&cursor, strings, section, .{ .required = required, .base = base });
        // RFC 9204 §2.2.1: a Required Insert Count larger than the references need MAY be
        // refused, and decision 74 refuses it. One smaller fails at the reference, by §2.2.3.
        if (reach < required) return Error.DecompressionFailed;
        assert(reach == required);
        decoder.unblock(stream_id);
        reader.* = cursor;
        // RFC 9204 §4.4.1: a section whose Required Insert Count is not zero is acknowledged.
        if (required != 0) decoder.owe(.{ .section_acknowledgment = .{ .stream_id = stream_id, .required_insert_count = required } });
        return .decoded;
    }

    /// Applies every whole instruction in `reader` to the dynamic table (RFC 9204 §4.3), and
    /// leaves a partial one unread for the caller to present again with more.
    pub fn read_encoder_stream(decoder: *Decoder, reader: *Reader) Error!void {
        return decoder_table.read(decoder, reader);
    }

    /// Writes every owed instruction that fits (RFC 9204 §4.4), oldest first.
    pub fn write_decoder_stream(decoder: *Decoder, writer: *Writer) void {
        decoder_stream.write(decoder, writer);
    }

    /// A blocked stream whose section the dynamic table can now decode, the one blocked longest,
    /// or null. RFC 9204 §2.2.1: a stream unblocks once the insert count reaches what its section
    /// requires.
    pub fn ready_stream(decoder: *const Decoder) ?u64 {
        const inserted = decoder.table.insert_count();
        for (decoder.blocked[0..decoder.blocked_len]) |held| {
            if (held.required_insert_count <= inserted) return held.stream_id;
        }
        return null;
    }

    /// RFC 9204 §2.2.2.2: the stream was reset, or its reading abandoned, before every section
    /// on it was decoded.
    pub fn abandon_stream(decoder: *Decoder, stream_id: u64) Abandoned {
        // §2.2.2.2: a decoder whose maximum table capacity is zero MAY omit the cancellation,
        // because the encoder cannot have any dynamic table references.
        if (decoder.settings.max_table_capacity == 0) {
            assert(decoder.blocked_len == 0);
            return .cancelled;
        }
        if (decoder.owed_len == decoder.owed.len) return .owes_instructions;
        decoder.unblock(stream_id);
        decoder.owe(.{ .stream_cancellation = stream_id });
        return .cancelled;
    }

    fn block(decoder: *Decoder, stream_id: u64, required: u64) Error!Outcome {
        for (decoder.blocked[0..decoder.blocked_len]) |held| {
            if (held.stream_id == stream_id) return .blocked;
        }
        // RFC 9204 §2.1.2: more blocked streams than the decoder promised to support is
        // QPACK_DECOMPRESSION_FAILED.
        if (decoder.still_blocked() >= decoder.settings.blocked_streams) return Error.DecompressionFailed;
        // Fewer than `blocked_streams` still wait, so a full list holds streams that are ready.
        if (decoder.blocked_len == decoder.blocked.len) {
            assert(decoder.ready_stream() != null);
            return .read_ready_first;
        }
        decoder.blocked[decoder.blocked_len] = .{ .stream_id = stream_id, .required_insert_count = required };
        decoder.blocked_len += 1;
        return .blocked;
    }

    /// How many held streams still wait for entries. RFC 9204 §2.2.1: a stream "becomes
    /// unblocked when the Insert Count becomes greater than or equal to the Required Insert
    /// Count", before its section is read again, and an encoder told of the entries no longer
    /// counts it (spec/tla/qpack_tables).
    fn still_blocked(decoder: *const Decoder) usize {
        const inserted = decoder.table.insert_count();
        var count: usize = 0;
        for (decoder.blocked[0..decoder.blocked_len]) |held| {
            if (held.required_insert_count > inserted) count += 1;
        }
        return count;
    }

    /// Takes the stream off the blocked list, keeping the others in the order they blocked.
    fn unblock(decoder: *Decoder, stream_id: u64) void {
        for (decoder.blocked[0..decoder.blocked_len], 0..) |held, index| {
            if (held.stream_id != stream_id) continue;
            std.mem.copyForwards(Section, decoder.blocked[index .. decoder.blocked_len - 1], decoder.blocked[index + 1 .. decoder.blocked_len]);
            decoder.blocked_len -= 1;
            return;
        }
    }

    fn owe(decoder: *Decoder, instruction: Owed) void {
        assert(decoder.owed_len < decoder.owed.len);
        assert(decoder.settings.max_table_capacity > 0);
        decoder.owed[decoder.owed_len] = instruction;
        decoder.owed_len += 1;
    }

    /// Reads every field line, and returns one past the largest absolute index referenced, or
    /// zero when no line references the dynamic table.
    fn read_lines(decoder: *const Decoder, cursor: *Reader, strings: *Writer, section: *FieldSection, origin: Origin) Error!u64 {
        var reach: u64 = 0;
        // Bounded by the octets the caller gave, since every representation consumes at least one.
        while (cursor.remaining_len() > 0) {
            const line = try representation.read(cursor, strings);
            const resolved = try decoder.resolve(line, origin);
            if (resolved.absolute) |absolute| reach = @max(reach, absolute + 1);
            try append(section, resolved.name, resolved.value);
        }
        return reach;
    }

    /// The field line a representation names.
    fn resolve(decoder: *const Decoder, line: Representation, origin: Origin) Error!Resolved {
        return switch (line) {
            .indexed => |held| if (held.table == .static)
                try static_line(held.index, null)
            else
                try decoder.dynamic_line(try origin.relative(held.index), origin, null),
            .indexed_post_base => |held| try decoder.dynamic_line(origin.post_base(held.index), origin, null),
            .literal_name_reference => |held| if (held.table == .static)
                try static_line(held.name_index, held.value)
            else
                try decoder.dynamic_line(try origin.relative(held.name_index), origin, held.value),
            .literal_post_base_name_reference => |held| try decoder.dynamic_line(origin.post_base(held.name_index), origin, held.value),
            .literal => |held| .{ .name = held.name, .value = held.value },
        };
    }

    /// The dynamic entry at `absolute`, with `literal_value` in place of its value when the
    /// representation carried one.
    fn dynamic_line(decoder: *const Decoder, absolute: u64, origin: Origin, literal_value: ?[]const u8) Error!Resolved {
        // RFC 9204 §2.2.3: a reference to an entry at or above the Required Insert Count, or to
        // one already evicted, is QPACK_DECOMPRESSION_FAILED.
        if (absolute >= origin.required) return Error.DecompressionFailed;
        const entry = decoder.table.get_absolute(absolute) orelse return Error.DecompressionFailed;
        return .{ .name = entry.name, .value = literal_value orelse entry.value, .absolute = absolute };
    }
};

/// What a section's references are resolved against (RFC 9204 §4.5.1).
const Origin = struct {
    required: u64,
    base: u64,

    /// RFC 9204 §3.2.5: in a field line, relative index 0 is the entry at absolute `base - 1`.
    fn relative(origin: Origin, index: u64) Error!u64 {
        // §2.2.3: an index that names no entry below the Base references nothing that exists.
        if (index >= origin.base) return Error.DecompressionFailed;
        return origin.base - 1 - index;
    }

    /// RFC 9204 §3.2.6: post-Base index 0 is the entry at absolute `base`.
    fn post_base(origin: Origin, index: u64) u64 {
        return origin.base +| index;
    }
};

/// One field line resolved, and the absolute index of the dynamic entry it used, if any.
const Resolved = struct {
    name: []const u8,
    value: []const u8,
    absolute: ?u64 = null,
};

/// The static entry at `index` (RFC 9204 §3.1), with `literal_value` in place of its value.
fn static_line(index: u64, literal_value: ?[]const u8) Error!Resolved {
    // RFC 9204 §3.1: an invalid static table index in a field line representation is
    // QPACK_DECOMPRESSION_FAILED.
    if (index >= constants.static_table_entries) return Error.DecompressionFailed;
    const entry = static_table.entries[@intCast(index)];
    return .{ .name = entry.name, .value = literal_value orelse entry.value };
}

fn append(section: *FieldSection, name: []const u8, value: []const u8) Error!void {
    // RFC 9204 §7.4: a value larger than the decoder is able to decode is a stream error of
    // QPACK_DECOMPRESSION_FAILED.
    if (name.len > core.constants.field_name_len_max) return Error.FieldTooLong;
    if (value.len > core.constants.field_value_len_max) return Error.FieldTooLong;
    try section.append(name, value);
}

test {
    _ = @import("decoder_test.zig");
}
