//! The decode tool of design §9: a file in the "QPACK Offline Interop" format in, a QIF text out,
//! read by colibri's decoder (decision 74).
//!
//! The format's page starts the table at its maximum capacity "for historical reasons", where
//! RFC 9204 §3.2.2 starts it at zero, so the tool sets it (decision 75). Encoder stream blocks are
//! read as they come, and an instruction may continue in the next one. A section whose stream
//! blocks is kept until `ready_stream` names it. Each set is written as it decodes, under its
//! `# stream` comment.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const qpack = @import("qpack");
const constants = @import("constants.zig");
const qif_text = @import("qif_text.zig");
const qif_block = @import("qif_block.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const FieldSection = qpack.http.field_section.FieldSection;

pub const Settings = struct {
    max_table_capacity: u64,
    blocked_streams: u64,
};

pub const Error = qpack.decoder.Error || core.writer.Error || core.reader.Error || error{
    /// The file ended with a section still waiting for entries that never arrived.
    StillBlocked,
};

pub const Counts = struct {
    sections: u64 = 0,
    lines: u64 = 0,
    blocked: u64 = 0,
};

/// The decoder and its buffers, placed outside any stack frame.
var decoder: qpack.decoder.Decoder = undefined;
var decoded: FieldSection = undefined;
var strings: [core.constants.field_section_size_max]u8 = undefined;
/// Encoder stream octets not yet read: an instruction may span two blocks.
var unread: [constants.file_len_max]u8 = undefined;
var unread_len: usize = 0;
var held: [qpack.constants.blocked_streams_max]qif_block.Block = undefined;
var held_len: usize = 0;

/// A section is read at most twice: once more after the decoder's full queue is written out.
const decode_attempts: usize = 2;

/// Decodes every block of `input` into QIF text in `output`.
pub fn decode(input: []const u8, output: *Writer, settings: Settings) Error!Counts {
    assert(settings.max_table_capacity <= qpack.constants.dynamic_table_capacity_max);
    decoder.init(.{ .max_table_capacity = settings.max_table_capacity, .blocked_streams = settings.blocked_streams });
    decoder.table.set_capacity(settings.max_table_capacity) catch unreachable;
    unread_len = 0;
    held_len = 0;
    var counts: Counts = .{};
    var blocks = Reader.init(input);
    // Bounded by the file: every block consumes at least its header.
    while (blocks.remaining_len() > 0) {
        const block = try qif_block.read(&blocks);
        if (block.stream_id == constants.encoder_stream_id) {
            try read_encoder_stream(block.octets);
            try decode_ready(output, &counts);
        } else if (!try decode_section(block, output, &counts)) {
            assert(held_len < held.len);
            held[held_len] = block;
            held_len += 1;
            counts.blocked += 1;
        }
    }
    if (held_len > 0) return error.StillBlocked;
    return counts;
}

fn read_encoder_stream(octets: []const u8) Error!void {
    if (unread_len + octets.len > unread.len) return error.NoSpaceLeft;
    @memcpy(unread[unread_len..][0..octets.len], octets);
    unread_len += octets.len;
    var reader = Reader.init(unread[0..unread_len]);
    try decoder.read_encoder_stream(&reader);
    // A partial instruction moves to the front, to wait for the next block.
    const rest = reader.take_rest();
    std.mem.copyForwards(u8, &unread, rest);
    unread_len = rest.len;
}

/// Decodes every held section the decoder now has the entries for (RFC 9204 §2.2.1).
fn decode_ready(output: *Writer, counts: *Counts) Error!void {
    // Bounded by the held sections, each decoded once.
    while (decoder.ready_stream()) |stream_id| {
        const index = for (held[0..held_len], 0..) |block, index| {
            if (block.stream_id == stream_id) break index;
        } else unreachable;
        const block = held[index];
        std.mem.copyForwards(qif_block.Block, held[index .. held_len - 1], held[index + 1 .. held_len]);
        held_len -= 1;
        if (!try decode_section(block, output, counts)) return error.StillBlocked;
    }
}

/// Decodes one section and writes it, and answers false when its stream blocks.
fn decode_section(block: qif_block.Block, output: *Writer, counts: *Counts) Error!bool {
    for (0..decode_attempts) |_| {
        decoded.init();
        var reader = Reader.init(block.octets);
        var writer = Writer.init(&strings);
        switch (try decoder.read_section(block.stream_id, &reader, &writer, &decoded)) {
            .decoded => {
                try qif_text.write_set(output, block.stream_id, &decoded);
                counts.sections += 1;
                counts.lines += decoded.len();
                return true;
            },
            .blocked => return false,
            .owes_instructions => drop_decoder_stream(),
            // Ready streams are read after every encoder stream block, so none waits.
            .read_ready_first => return error.StillBlocked,
        }
    }
    unreachable;
}

/// Writes out what the decoder owes, which an offline file has no stream to carry.
fn drop_decoder_stream() void {
    var octets: [constants.decoder_stream_len_max]u8 = undefined;
    var writer = Writer.init(&octets);
    decoder.write_decoder_stream(&writer);
}
