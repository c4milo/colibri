//! The encode tool of design §9: a QIF text in, a file in the "QPACK Offline Interop" format out,
//! written by colibri's encoder (decision 76).
//!
//! Each header set is a section on the next request stream, from 1. Its encoder stream octets go
//! in a block ahead of its section, so a decoder that reads the file in order never blocks. In the
//! format's immediate acknowledgment mode the encoder hears, after each section, what a decoder
//! that received everything would send: the Section Acknowledgment and an Insert Count Increment
//! for the rest (RFC 9204 §4.4.1, §4.4.3).
const std = @import("std");
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
    /// The format's acknowledgment mode: immediate, or none.
    immediate_acknowledgment: bool,
};

pub const Error = qif_text.Error || core.writer.Error || error{
    /// The encoder refused an acknowledgment the tool made for it, which is the tool's defect.
    EncoderFailed,
};

pub const Counts = struct {
    sections: u64 = 0,
    lines: u64 = 0,
    inserts: u64 = 0,
};

/// The encoder and its buffers, placed outside any stack frame.
var encoder: qpack.encoder.Encoder = undefined;
var section: FieldSection = undefined;
var section_octets: [constants.section_len_max]u8 = undefined;
var instruction_octets: [constants.section_len_max]u8 = undefined;

/// Encodes every header set of `input` into `output`.
pub fn encode(input: []const u8, output: *Writer, settings: Settings) Error!Counts {
    encoder.init(.when_shorter);
    encoder.on_settings(.{ .max_table_capacity = settings.max_table_capacity, .blocked_streams = settings.blocked_streams });
    var reader = qif_text.Reader.init(input);
    var counts: Counts = .{};
    var stream_id = constants.first_request_stream_id;
    // Bounded by the input's header sets.
    while (try reader.next(&section)) : (stream_id += 1) {
        var encoded = Writer.init(&section_octets);
        var instructions = Writer.init(&instruction_octets);
        try encoder.write_section(stream_id, &encoded, &instructions, &section, &.{});
        if (instructions.written().len > 0) try qif_block.write(output, constants.encoder_stream_id, instructions.written());
        try qif_block.write(output, stream_id, encoded.written());
        if (settings.immediate_acknowledgment) try acknowledge(stream_id);
        counts.sections += 1;
        counts.lines += section.len();
    }
    counts.inserts = encoder.table.insert_count();
    return counts;
}

/// What a decoder that received the section and every insert would send back at once.
fn acknowledge(stream_id: u64) Error!void {
    var octets: [constants.decoder_stream_len_max]u8 = undefined;
    // RFC 9204 §4.4.1: a section whose Required Insert Count is not zero is acknowledged.
    if (encoder.plan.required != 0) {
        var writer = Writer.init(&octets);
        try qpack.instruction.write_decoder(&writer, .{ .section_acknowledgment = stream_id });
        try feed(writer.written());
    }
    // RFC 9204 §4.4.3: the increment raises the Known Received Count to the insert count.
    const increment = encoder.table.insert_count() - encoder.state.known_received;
    if (increment == 0) return;
    var writer = Writer.init(&octets);
    try qpack.instruction.write_decoder(&writer, .{ .insert_count_increment = increment });
    try feed(writer.written());
}

fn feed(octets: []const u8) Error!void {
    var reader = Reader.init(octets);
    encoder.read_decoder_stream(&reader) catch return error.EncoderFailed;
}
