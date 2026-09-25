//! The chunked coding's decoder (RFC 9112 §7.1), over octets the caller has already read. Each
//! call takes every unconsumed octet the caller holds, and consumes the framing it can read and
//! at most one run of chunk data, which it returns as a slice of the caller's octets. The state
//! the caller keeps between calls says where the coding stands, so a body that arrives in any
//! pieces decodes to the same octets (design §4.1).
//!
//! A line of the coding, the chunk-size line or the trailer section, is read only once whole, as a
//! head is, and `search` keeps the place of the search for its end between calls, so each octet
//! is searched once. Each line is held to RFC 9112 §2.2: a bare CR is refused, and so is a lone
//! LF, the strict side of the choice §2.2 leaves.
//!
//! The trailer section (§7.1.2) is read into the caller's `FieldSection`, separately from the
//! header section, and never merged into it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("../constants.zig");
const chunked_line = @import("chunked_line.zig");
const message_scan = @import("../message/message_scan.zig");
const message_fields = @import("../message/message_fields.zig");
const chunked_write = @import("chunked_write.zig");

pub const WriteError = chunked_write.Error;
pub const write_chunk = chunked_write.write_chunk;
pub const write_last_chunk = chunked_write.write_last_chunk;

const FieldSection = http.FieldSection;
const Reader = core.reader.Reader;
const Role = message_scan.Role;

pub const Error = chunked_line.Error || message_fields.Error || error{
    /// A CR not followed by LF in a line of the coding (RFC 9112 §2.2).
    BareCarriageReturn,
    /// An LF not preceded by CR, which colibri does not accept as a line end (RFC 9112 §2.2).
    BareLineFeed,
    /// A chunk-size line longer than `chunk_line_len_max` (RFC 9112 §7.1.1).
    ChunkLineTooLong,
    /// Chunk data not followed by CRLF (RFC 9112 §7.1).
    ChunkDataEndInvalid,
    /// A trailer section longer than `trailer_len_max` (RFC 9110 §5.4).
    TrailerTooLarge,
};

/// Where the coding stands.
pub const State = enum {
    /// Before a chunk-size line.
    size_line,
    /// Inside a chunk's data, with `remaining` octets of it to come.
    data,
    /// After a chunk's data, before its CRLF.
    data_end,
    /// After the last chunk, before the end of the trailer section.
    trailer,
    /// The coding has ended.
    done,
};

/// What one call decoded.
pub const Decoded = struct {
    /// Octets of the caller's input the call consumed. `data` is among them.
    consumed: usize,
    /// Chunk data, a slice of the caller's input. Empty when the call read framing alone.
    data: []const u8,
    /// The coding and its trailer section have ended; the trailer fields are in the section the
    /// caller passed.
    done: bool,
};

/// The CR and LF that end every line (RFC 9112 §2.1).
const line_end = "\r\n";

/// Most octets of a chunk-size line with its CRLF.
const size_line_octets_max = constants.chunk_line_len_max + line_end.len;

/// What a search for the end of a line looks for: the end of one line, or the empty line that ends
/// a section of lines, which may be the first.
const Until = enum { line, empty_line };

/// The place of a search for the end of a line, or of a section, kept between calls.
const Search = struct {
    /// Octets searched so far, from the start of the line or section.
    scanned: u32 = 0,
    /// Octets of the current line searched so far, its CR not counted.
    line_len: u32 = 0,
    /// The last octet searched was a CR, so the next must be LF.
    after_carriage_return: bool = false,

    /// Searches the octets of `octets` not searched before, up to `octets_max` in all. Returns the
    /// offset past the CRLF that ends what `until` names, or null while it has not arrived.
    fn find(search: *Search, until: Until, octets: []const u8, octets_max: u32) Error!?u32 {
        assert(search.scanned <= octets.len and search.scanned <= octets_max);
        var reader = Reader.init(octets[0..@min(octets.len, octets_max)]);
        _ = reader.take(search.scanned) catch unreachable;
        // Bounded by `octets_max`.
        for (0..octets_max) |_| {
            const octet = reader.read_byte() catch return null;
            search.scanned += 1;
            if (try search.step(until, octet)) {
                const end = search.scanned;
                search.* = .{};
                return end;
            }
        }
        return null;
    }

    /// One octet. Returns true when it is the LF that ends the search.
    fn step(search: *Search, until: Until, octet: u8) Error!bool {
        if (search.after_carriage_return) {
            search.after_carriage_return = false;
            // RFC 9112 §2.2: a CR not immediately followed by LF is a bare CR.
            if (octet != '\n') return error.BareCarriageReturn;
            const empty = search.line_len == 0;
            search.line_len = 0;
            return until == .line or empty;
        }
        if (octet == '\r') {
            search.after_carriage_return = true;
            return false;
        }
        // RFC 9112 §2.2: a recipient MAY recognize a lone LF as a line end; colibri does not.
        if (octet == '\n') return error.BareLineFeed;
        search.line_len += 1;
        return false;
    }
};

pub const Decoder = struct {
    state: State = .size_line,
    /// Data octets left in the current chunk.
    remaining: u64 = 0,
    search: Search = .{},

    /// Decodes from the start of `input`, which holds every octet the last call did not consume
    /// and any that arrived since.
    pub fn decode(decoder: *Decoder, role: Role, input: []const u8, trailers: *FieldSection) Error!Decoded {
        assert(decoder.state != .done);
        var reader = Reader.init(input);
        // Bounded: every pass but the last consumes a line, a CRLF, or data.
        for (0..input.len + 1) |_| {
            const progressed = switch (decoder.state) {
                .size_line => try decoder.read_size_line(&reader),
                .data => return decoder.take_data(&reader),
                .data_end => try decoder.read_data_end(&reader),
                .trailer => try decoder.read_trailer(role, &reader, trailers),
                .done => return .{ .consumed = reader.offset, .data = &.{}, .done = true },
            };
            if (!progressed) break;
        }
        return .{ .consumed = reader.offset, .data = &.{}, .done = false };
    }

    /// Reads a whole chunk-size line, or returns false when it is not whole yet.
    fn read_size_line(decoder: *Decoder, reader: *Reader) Error!bool {
        const end = try decoder.search.find(.line, reader.peek_rest(), size_line_octets_max) orelse {
            // RFC 9112 §7.1.1: a server ought to limit the chunk extensions it accepts, so
            // colibri's limit applies to the whole line.
            if (reader.remaining_len() >= size_line_octets_max) return error.ChunkLineTooLong;
            return false;
        };
        const line = reader.take(end - line_end.len) catch unreachable;
        _ = reader.take(line_end.len) catch unreachable;
        const size = try chunked_line.parse(line);
        if (size > 0) {
            decoder.remaining = size;
            decoder.state = .data;
            return true;
        }
        // RFC 9112 §7.1: the coding is complete at a chunk-size of zero, which the trailer
        // section and an empty line follow. Reading that section empties the caller's first.
        decoder.state = .trailer;
        return true;
    }

    fn take_data(decoder: *Decoder, reader: *Reader) Decoded {
        assert(decoder.remaining > 0);
        const available = @min(decoder.remaining, reader.remaining_len());
        const data = reader.take(@intCast(available)) catch unreachable;
        decoder.remaining -= available;
        if (decoder.remaining == 0) decoder.state = .data_end;
        return .{ .consumed = reader.offset, .data = data, .done = false };
    }

    /// Reads the CRLF after a chunk's data, or returns false when it has not arrived.
    fn read_data_end(decoder: *Decoder, reader: *Reader) Error!bool {
        const octets = reader.take(line_end.len) catch return false;
        // RFC 9112 §7.1: chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF.
        if (!std.mem.eql(u8, octets, line_end)) return error.ChunkDataEndInvalid;
        decoder.state = .size_line;
        return true;
    }

    /// Reads the whole trailer section into `trailers`, or returns false when it is not whole.
    fn read_trailer(decoder: *Decoder, role: Role, reader: *Reader, trailers: *FieldSection) Error!bool {
        const end = try decoder.search.find(.empty_line, reader.peek_rest(), constants.trailer_len_max) orelse {
            // RFC 9110 §5.4: no predefined limit on a section, so colibri's applies.
            if (reader.remaining_len() >= constants.trailer_len_max) return error.TrailerTooLarge;
            return false;
        };
        const section = reader.take(end) catch unreachable;
        // RFC 9112 §7.1.2: trailer-section = *( field-line CRLF ), then the CRLF that ends the
        // coding. The field lines are read as a head's are.
        try message_fields.parse(role, section, trailers);
        decoder.state = .done;
        return true;
    }
};

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_trailers: FieldSection = undefined;

/// Decodes `input` whole, one call after another, and returns the data it held.
fn decode_all(role: Role, input: []const u8, data: []u8) ![]const u8 {
    var decoder: Decoder = .{};
    var offset: usize = 0;
    var written: usize = 0;
    for (0..input.len + 1) |_| {
        const decoded = try decoder.decode(role, input[offset..], &test_trailers);
        @memcpy(data[written..][0..decoded.data.len], decoded.data);
        written += decoded.data.len;
        offset += decoded.consumed;
        if (decoded.done) {
            try testing.expectEqual(input.len, offset);
            return data[0..written];
        }
        if (decoded.consumed == 0) return error.TestUnexpectedResult;
    }
    return error.TestUnexpectedResult;
}

test "RFC 9112 §7.1: chunks decode to their data, and the coding ends at a zero-size chunk" {
    var data: [64]u8 = undefined;
    try testing.expectEqualStrings("Wikipedia", try decode_all(.request, "4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n", &data));
    try testing.expectEqual(0, test_trailers.len());
    try testing.expectEqualStrings("", try decode_all(.request, "000\r\n\r\n", &data));
    try testing.expectEqualStrings("abcdefghij", try decode_all(.response, "A\r\nabcdefghij\r\n0\r\n\r\n", &data));
}

test "RFC 9112 §7.1.2: the trailer section is read into its own section" {
    var data: [64]u8 = undefined;
    try testing.expectEqualStrings("ab", try decode_all(.request, "2\r\nab\r\n0\r\nChecksum: 1\r\nX: y\r\n\r\n", &data));
    try testing.expectEqual(2, test_trailers.len());
    try testing.expectEqualStrings("1", test_trailers.find("checksum").?.value);
    // A client joins a folded trailer value as it joins a folded header value (RFC 9112 §5.2).
    _ = try decode_all(.response, "0\r\nX: a\r\n b\r\n\r\n", &data);
    try testing.expectEqualStrings("a b", test_trailers.find("x").?.value);
}

/// The longest input `decode_in_pieces` holds, and the passes it allows per octet of it.
const test_input_len_max = 128;
const test_passes_per_octet = 4;

/// Feeds `input` to a decoder `split` octets at a time, keeping what each call does not consume,
/// and returns the data it decoded.
fn decode_in_pieces(input: []const u8, split: usize, data: []u8) ![]const u8 {
    var decoder: Decoder = .{};
    var held: [test_input_len_max]u8 = undefined;
    var held_len: usize = 0;
    var written: usize = 0;
    var fed: usize = 0;
    // Bounded: each pass feeds at least one octet, and the decoder consumes what it can.
    for (0..input.len * test_passes_per_octet) |_| {
        const piece_end = @min(input.len, fed + split);
        @memcpy(held[held_len..][0 .. piece_end - fed], input[fed..piece_end]);
        held_len += piece_end - fed;
        fed = piece_end;
        const decoded = try decoder.decode(.request, held[0..held_len], &test_trailers);
        @memcpy(data[written..][0..decoded.data.len], decoded.data);
        written += decoded.data.len;
        std.mem.copyForwards(u8, held[0 .. held_len - decoded.consumed], held[decoded.consumed..held_len]);
        held_len -= decoded.consumed;
        if (decoded.done) return data[0..written];
    }
    return error.TestUnexpectedResult;
}

test "every split of a chunked body decodes to the same data and trailers" {
    const input = "3;a=\"b\"\r\nabc\r\n10\r\n0123456789abcdef\r\n0\r\nT: v\r\n\r\n";
    for (1..input.len) |split| {
        var data: [64]u8 = undefined;
        try testing.expectEqualStrings("abc0123456789abcdef", try decode_in_pieces(input, split, &data));
        try testing.expectEqualStrings("v", test_trailers.find("t").?.value);
    }
}

test "RFC 9112 §2.2 and §7.1: a bare CR, a lone LF, or data without its CRLF is refused" {
    var data: [64]u8 = undefined;
    try testing.expectError(error.BareLineFeed, decode_all(.request, "2\nab\r\n0\r\n\r\n", &data));
    try testing.expectError(error.BareCarriageReturn, decode_all(.request, "2\rab\r\n0\r\n\r\n", &data));
    try testing.expectError(error.ChunkDataEndInvalid, decode_all(.request, "2\r\nabc\r\n0\r\n\r\n", &data));
    try testing.expectError(error.ChunkDataEndInvalid, decode_all(.request, "2\r\nab\n\r0\r\n\r\n", &data));
    try testing.expectError(error.BareLineFeed, decode_all(.request, "0\r\nX: a\n\r\n", &data));
    try testing.expectError(error.ChunkSizeInvalid, decode_all(.request, "\r\n", &data));
    try testing.expectError(error.ObsFold, decode_all(.request, "0\r\nX: a\r\n b\r\n\r\n", &data));
}

/// Octets the limit tests fill a line with.
var test_octets: [constants.trailer_len_max + 1]u8 = @splat('a');

test "a chunk-size line or trailer section past its limit is refused, and one at it is read" {
    var decoder: Decoder = .{};
    var line: [size_line_octets_max]u8 = @splat('0');
    @memcpy(line[size_line_octets_max - 3 ..], "1\r\n");
    const at_limit = try decoder.decode(.request, &line, &test_trailers);
    try testing.expectEqual(size_line_octets_max, at_limit.consumed);
    decoder = .{};
    @memcpy(line[size_line_octets_max - 3 ..], "001");
    try testing.expectError(error.ChunkLineTooLong, decoder.decode(.request, &line, &test_trailers));
    decoder = .{ .state = .trailer };
    @memcpy(test_octets[0..3], "X: ");
    try testing.expectError(error.TrailerTooLarge, decoder.decode(.request, test_octets[0..constants.trailer_len_max], &test_trailers));
}

test "a call on a body that is not whole consumes what it can and waits" {
    var decoder: Decoder = .{};
    const first = try decoder.decode(.request, "5\r", &test_trailers);
    try testing.expectEqual(0, first.consumed);
    const second = try decoder.decode(.request, "5\r\nab", &test_trailers);
    try testing.expectEqual(5, second.consumed);
    try testing.expectEqualStrings("ab", second.data);
    try testing.expectEqual(State.data, decoder.state);
    try testing.expectEqual(3, decoder.remaining);
}
