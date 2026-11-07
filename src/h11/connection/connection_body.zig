//! A message body, read and written, for both roles (RFC 9112 §6, §7.1). Reading takes the octets
//! the caller holds and returns data as slices of them; writing frames the caller's data by the
//! length the head declared. Nothing here knows which role it serves.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const message = @import("../message/message.zig");
const chunked = @import("../chunked/chunked.zig");
const coding = @import("../coding.zig");

const Length = message.Length;
const Role = message.Role;

/// Where the reading of one body stands.
pub const Reader = struct {
    kind: Kind = .none,
    /// Octets of a fixed body still to come.
    remaining: u64 = 0,
    decoder: chunked.Decoder = .{},

    pub const Kind = enum { none, fixed, chunked, close_delimited, tunnel };

    pub fn start(length: Length) Reader {
        return switch (length) {
            .none => .{ .kind = .none },
            .fixed => |octets| .{ .kind = if (octets == 0) .none else .fixed, .remaining = octets },
            .chunked => .{ .kind = .chunked },
            .close_delimited => .{ .kind = .close_delimited },
            .tunnel => .{ .kind = .tunnel },
        };
    }

    /// Whether the body is still being read.
    pub fn open(reader: *const Reader) bool {
        return reader.kind != .none;
    }
};

/// What one read of a body found.
pub const Read = struct {
    consumed: usize,
    data: []const u8,
    /// The body ended with this read; a chunked body's trailers are in the section passed.
    ended: bool,
};

pub const ReadError = chunked.Error;

/// Reads from the start of `input`: at most one run of data, and the end of the body when it
/// comes. A close-delimited body ends only when the caller reports the close.
pub fn read(reader: *Reader, role: Role, input: []const u8, trailers: *http.FieldSection) ReadError!Read {
    assert(reader.open());
    switch (reader.kind) {
        .none => unreachable,
        .fixed => {
            const taken: usize = @intCast(@min(reader.remaining, input.len));
            var octets = core.Reader.init(input);
            const data = octets.take(taken) catch unreachable;
            reader.remaining -= taken;
            const ended = reader.remaining == 0;
            if (ended) reader.kind = .none;
            return .{ .consumed = taken, .data = data, .ended = ended };
        },
        .chunked => {
            const decoded = try reader.decoder.decode(role, input, trailers);
            if (decoded.done) reader.kind = .none;
            return .{ .consumed = decoded.consumed, .data = decoded.data, .ended = decoded.done };
        },
        // RFC 9112 §6.3 rules 2 and 8: every octet until the close belongs to the body or tunnel.
        .close_delimited, .tunnel => return .{ .consumed = input.len, .data = input, .ended = false },
    }
}

/// Reads as `read` does, and decodes the data of a body carrying `gzip` or `deflate` into
/// `decoded` (decision 98). What the decoder could not take yet is given back, so the next call
/// reads it again.
pub fn read_coded(
    reader: *Reader,
    decoding: *coding.Decoding,
    storage: coding.Storage,
    role: Role,
    input: []const u8,
    trailers: *http.FieldSection,
    decoded: []u8,
) (ReadError || coding.Error)!Read {
    assert(decoding.active());
    const run = try read(reader, role, input, trailers);
    if (run.data.len == 0) {
        // RFC 9112 §6.3 and decision 91: the body ended, and its coded stream must end with it.
        if (run.ended) try decoding.finish(storage);
        return run;
    }
    // A read that returns data returns nothing after it (`chunked.Decoder.decode`).
    assert(!run.ended);
    const progress = try decoding.decode(storage, run.data, decoded);
    const left = run.data.len - progress.consumed;
    give_back(reader, left);
    var written = core.Reader.init(decoded);
    const data = written.take(progress.written) catch unreachable;
    return .{ .consumed = run.consumed - left, .data = data, .ended = false };
}

/// Takes back the last `octets` of the data the last read returned.
fn give_back(reader: *Reader, octets: usize) void {
    switch (reader.kind) {
        .chunked => reader.decoder.give_back(octets),
        // Every octet until the close is the body's, so octets not taken are simply not consumed.
        .close_delimited => {},
        // RFC 9112 §6.1 and §6.3: a compression coding comes with chunked, or runs until the close.
        .none, .fixed, .tunnel => assert(octets == 0),
    }
}

/// Where the writing of one body stands.
pub const Writer = struct {
    kind: Kind = .none,
    /// Octets of a fixed body still owed, or of the chunk whose head `write_chunk_head` wrote.
    remaining: u64 = 0,
    /// The data of the chunk whose head `write_chunk_head` wrote went out, and the CRLF that ends
    /// it goes before the next chunk or the last chunk (RFC 9112 §7.1).
    crlf_owed: bool = false,

    pub const Kind = enum { none, fixed, chunked, close_delimited, tunnel };

    pub fn open(writer: *const Writer) bool {
        return writer.kind != .none;
    }
};

pub const WriteError = chunked.WriteError || error{
    /// More octets than the Content-Length declared (RFC 9112 §6.2), or than the chunk head
    /// declared (RFC 9112 §7.1).
    BodyTooLong,
    /// The body ended before the Content-Length declared it would (RFC 9112 §6.2).
    BodyIncomplete,
    /// Trailers after a body that is not chunked, which alone carries them (RFC 9112 §7.1.2).
    TrailersWithoutChunked,
    /// A chunk head for a body that is not chunked (RFC 9112 §6.1).
    BodyNotChunked,
    /// A chunk head of length 0, which is the last chunk that `end` writes (RFC 9112 §7.1).
    ChunkEmpty,
    /// A chunk head, or the end of the body, before the data the last chunk head declared went
    /// out (RFC 9112 §7.1).
    ChunkIncomplete,
};

/// The CRLF that ends a chunk's data (RFC 9112 §7.1).
const chunk_data_end = "\r\n";

/// Writes `data` framed as the body declared. Returns the octets written into `output`.
pub fn write(writer: *Writer, output: []u8, data: []const u8) WriteError!usize {
    assert(writer.open());
    assert(data.len > 0);
    switch (writer.kind) {
        .none => unreachable,
        .fixed => {
            // RFC 9112 §6.2: the Content-Length is the number of octets that follow.
            if (data.len > writer.remaining) return error.BodyTooLong;
            // RFC 9112 §2.1: a body is written whole or not at all into one buffer.
            if (data.len > output.len) return error.OutputTooSmall;
            @memcpy(output[0..data.len], data);
            writer.remaining -= data.len;
            return data.len;
        },
        .chunked => return write_chunked(writer, output, data),
        .close_delimited, .tunnel => {
            // RFC 9112 §2.1: a body is written whole or not at all into one buffer.
            if (data.len > output.len) return error.OutputTooSmall;
            @memcpy(output[0..data.len], data);
            return data.len;
        },
    }
}

/// Counts `len` body octets the caller sends from its own buffer, and writes nothing (decision 95).
/// In a chunked body, they are the data of the chunk whose head `write_chunk_head` wrote.
pub fn count(writer: *Writer, len: u64) WriteError!void {
    assert(writer.open());
    assert(len > 0);
    switch (writer.kind) {
        .none => unreachable,
        .fixed => {
            // RFC 9112 §6.2: the Content-Length is the number of octets that follow.
            if (len > writer.remaining) return error.BodyTooLong;
            writer.remaining -= len;
        },
        .chunked => {
            // RFC 9112 §7.1: the caller's octets are the data of the chunk whose head went out,
            // and no more.
            if (len > writer.remaining) return error.BodyTooLong;
            writer.remaining -= len;
            writer.crlf_owed = writer.remaining == 0;
        },
        .close_delimited, .tunnel => {},
    }
}

/// Writes the head of a chunk of `len` octets, which the caller sends next from its own buffer and
/// counts with `count` (decision 139). The head starts with the CRLF the chunk before owes. Returns
/// the octets written into `output`.
pub fn write_chunk_head(writer: *Writer, output: []u8, len: u64) WriteError!usize {
    assert(writer.open());
    // RFC 9112 §6.1: only a body in the chunked coding is written in chunks.
    if (writer.kind != .chunked) return error.BodyNotChunked;
    // RFC 9112 §7.1: a chunk-size of 0 is the last-chunk, which ends the body.
    if (len == 0) return error.ChunkEmpty;
    // RFC 9112 §7.1: the next chunk-size follows all the chunk-data the last one declared.
    if (writer.remaining > 0) return error.ChunkIncomplete;
    const written = try chunked.write_chunk_size(try after_owed(writer, output), len);
    const closed = close_chunk(writer, output);
    writer.remaining = len;
    return closed + written;
}

/// Writes `data` into a chunked body: as more of the data of the chunk whose head went out, or as
/// a whole chunk after it.
fn write_chunked(writer: *Writer, output: []u8, data: []const u8) WriteError!usize {
    assert(writer.kind == .chunked);
    if (writer.remaining == 0) {
        const written = try chunked.write_chunk(try after_owed(writer, output), data);
        return close_chunk(writer, output) + written;
    }
    // RFC 9112 §7.1: the chunk-data is the octets its chunk-size declared, and no more.
    if (data.len > writer.remaining) return error.BodyTooLong;
    // RFC 9112 §2.1: a body is written whole or not at all into one buffer.
    if (data.len > output.len) return error.OutputTooSmall;
    @memcpy(output[0..data.len], data);
    writer.remaining -= data.len;
    writer.crlf_owed = writer.remaining == 0;
    return data.len;
}

/// The part of `output` after the CRLF that the chunk before owes, which `close_chunk` writes once
/// what follows it was written.
fn after_owed(writer: *const Writer, output: []u8) WriteError![]u8 {
    const owed = if (writer.crlf_owed) chunk_data_end.len else 0;
    // RFC 9112 §7.1: the CRLF and what follows it are written together, or not at all.
    if (output.len < owed) return error.OutputTooSmall;
    return output[owed..];
}

/// Writes the CRLF the chunk before owes at the start of `output`, and returns its length: 0 when
/// none is owed (RFC 9112 §7.1).
fn close_chunk(writer: *Writer, output: []u8) usize {
    if (!writer.crlf_owed) return 0;
    @memcpy(output[0..chunk_data_end.len], chunk_data_end);
    writer.crlf_owed = false;
    return chunk_data_end.len;
}

/// Ends the body: the last chunk and `trailers` for a chunked body, nothing for the others.
/// Returns the octets written into `output`.
pub fn end(writer: *Writer, output: []u8, trailers: []const http.Field) WriteError!usize {
    assert(writer.open());
    const written: usize = switch (writer.kind) {
        .none => unreachable,
        .chunked => try end_chunked(writer, output, trailers),
        .fixed, .close_delimited, .tunnel => blk: {
            // RFC 9112 §7.1.2: only the chunked coding carries a trailer section.
            if (trailers.len > 0) return error.TrailersWithoutChunked;
            // RFC 9112 §6.2: a body shorter than its Content-Length is incomplete.
            if (writer.kind == .fixed and writer.remaining > 0) return error.BodyIncomplete;
            break :blk 0;
        },
    };
    writer.kind = .none;
    return written;
}

/// Writes the last chunk and `trailers` after the CRLF the chunk before owes (RFC 9112 §7.1).
fn end_chunked(writer: *Writer, output: []u8, trailers: []const http.Field) WriteError!usize {
    // RFC 9112 §7.1: the last-chunk follows all the chunk-data the last chunk-size declared.
    if (writer.remaining > 0) return error.ChunkIncomplete;
    const written = try chunked.write_last_chunk(try after_owed(writer, output), trailers);
    return close_chunk(writer, output) + written;
}

/// The body a head declares with its own fields, from the pass over them: chunked when
/// Transfer-Encoding names it, fixed when Content-Length gives a length, and `otherwise` when
/// neither does. A server calls it before it writes the head, so it refuses a Content-Length it
/// cannot read.
pub fn declared(checked: *const message.Checked, otherwise: Writer.Kind) error{FramingInvalid}!Writer {
    if (checked.transfer_encoding.value != null) return .{ .kind = .chunked };
    if (checked.content_length.value == null) return .{ .kind = otherwise };
    // RFC 9110 §8.6: Content-Length = 1*DIGIT, and colibri counts a length a u64 holds.
    const octets = checked.content_length_octets orelse return error.FramingInvalid;
    return .{ .kind = if (octets == 0) .none else .fixed, .remaining = octets };
}
