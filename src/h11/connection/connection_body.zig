//! A message body, read and written, for both roles (RFC 9112 §6, §7.1). Reading takes the octets
//! the caller holds and returns data as slices of them; writing frames the caller's data by the
//! length the head declared. Nothing here knows which role it serves.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const message = @import("../message/message.zig");
const chunked = @import("../chunked/chunked.zig");

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
            var octets = core.reader.Reader.init(input);
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

/// Where the writing of one body stands.
pub const Writer = struct {
    kind: Kind = .none,
    /// Octets of a fixed body still owed.
    remaining: u64 = 0,

    pub const Kind = enum { none, fixed, chunked, close_delimited, tunnel };

    pub fn open(writer: *const Writer) bool {
        return writer.kind != .none;
    }
};

pub const WriteError = chunked.WriteError || error{
    /// More octets than the Content-Length declared (RFC 9112 §6.2).
    BodyTooLong,
    /// The body ended before the Content-Length declared it would (RFC 9112 §6.2).
    BodyIncomplete,
    /// Trailers after a body that is not chunked, which alone carries them (RFC 9112 §7.1.2).
    TrailersWithoutChunked,
};

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
        .chunked => return chunked.write_chunk(output, data),
        .close_delimited, .tunnel => {
            // RFC 9112 §2.1: a body is written whole or not at all into one buffer.
            if (data.len > output.len) return error.OutputTooSmall;
            @memcpy(output[0..data.len], data);
            return data.len;
        },
    }
}

/// Ends the body: the last chunk and `trailers` for a chunked body, nothing for the others.
/// Returns the octets written into `output`.
pub fn end(writer: *Writer, output: []u8, trailers: []const http.field.Field) WriteError!usize {
    assert(writer.open());
    const written: usize = switch (writer.kind) {
        .none => unreachable,
        .chunked => try chunked.write_last_chunk(output, trailers),
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

/// The body a head declares with its own fields: chunked when Transfer-Encoding names it, fixed
/// when Content-Length gives a length, and `otherwise` when neither does.
pub fn declared(fields: []const http.field.Field, otherwise: Writer.Kind) Writer {
    for (fields) |line| {
        if (http.field.names_equal(line.name, "Transfer-Encoding")) return .{ .kind = .chunked };
    }
    for (fields) |line| {
        if (!http.field.names_equal(line.name, http.content_length.name)) continue;
        // The head writers accepted it as 1*DIGIT that fits a u64 (RFC 9110 §8.6).
        const octets = std.fmt.parseUnsigned(u64, line.value, http.constants.content_length_radix) catch unreachable;
        return .{ .kind = if (octets == 0) .none else .fixed, .remaining = octets };
    }
    return .{ .kind = otherwise };
}
