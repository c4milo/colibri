//! The line that starts each chunk of the chunked coding (RFC 9112 §7.1):
//! `chunk-size [ chunk-ext ]`, where `chunk-size = 1*HEXDIG`. The line arrives whole and without
//! its CRLF, which `chunked.zig` has already found.
//!
//! RFC 9112 §7.1 has a recipient "anticipate potentially large hexadecimal numerals and prevent
//! parsing errors due to integer conversion overflows", so a size that does not fit a u64 is
//! refused, however many leading zeros precede it.
//!
//! A chunk extension (§7.1.1) is checked against its grammar and then ignored, because a
//! recipient MUST ignore unrecognized chunk extensions and colibri recognizes none.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("../constants.zig");

const Reader = core.reader.Reader;

pub const Error = error{
    /// A chunk-size that is not one or more hex digits (RFC 9112 §7.1).
    ChunkSizeInvalid,
    /// A chunk-size that does not fit a u64 (RFC 9112 §7.1).
    ChunkSizeTooLarge,
    /// A chunk-ext that does not match its grammar (RFC 9112 §7.1.1).
    ChunkExtensionInvalid,
};

/// The base of a chunk-size (RFC 9112 §7.1).
const hex_radix = 16;

/// The octet before each chunk extension, and between its name and value (RFC 9112 §7.1.1).
const extension_start = ';';
const extension_equals = '=';

/// The octet that opens and closes a quoted-string, and the one that quotes the next octet
/// (RFC 9110 §5.6.4).
const double_quote = '"';
const backslash = '\\';

/// The chunk-size of `line`, after checking the chunk extensions that follow it.
pub fn parse(line: []const u8) Error!u64 {
    assert(line.len <= constants.chunk_line_len_max);
    var reader = Reader.init(line);
    const size = try parse_size(&reader);
    try check_extensions(&reader);
    assert(reader.remaining_len() == 0);
    return size;
}

/// `chunk-size = 1*HEXDIG` (RFC 9112 §7.1).
fn parse_size(reader: *Reader) Error!u64 {
    var size: u64 = 0;
    var digits: usize = 0;
    // Bounded by the line's length.
    for (0..constants.chunk_line_len_max) |_| {
        const octet = reader.peek_byte() catch break;
        const value = std.fmt.charToDigit(octet, hex_radix) catch break;
        _ = reader.read_byte() catch unreachable;
        digits += 1;
        // RFC 9112 §7.1: prevent integer conversion overflows on a large hexadecimal numeral.
        const shifted = std.math.mul(u64, size, hex_radix) catch return error.ChunkSizeTooLarge;
        size = shifted + value;
    }
    // RFC 9112 §7.1: chunk-size = 1*HEXDIG.
    if (digits == 0) return error.ChunkSizeInvalid;
    return size;
}

/// `chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )`, where
/// `chunk-ext-name = token` and `chunk-ext-val = token / quoted-string` (RFC 9112 §7.1.1).
fn check_extensions(reader: *Reader) Error!void {
    // Bounded: each extension consumes at least its ";".
    for (0..constants.chunk_line_len_max) |_| {
        if (try at_end_after_whitespace(reader)) return;
        if (try check_extension(reader)) return;
    }
    unreachable;
}

/// One chunk extension, from its ";". True when the line ended with it.
fn check_extension(reader: *Reader) Error!bool {
    const octet = reader.read_byte() catch unreachable;
    // RFC 9112 §7.1.1: each chunk extension starts with ";".
    if (octet != extension_start) return error.ChunkExtensionInvalid;
    skip_whitespace(reader);
    // RFC 9112 §7.1.1: chunk-ext-name = token.
    if (take_token(reader).len == 0) return error.ChunkExtensionInvalid;
    if (try at_end_after_whitespace(reader)) return true;
    const next = reader.peek_byte() catch unreachable;
    if (next != extension_equals) return false;
    _ = reader.read_byte() catch unreachable;
    skip_whitespace(reader);
    try check_extension_value(reader);
    return false;
}

/// Skips BWS, and answers whether the line ended there. RFC 9112 §7.1.1 puts BWS before ";" and
/// "=" and nowhere else, so whitespace that ends the line, after the size or after an extension,
/// is none of the grammar's.
fn at_end_after_whitespace(reader: *Reader) Error!bool {
    const before = reader.offset;
    skip_whitespace(reader);
    if (reader.remaining_len() != 0) return false;
    // RFC 9112 §7.1.1: BWS that nothing follows on the line is refused.
    if (reader.offset != before) return error.ChunkExtensionInvalid;
    return true;
}

/// `chunk-ext-val = token / quoted-string` (RFC 9112 §7.1.1).
fn check_extension_value(reader: *Reader) Error!void {
    // RFC 9112 §7.1.1: after "=", a chunk-ext-val, which is never empty.
    const first = reader.peek_byte() catch return error.ChunkExtensionInvalid;
    if (first == double_quote) return check_quoted_string(reader);
    // RFC 9112 §7.1.1: chunk-ext-val = token / quoted-string, and a token has one tchar at least.
    if (take_token(reader).len == 0) return error.ChunkExtensionInvalid;
}

/// `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` (RFC 9110 §5.6.4).
fn check_quoted_string(reader: *Reader) Error!void {
    assert((reader.peek_byte() catch unreachable) == double_quote);
    _ = reader.read_byte() catch unreachable;
    // Bounded by the line's length.
    for (0..constants.chunk_line_len_max) |_| {
        if (try quoted_octet(reader)) return;
    }
    unreachable;
}

/// One qdtext or quoted-pair of a quoted-string, or its closing DQUOTE, for which it returns true.
fn quoted_octet(reader: *Reader) Error!bool {
    // RFC 9110 §5.6.4: the string ends at its closing DQUOTE, so the line may not end first.
    const octet = reader.read_byte() catch return error.ChunkExtensionInvalid;
    if (octet == double_quote) return true;
    if (octet == backslash) {
        // RFC 9110 §5.6.4: quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text ), so an octet follows.
        const quoted = reader.read_byte() catch return error.ChunkExtensionInvalid;
        // RFC 9110 §5.6.4: what a quoted-pair quotes is HTAB, SP, VCHAR or obs-text.
        if (!is_quoted_pair_octet(quoted)) return error.ChunkExtensionInvalid;
        return false;
    }
    // RFC 9110 §5.6.4: qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text.
    if (!is_quoted_pair_octet(octet)) return error.ChunkExtensionInvalid;
    return false;
}

/// HTAB, SP, VCHAR or obs-text: what a quoted-pair quotes, and, less DQUOTE and "\", what qdtext
/// is (RFC 9110 §5.6.4).
fn is_quoted_pair_octet(octet: u8) bool {
    return octet == '\t' or octet == ' ' or (octet >= '!' and octet != delete);
}

/// DEL, the one control above VCHAR's range (RFC 5234 Appendix B.1).
const delete = 0x7f;

/// The run of tchar at the reader, which may be empty (RFC 9110 §5.6.2).
fn take_token(reader: *Reader) []const u8 {
    const start = reader.offset;
    // Bounded by the line's length.
    for (0..constants.chunk_line_len_max) |_| {
        const octet = reader.peek_byte() catch break;
        if (!http.field.is_tchar(octet)) break;
        _ = reader.read_byte() catch unreachable;
    }
    return reader.consumed_since(start);
}

/// BWS: SP and HTAB (RFC 9110 §5.6.3).
fn skip_whitespace(reader: *Reader) void {
    // Bounded by the line's length.
    for (0..constants.chunk_line_len_max) |_| {
        const octet = reader.peek_byte() catch return;
        if (octet != ' ' and octet != '\t') return;
        _ = reader.read_byte() catch unreachable;
    }
}

const testing = std.testing;

test "RFC 9112 §7.1: a chunk-size is hex digits in either case, leading zeros included" {
    try testing.expectEqual(0, try parse("0"));
    try testing.expectEqual(0, try parse("000"));
    try testing.expectEqual(0x1a, try parse("1A"));
    try testing.expectEqual(0x1a, try parse("001a"));
    try testing.expectEqual(std.math.maxInt(u64), try parse("ffffffffffffffff"));
    try testing.expectEqual(std.math.maxInt(u64), try parse("0000ffffffffffffffff"));
}

test "RFC 9112 §7.1: no digits, other octets, or a size past a u64 is refused" {
    try testing.expectError(error.ChunkSizeInvalid, parse(""));
    try testing.expectError(error.ChunkSizeInvalid, parse(";a"));
    try testing.expectError(error.ChunkSizeInvalid, parse(" 1"));
    try testing.expectError(error.ChunkSizeInvalid, parse("-1"));
    // "0" is the size, and "x1" is no chunk extension.
    try testing.expectError(error.ChunkExtensionInvalid, parse("0x1"));
    try testing.expectError(error.ChunkSizeTooLarge, parse("10000000000000000"));
    try testing.expectError(error.ChunkExtensionInvalid, parse("1g"));
    try testing.expectError(error.ChunkExtensionInvalid, parse("1 2"));
}

test "RFC 9112 §7.1.1: chunk extensions are checked and ignored" {
    for ([_][]const u8{ "5;a", "5 ; a", "5;a=b", "5;a = b", "5;a=\"b c\"", "5;a=\"q\\\"d\";b;c=d", "5\t;\ta\t=\t\"\"" }) |line| {
        try testing.expectEqual(5, try parse(line));
    }
}

test "RFC 9112 §7.1.1: a malformed chunk extension is refused" {
    for ([_][]const u8{ "5;", "5;=b", "5;a=", "5;a=\"b", "5;a=b c", "5 a", "5;a=\"\x7f\"", "5;a=\"\\\x00\"", "5;a b", "5;(a)", "5;a=;b", "5 ", "5\t", "5;a ", "5;a=b\t", "5;a=\"b\" " }) |line| {
        try testing.expectError(error.ChunkExtensionInvalid, parse(line));
    }
}
