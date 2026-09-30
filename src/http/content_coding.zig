//! Content codings (RFC 9110 §8.4.1) as the client and the server exchange them (decision 101,
//! design §8 step 17e): the codings colibri codes, their names in Content-Encoding (§8.4) and
//! Accept-Encoding (§12.5.3), and the weights an Accept-Encoding field gives them (§12.4.2). It
//! reads field values and codes nothing: `server` holds the encoders and `client` the decoders.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const field = @import("field.zig");

/// The content codings colibri codes, with stdx (decision 101): `gzip` (RFC 9110 §8.4.1.3),
/// `deflate`, which is the zlib format (§8.4.1.2), `zstd` (RFC 8878 §7.2) and `br` (RFC 7932 §13).
/// The server encodes `gzip` and `deflate` alone, and the client decodes all four (decision 101 as
/// amended on 2026-09-30).
pub const Coding = enum {
    gzip,
    deflate,
    zstd,
    br,

    /// The coding's name in a field value, as the HTTP Content Coding Registry holds it (RFC 9110
    /// §16.6.1, RFC 8878 §7.2, RFC 7932 §13).
    pub fn name(coding: Coding) []const u8 {
        return switch (coding) {
            .gzip => "gzip",
            .deflate => "deflate",
            .zstd => "zstd",
            .br => "br",
        };
    }
};

/// The coding a content-coding token names, or null for one colibri does not code. RFC 9110 §8.4.1:
/// "All content codings are case-insensitive". §8.4.1.3: "A recipient SHOULD consider "x-gzip" to
/// be equivalent to "gzip"."
pub fn from_name(token: []const u8) ?Coding {
    if (std.ascii.eqlIgnoreCase(token, "gzip") or std.ascii.eqlIgnoreCase(token, "x-gzip")) return .gzip;
    if (std.ascii.eqlIgnoreCase(token, "deflate")) return .deflate;
    if (std.ascii.eqlIgnoreCase(token, "zstd")) return .zstd;
    if (std.ascii.eqlIgnoreCase(token, "br")) return .br;
    return null;
}

/// A weight in thousandths: 0, not acceptable, to 1000, the most preferred (RFC 9110 §12.4.2).
pub const Weight = u16;
pub const weight_max: Weight = 1000;

/// What Accept-Encoding says of the codings colibri codes: each one's weight when the field lists
/// it, and the weight of "*", which covers every coding the field does not list (RFC 9110
/// §12.5.3). `identity` changes nothing here, since a server that finds no coding acceptable
/// sends the content uncoded (decision 101, §12.4.1).
pub const Acceptance = struct {
    weights: std.EnumArray(Coding, ?Weight) = .initFill(null),
    star: ?Weight = null,

    /// The weight `coding` has: its own, else that of "*", else 0. RFC 9110 §12.5.3: a coding the
    /// field lists "is acceptable unless it is accompanied by a qvalue of 0", and "*" "matches any
    /// available content coding not explicitly listed".
    pub fn weight_of(acceptance: *const Acceptance, coding: Coding) Weight {
        if (acceptance.weights.get(coding)) |weight| return weight;
        return acceptance.star orelse 0;
    }

    /// The coding of `preferred` the field accepts with the highest nonzero weight, the first of
    /// them in `preferred` on a tie (RFC 9110 §12.5.3, decision 101), or null when it accepts
    /// none.
    pub fn choose(acceptance: *const Acceptance, preferred: []const Coding) ?Coding {
        var chosen: ?Coding = null;
        var chosen_weight: Weight = 0;
        for (preferred) |coding| {
            const weight = acceptance.weight_of(coding);
            // RFC 9110 §12.4.2: "a value of 0 means "not acceptable"".
            if (weight > chosen_weight) {
                chosen = coding;
                chosen_weight = weight;
            }
        }
        return chosen;
    }
};

pub const Error = error{
    /// The value breaks RFC 9110 §12.5.3's grammar, or a qvalue §12.4.2's.
    AcceptEncodingInvalid,
};

/// Reads one Accept-Encoding field line's value into `acceptance`. Several lines are one list (RFC
/// 9110 §5.3), read in order, and the first weight a coding gets is the one it keeps.
pub fn read_accept(acceptance: *Acceptance, value: []const u8) Error!void {
    var reader = core.Reader.init(value);
    // Bounded: each pass reads an element or an empty one's comma.
    for (0..value.len + 1) |_| {
        skip_whitespace(&reader);
        if (reader.remaining_len() == 0) return;
        // RFC 9110 §5.6.1.2: a recipient ignores empty list elements.
        if (take(&reader, ',')) continue;
        try read_element(acceptance, &reader);
        skip_whitespace(&reader);
        if (reader.remaining_len() == 0) return;
        // RFC 9110 §5.6.1: a comma separates the list's elements.
        if (!take(&reader, ',')) return error.AcceptEncodingInvalid;
    }
    unreachable;
}

/// Reads `codings [ weight ]` (RFC 9110 §12.5.3).
fn read_element(acceptance: *Acceptance, reader: *core.Reader) Error!void {
    const token = read_token(reader);
    // RFC 9110 §12.5.3: codings = content-coding / "identity" / "*", each a token.
    if (token.len == 0) return error.AcceptEncodingInvalid;
    const weight = try read_weight(reader);
    if (std.mem.eql(u8, token, "*")) {
        if (acceptance.star == null) acceptance.star = weight;
        return;
    }
    const coding = from_name(token) orelse return;
    if (acceptance.weights.get(coding) == null) acceptance.weights.set(coding, weight);
}

/// Reads the optional `weight = OWS ";" OWS "q=" qvalue` (RFC 9110 §12.4.2), 1000 when absent.
fn read_weight(reader: *core.Reader) Error!Weight {
    var ahead = reader.*;
    skip_whitespace(&ahead);
    if (!take(&ahead, ';')) return weight_max;
    skip_whitespace(&ahead);
    // RFC 9110 §12.4.2: a weight's ";" is followed by its parameter.
    const q = ahead.read_byte() catch return error.AcceptEncodingInvalid;
    // RFC 9110 §12.4.2: the parameter is named "q", case-insensitively, and nothing else.
    if (std.ascii.toLower(q) != 'q' or !take(&ahead, '=')) return error.AcceptEncodingInvalid;
    const weight = try read_qvalue(&ahead);
    reader.* = ahead;
    return weight;
}

/// Reads `qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )` (RFC 9110 §12.4.2).
fn read_qvalue(reader: *core.Reader) Error!Weight {
    // RFC 9110 §12.4.2: a qvalue has at least its integral digit.
    const whole = reader.read_byte() catch return error.AcceptEncodingInvalid;
    // RFC 9110 §12.4.2: the weight is 0 or 1 before the point.
    if (whole != '0' and whole != '1') return error.AcceptEncodingInvalid;
    const integral: Weight = if (whole == '1') weight_max else 0;
    if (!take(reader, '.')) return integral;
    const weight = integral + read_decimals(reader);
    // RFC 9110 §12.4.2: 1 takes only zeros after the point. A fourth digit, which a sender "MUST
    // NOT generate", is left unread, and `read_accept` refuses it as no comma (§5.6.1).
    if (weight > weight_max) return error.AcceptEncodingInvalid;
    return weight;
}

/// The thousandths the digits after a qvalue's point give, at most three of them.
fn read_decimals(reader: *core.Reader) Weight {
    var thousandths: Weight = 0;
    var scale: Weight = weight_max / decimal_base;
    for (0..qvalue_decimals_max) |_| {
        const digit = reader.peek_byte() catch break;
        if (!std.ascii.isDigit(digit)) break;
        _ = reader.read_byte() catch unreachable;
        thousandths += (digit - '0') * scale;
        scale /= decimal_base;
    }
    return thousandths;
}

const decimal_base: Weight = 10;
const qvalue_decimals_max: usize = 3;

fn read_token(reader: *core.Reader) []const u8 {
    const rest = reader.peek_rest();
    var len: usize = 0;
    while (len < rest.len and field.is_tchar(rest[len])) len += 1;
    return reader.take(len) catch unreachable;
}

/// RFC 9110 §5.6.3: OWS is spaces and horizontal tabs.
fn skip_whitespace(reader: *core.Reader) void {
    const rest = reader.peek_rest();
    var len: usize = 0;
    while (len < rest.len and (rest[len] == ' ' or rest[len] == '\t')) len += 1;
    _ = reader.take(len) catch unreachable;
}

fn take(reader: *core.Reader, octet: u8) bool {
    const next = reader.peek_byte() catch return false;
    if (next != octet) return false;
    _ = reader.read_byte() catch unreachable;
    return true;
}

const testing = std.testing;

fn accept(value: []const u8) !Acceptance {
    var acceptance: Acceptance = .{};
    try read_accept(&acceptance, value);
    return acceptance;
}

test "RFC 9110 §8.4.1: coding names are case-insensitive, and x-gzip is gzip" {
    try testing.expectEqual(Coding.gzip, from_name("GZip").?);
    try testing.expectEqual(Coding.gzip, from_name("x-gzip").?);
    try testing.expectEqual(Coding.deflate, from_name("Deflate").?);
    // RFC 8878 §7.2 and RFC 7932 §13 register `zstd` and `br`, which colibri decodes too.
    try testing.expectEqual(Coding.zstd, from_name("ZStd").?);
    try testing.expectEqual(Coding.br, from_name("BR").?);
    for (std.enums.values(Coding)) |coding| try testing.expectEqual(coding, from_name(coding.name()).?);
    try testing.expectEqual(null, from_name("compress"));
    try testing.expectEqual(null, from_name("identity"));
}

test "RFC 9110 §12.5.3: the highest nonzero weight wins, and the preference breaks a tie" {
    const both = [_]Coding{ .gzip, .deflate };
    const reversed = [_]Coding{ .deflate, .gzip };
    try testing.expectEqual(Coding.deflate, (try accept("gzip;q=0.5, deflate")).choose(&both).?);
    try testing.expectEqual(Coding.gzip, (try accept("gzip, deflate")).choose(&both).?);
    try testing.expectEqual(Coding.deflate, (try accept("gzip, deflate")).choose(&reversed).?);
    // A coding the server does not apply is never chosen, however the field weighs it.
    const gzip_only = [_]Coding{.gzip};
    try testing.expectEqual(null, (try accept("deflate")).choose(&gzip_only));
}

test "RFC 9110 §12.5.3: q=0 refuses a coding, * covers the unlisted, and an empty field accepts none" {
    const both = [_]Coding{ .gzip, .deflate };
    try testing.expectEqual(null, (try accept("gzip;q=0, deflate;q=0")).choose(&both));
    try testing.expectEqual(Coding.deflate, (try accept("gzip;q=0, *")).choose(&both).?);
    try testing.expectEqual(null, (try accept("*;q=0")).choose(&both));
    try testing.expectEqual(null, (try accept("")).choose(&both));
    try testing.expectEqual(null, (try accept("identity")).choose(&both));
    try testing.expectEqual(Coding.gzip, (try accept(" , gzip ,, ")).choose(&both).?);
    // The first weight a coding gets is the one it keeps, and so does "*".
    try testing.expectEqual(null, (try accept("gzip;q=0, gzip")).choose(&[_]Coding{.gzip}));
    try testing.expectEqual(null, (try accept("*;q=0, *")).choose(&both));
}

test "RFC 9110 §12.4.2: a qvalue is 0 to 1 with at most three decimals, and the q is case-insensitive" {
    try testing.expectEqual(500, (try accept("gzip;q=0.5")).weight_of(.gzip));
    try testing.expectEqual(1, (try accept("gzip ; Q=0.001")).weight_of(.gzip));
    try testing.expectEqual(1000, (try accept("gzip;q=1.000")).weight_of(.gzip));
    try testing.expectEqual(1000, (try accept("gzip;q=1")).weight_of(.gzip));
    try testing.expectEqual(0, (try accept("gzip;q=0.")).weight_of(.gzip));
    try testing.expectError(error.AcceptEncodingInvalid, accept("gzip;q=1.5"));
    try testing.expectError(error.AcceptEncodingInvalid, accept("gzip;q=0.1234"));
    try testing.expectError(error.AcceptEncodingInvalid, accept("gzip;q=2"));
    try testing.expectError(error.AcceptEncodingInvalid, accept("gzip;level=1"));
    try testing.expectError(error.AcceptEncodingInvalid, accept("gzip;x=1"));
    try testing.expectError(error.AcceptEncodingInvalid, accept("gzip deflate"));
    try testing.expectError(error.AcceptEncodingInvalid, accept("gzip;"));
    // RFC 9110 §12.5.3: an element names a coding, "identity" or "*" before any weight.
    try testing.expectError(error.AcceptEncodingInvalid, accept(";q=1"));
}
