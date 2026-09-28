//! The Alt-Svc field of a response the client reads over TCP (RFC 7838 §3): what it says of an h3
//! endpoint on the origin's own host. The client reads the first alternative naming "h3" there,
//! its port and its "ma", and the keyword "clear". An alternative on another host would need a
//! name resolved, which colibri never does (decision 100), so it is passed over, as RFC 7838 §2.4
//! lets a client pass over any alternative.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");

/// What one response's Alt-Svc field says of h3 on the origin's host.
pub const Advert = union(enum) {
    /// "clear": the origin invalidates every alternative it advertised (RFC 7838 §3).
    clear,
    /// No alternative names h3 on the origin's host. It still replaces what an earlier response
    /// advertised (RFC 7838 §3.1).
    none,
    h3: H3,
};

/// An h3 endpoint on the origin's host.
pub const H3 = struct {
    port: u16,
    /// Seconds the alternative stays fresh after the response (RFC 7838 §3.1).
    max_age_s: u64,
};

/// RFC 7838 §3.1: an alternative "is considered fresh for 24 hours" unless "ma" says otherwise.
pub const max_age_default_s: u64 = 86_400;

/// RFC 9111 §1.2.2: a delta-seconds value past what the recipient represents is 2^31.
pub const delta_seconds_max: u64 = 2_147_483_648;

/// Reads every "alt-svc" field line of `section`'s regular lines, which start at index `first`,
/// in order, as one list (RFC 9110 §5.3). Null when the section has none, or when one is
/// malformed, and the client then keeps what it knew.
pub fn from_section(section: *const http.FieldSection, first: u32, host: []const u8) ?Advert {
    assert(first <= section.len());
    var advert: ?Advert = null;
    var iterator: http.field_section.Iterator = .{ .section = section, .index = first };
    // Bounded: the section holds `len()` lines.
    for (0..section.len()) |_| {
        const line = iterator.next() orelse break;
        // RFC 9110 §5.1: field names are case-insensitive.
        if (!std.ascii.eqlIgnoreCase(line.name, "alt-svc")) continue;
        const read = parse(line.value, host) orelse return null;
        advert = join(advert, read);
    }
    return advert;
}

/// The advert of two field lines read in order: "clear" anywhere invalidates every alternative
/// (RFC 7838 §3), and otherwise the first line naming h3 names the most preferred one.
fn join(earlier: ?Advert, later: Advert) Advert {
    const held = earlier orelse return later;
    if (held == .clear or later == .clear) return .clear;
    if (held == .h3) return held;
    return later;
}

/// Reads one Alt-Svc field value, or null when it is malformed. `host` is the origin's host.
pub fn parse(value: []const u8, host: []const u8) ?Advert {
    var reader = core.Reader.init(value);
    var found: ?H3 = null;
    var elements: usize = 0;
    // Bounded: each pass reads an element, or ends.
    for (0..value.len + 1) |_| {
        const next = next_element(&reader, host) orelse return null;
        const element = switch (next) {
            .end => break,
            .element => |held| held,
        };
        elements += 1;
        switch (element) {
            // RFC 7838 §3: "clear" invalidates every alternative, those beside it included.
            .clear => return .clear,
            .h3 => |alternative| if (found == null) {
                found = alternative;
            },
            .other => {},
        }
    }
    // RFC 7838 §3: the value is "clear" or at least one alt-value.
    if (elements == 0) return null;
    return if (found) |alternative| .{ .h3 = alternative } else .none;
}

const Element = union(enum) {
    clear,
    h3: H3,
    /// Another protocol, another host, or a value the client cannot use.
    other,
};

const Next = union(enum) {
    end,
    element: Element,
};

/// Reads the list's next element and the comma after it, or null when the list breaks the
/// grammar.
fn next_element(reader: *core.Reader, host: []const u8) ?Next {
    // Bounded: each pass reads an empty element's comma.
    for (0..reader.remaining_len() + 1) |_| {
        skip_whitespace(reader);
        if (reader.remaining_len() == 0) return .end;
        // RFC 9110 §5.6.1.2: a recipient ignores empty list elements.
        if (!take(reader, ',')) break;
    }
    const element = read_element(reader, host) orelse return null;
    skip_whitespace(reader);
    // RFC 9110 §5.6.1: a comma separates the elements of a list.
    if (reader.remaining_len() > 0 and !take(reader, ',')) return null;
    return .{ .element = element };
}

/// Reads `alternative *( OWS ";" OWS parameter )` (RFC 7838 §3), or "clear".
fn read_element(reader: *core.Reader, host: []const u8) ?Element {
    const protocol_id = read_token(reader) orelse return null;
    // RFC 7838 §3: "clear" is case-sensitive, and names no alternative.
    if (std.mem.eql(u8, protocol_id, "clear") and !next_is(reader, '=')) return .clear;
    // RFC 7838 §3: alternative = protocol-id "=" alt-authority.
    if (!take(reader, '=')) return null;
    const authority = read_quoted(reader) orelse return null;
    const parameters = read_parameters(reader) orelse return null;
    // RFC 7838 §3: protocol-id is compared as a string, and "h3" is RFC 9114 §3.1's token.
    if (!parameters.usable or !std.mem.eql(u8, protocol_id, "h3")) return .other;
    const port = same_host_port(authority.content, host) orelse return .other;
    return .{ .h3 = .{ .port = port, .max_age_s = parameters.max_age_s } };
}

const Parameters = struct {
    max_age_s: u64 = max_age_default_s,
    /// No parameter the client reads holds a quoted-pair.
    usable: bool = true,
};

/// Reads the parameters after an alternative (RFC 7838 §3): its "ma", and whether the client can
/// read it. Null when one breaks the grammar.
fn read_parameters(reader: *core.Reader) ?Parameters {
    var parameters: Parameters = .{};
    // Bounded: each pass reads a parameter, or ends.
    for (0..reader.remaining_len() + 1) |_| {
        skip_whitespace(reader);
        if (!take(reader, ';')) break;
        skip_whitespace(reader);
        const parameter = read_parameter(reader) orelse return null;
        // RFC 7838 §3: unknown parameters are ignored; §3.1 defines "ma".
        if (!std.mem.eql(u8, parameter.name, "ma")) continue;
        if (parameter.escaped) {
            parameters.usable = false;
            continue;
        }
        parameters.max_age_s = delta_seconds(parameter.value) orelse return null;
    }
    return parameters;
}

const Parameter = struct {
    name: []const u8,
    value: []const u8,
    /// The value was a quoted-string holding a quoted-pair, so `value` is not its octets.
    escaped: bool,
};

/// Reads `parameter = token "=" ( token / quoted-string )` (RFC 7838 §3).
fn read_parameter(reader: *core.Reader) ?Parameter {
    const name = read_token(reader) orelse return null;
    if (!take(reader, '=')) return null;
    if (next_is(reader, '"')) {
        const quoted = read_quoted(reader) orelse return null;
        return .{ .name = name, .value = quoted.content, .escaped = quoted.escaped };
    }
    const value = read_token(reader) orelse return null;
    return .{ .name = name, .value = value, .escaped = false };
}

/// The port of an alt-authority `[ uri-host ] ":" port` (RFC 7838 §3) whose host is empty or the
/// origin's, or null for another host or a port no connection can use. A quoted-pair's backslash
/// is neither a host's octet nor a digit (RFC 3986 §3.2.2, §3.2.3), so an escaped alt-authority
/// names no port here.
fn same_host_port(authority: []const u8, host: []const u8) ?u16 {
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return null;
    const named = authority[0..colon];
    // RFC 7838 §3: an alt-authority without a host names the origin's; RFC 3986 §3.2.2: a host
    // is case-insensitive.
    if (named.len > 0 and !std.ascii.eqlIgnoreCase(named, host)) return null;
    return port_of(authority[colon + 1 ..]);
}

/// A port of 1 to 65535 (RFC 3986 §3.2.3's `*DIGIT`), or null.
fn port_of(digits: []const u8) ?u16 {
    // More digits could not fit the sum; none sums to 0, which names no port.
    if (digits.len > port_digits_max) return null;
    var port: u32 = 0;
    for (digits) |digit| {
        if (!std.ascii.isDigit(digit)) return null;
        port = port * decimal_base + (digit - '0');
    }
    if (port == 0 or port > std.math.maxInt(u16)) return null;
    return @intCast(port);
}

const port_digits_max: usize = 5;
const decimal_base: u32 = 10;

/// RFC 9111 §1.2.2: delta-seconds = 1*DIGIT, a value past 2^31 being 2^31. Null when not digits.
fn delta_seconds(digits: []const u8) ?u64 {
    if (digits.len == 0) return null;
    var seconds: u64 = 0;
    for (digits) |digit| {
        if (!std.ascii.isDigit(digit)) return null;
        seconds = @min(seconds * decimal_base + (digit - '0'), delta_seconds_max);
    }
    assert(seconds <= delta_seconds_max);
    return seconds;
}

/// Whether `origin`, an origin's ASCII serialization (RFC 6454 §6.2), names the "https" origin
/// whose authority is `authority`. RFC 6454 §6.2 writes the scheme and the host lowercase and
/// leaves out the scheme's default port, 443 for "https" (RFC 9110 §4.2.2).
pub fn names_origin(origin: []const u8, authority: []const u8) bool {
    // RFC 6454 §6.2: the scheme, then "://", then the host.
    if (origin.len < https_prefix.len or !std.ascii.eqlIgnoreCase(origin[0..https_prefix.len], https_prefix)) return false;
    const rest = origin[https_prefix.len..];
    const host = host_of(authority);
    // RFC 3986 §3.2.2: a host is case-insensitive.
    if (rest.len < host.len or !std.ascii.eqlIgnoreCase(rest[0..host.len], host)) return false;
    const port = port_of_authority(authority[host.len..]) orelse return false;
    const tail = rest[host.len..];
    // RFC 6454 §6.2: the port follows a colon unless it is the scheme's default.
    if (tail.len == 0) return port == https_port;
    if (tail[0] != ':') return false;
    return port_of(tail[1..]) == port;
}

/// The port the rest of an authority after its host names, 443 when it names none (RFC 9110
/// §4.2.2), or null when it is not a colon and a port.
fn port_of_authority(after_host: []const u8) ?u16 {
    if (after_host.len == 0) return https_port;
    // RFC 3986 §3.2.3: a port follows the host after a colon.
    if (after_host[0] != ':') return null;
    return port_of(after_host[1..]);
}

const https_prefix = "https://";
/// RFC 9110 §4.2.2: the "https" scheme's default port.
const https_port: u16 = 443;

/// The origin's host: an authority's `host`, without the port (RFC 3986 §3.2).
pub fn host_of(authority: []const u8) []const u8 {
    // RFC 3986 §3.2.2: an IP-literal is bracketed, and may hold colons.
    if (authority.len > 0 and authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return authority;
        return authority[0 .. end + 1];
    }
    const colon = std.mem.indexOfScalar(u8, authority, ':') orelse return authority;
    return authority[0..colon];
}

const Quoted = struct {
    /// The octets between the quotes.
    content: []const u8,
    /// Whether they hold a quoted-pair, which stands for the octet after the backslash (RFC 9110
    /// §5.6.4), so `content` is not the value itself.
    escaped: bool,
};

/// Reads a quoted-string (RFC 9110 §5.6.4), or null when it is not one.
fn read_quoted(reader: *core.Reader) ?Quoted {
    if (!take(reader, '"')) return null;
    const rest = reader.peek_rest();
    var escaped = false;
    var index: usize = 0;
    // Bounded: each pass moves past one octet or a quoted-pair.
    while (index < rest.len) : (index += 1) {
        const octet = rest[index];
        if (qdtext(octet)) continue;
        if (octet == '"') {
            _ = reader.take(index + 1) catch unreachable;
            return .{ .content = rest[0..index], .escaped = escaped };
        }
        // RFC 9110 §5.6.4: quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text ).
        if (octet != '\\') return null;
        escaped = true;
        index += 1;
        if (index == rest.len or !quoted_pair_octet(rest[index])) return null;
    }
    // A quoted-string ends with DQUOTE.
    return null;
}

/// RFC 9110 §5.6.4: qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text, which is every
/// octet a quoted-pair may quote but DQUOTE and the backslash.
fn qdtext(octet: u8) bool {
    return quoted_pair_octet(octet) and octet != '"' and octet != '\\';
}

/// RFC 9110 §5.6.4: the octet a quoted-pair quotes is HTAB, SP, VCHAR or obs-text.
fn quoted_pair_octet(octet: u8) bool {
    // RFC 5234 Appendix B.1: VCHAR = %x21-7E, from "!" to "~".
    const vchar = octet >= '!' and octet <= '~';
    return octet == '\t' or octet == ' ' or vchar or octet >= obs_text_min;
}

/// RFC 9110 §5.5: obs-text = %x80-FF.
const obs_text_min: u8 = 0x80;

/// Reads `token = 1*tchar` (RFC 9110 §5.6.2), or null when none is next.
fn read_token(reader: *core.Reader) ?[]const u8 {
    const rest = reader.peek_rest();
    var len: usize = 0;
    while (len < rest.len and http.field.is_tchar(rest[len])) len += 1;
    if (len == 0) return null;
    return reader.take(len) catch unreachable;
}

/// RFC 9110 §5.6.3: OWS = *( SP / HTAB ).
fn skip_whitespace(reader: *core.Reader) void {
    // Bounded: each pass reads one octet.
    for (0..reader.remaining_len()) |_| {
        const octet = reader.peek_byte() catch return;
        if (octet != ' ' and octet != '\t') return;
        _ = reader.read_byte() catch unreachable;
    }
}

fn next_is(reader: *const core.Reader, octet: u8) bool {
    const next = reader.peek_byte() catch return false;
    return next == octet;
}

/// Reads `octet` when it is next, and answers whether it was.
fn take(reader: *core.Reader, octet: u8) bool {
    if (!next_is(reader, octet)) return false;
    _ = reader.read_byte() catch unreachable;
    return true;
}

const testing = std.testing;

fn expect_h3(value: []const u8, port: u16, max_age_s: u64) !void {
    return expect_h3_at(value, "localhost", port, max_age_s);
}

fn expect_h3_at(value: []const u8, host: []const u8, port: u16, max_age_s: u64) !void {
    const advert = parse(value, host) orelse return error.TestUnexpectedResult;
    if (advert != .h3) return error.TestUnexpectedResult;
    try testing.expectEqual(port, advert.h3.port);
    try testing.expectEqual(max_age_s, advert.h3.max_age_s);
}

test "RFC 7838 §3: h3 on the origin's host names its port, fresh for 24 hours unless ma says otherwise" {
    try expect_h3("h3=\":443\"", 443, max_age_default_s);
    try expect_h3("h3=\":50781\"; ma=3600", 50781, 3600);
    // RFC 3986 §3.2.2: the host is compared case-insensitively.
    try expect_h3("h3=\"LOCALHOST:8443\";ma=60", 8443, 60);
    // RFC 9110 §5.6.3: OWS is spaces and horizontal tabs.
    try expect_h3("h3=\":443\"\t;\tma=7", 443, 7);
    // RFC 7838 §3.1: a quoted ma is read as the same value.
    try expect_h3("h3=\":443\"; ma=\"60\"", 443, 60);
}

test "RFC 7838 §3: the first h3 alternative wins, and other protocols and unknown parameters are passed over" {
    try expect_h3("h2=\":443\", h3=\":8443\"; ma=60; persist=1", 8443, 60);
    try expect_h3("h3=\":9000\"; foo=\"a,b;c\"; ma=5, h3=\":9001\"", 9000, 5);
    try testing.expectEqual(Advert.none, parse("h3-29=\":443\", h2=\":443\"", "localhost").?);
}

test "RFC 7838 §2.4: an alternative on another host, or with a port no connection can use, is passed over" {
    try testing.expectEqual(Advert.none, parse("h3=\"other.example:443\"", "localhost").?);
    try testing.expectEqual(Advert.none, parse("h3=\":0\"", "localhost").?);
    try testing.expectEqual(Advert.none, parse("h3=\":65536\"", "localhost").?);
    try testing.expectEqual(Advert.none, parse("h3=\":\"", "localhost").?);
    try testing.expectEqual(Advert.none, parse("h3=\":44a\"", "localhost").?);
    try testing.expectEqual(Advert.none, parse("h3=\":4294967296\"", "localhost").?);
    // RFC 9110 §5.6.4: a quoted-pair's octet is not the one written, so it is not compared.
    try testing.expectEqual(Advert.none, parse("h3=\"\\:443\"", "localhost").?);
    try testing.expectEqual(Advert.none, parse("h3=\":443\"; ma=\"\\60\"", "localhost").?);
    // RFC 3986 §3.2.2: an IP-literal holds colons, and the last one starts the port.
    try expect_h3_at("h3=\"[::1]:443\"", "[::1]", 443, max_age_default_s);
}

test "RFC 7838 §3: clear invalidates every alternative, those beside it included" {
    try testing.expectEqual(Advert.clear, parse("clear", "localhost").?);
    try testing.expectEqual(Advert.clear, parse("h3=\":443\", clear", "localhost").?);
    // "clear" is case-sensitive, so "Clear" is a protocol-id without an alt-authority.
    try testing.expectEqual(null, parse("Clear", "localhost"));
}

test "RFC 9110 §5.6.1.2: empty list elements are ignored, and a value with no element is malformed" {
    try expect_h3(" , h3=\":443\" ,, ", 443, max_age_default_s);
    try testing.expectEqual(null, parse("", "localhost"));
    try testing.expectEqual(null, parse(" , ", "localhost"));
}

test "RFC 7838 §3: a value that breaks the grammar is malformed" {
    // The alt-authority is a quoted-string.
    try testing.expectEqual(null, parse("h3=:443", "localhost"));
    try testing.expectEqual(null, parse("h3=\":443", "localhost"));
    try testing.expectEqual(null, parse("h3", "localhost"));
    try testing.expectEqual(null, parse("h3\":443\"", "localhost"));
    try testing.expectEqual(null, parse("h3=\":443\" h2=\":443\"", "localhost"));
    try testing.expectEqual(null, parse("h3=\":443\"; ma", "localhost"));
    // RFC 9111 §1.2.2: delta-seconds is digits.
    try testing.expectEqual(null, parse("h3=\":443\"; ma=-1", "localhost"));
    try testing.expectEqual(null, parse("h3=\":443\"; ma=\"\"", "localhost"));
    try testing.expectEqual(null, parse("h3=\"a\x01b:443\"", "localhost"));
    try testing.expectEqual(null, parse("h3=\"\\\x01:443\"", "localhost"));
}

test "RFC 9111 §1.2.2: a max-age past 2^31 is 2^31" {
    try expect_h3("h3=\":443\"; ma=99999999999999999999999", 443, delta_seconds_max);
    try expect_h3("h3=\":443\"; ma=2147483648", 443, delta_seconds_max);
    try expect_h3("h3=\":443\"; ma=2147483647", 443, delta_seconds_max - 1);
}

test "RFC 3986 §3.2: the origin's host is its authority without the port" {
    try testing.expectEqualStrings("example.com", host_of("example.com:8443"));
    try testing.expectEqualStrings("example.com", host_of("example.com"));
    try testing.expectEqualStrings("[::1]", host_of("[::1]:443"));
}

/// A section the tests fill, outside any stack frame. Test-only.
threadlocal var test_section: http.FieldSection align(@alignOf(http.FieldSection)) = undefined;

test "RFC 9110 §5.3: the section's Alt-Svc lines are one list, and a malformed one leaves nothing learned" {
    test_section.init();
    try test_section.append(":status", "200");
    try test_section.append("alt-svc", "h2=\":443\"");
    try test_section.append("Alt-Svc", "h3=\":8443\"");
    try testing.expectEqual(@as(u16, 8443), from_section(&test_section, 1, "localhost").?.h3.port);
    // The first line naming h3 names the most preferred alternative.
    try test_section.append("alt-svc", "h3=\":9443\"");
    try testing.expectEqual(@as(u16, 8443), from_section(&test_section, 1, "localhost").?.h3.port);
    try test_section.append("alt-svc", "clear");
    try testing.expectEqual(Advert.clear, from_section(&test_section, 1, "localhost").?);
    // "clear" in an earlier line invalidates a later line's alternative too.
    test_section.init();
    try test_section.append("alt-svc", "clear");
    try test_section.append("alt-svc", "h3=\":8443\"");
    try testing.expectEqual(Advert.clear, from_section(&test_section, 0, "localhost").?);
    test_section.init();
    try test_section.append("content-type", "text/plain");
    try testing.expectEqual(null, from_section(&test_section, 0, "localhost"));
    try test_section.append("alt-svc", "h3=:443");
    try testing.expectEqual(null, from_section(&test_section, 0, "localhost"));
    // A malformed line leaves nothing learned, even after a line that names h3.
    test_section.init();
    try test_section.append("alt-svc", "h3=\":8443\"");
    try test_section.append("alt-svc", "h3=:443");
    try testing.expectEqual(null, from_section(&test_section, 0, "localhost"));
}

test "RFC 6454 §6.2: an ALTSVC Origin names the https origin of the authority, 443 left out" {
    try testing.expect(names_origin("https://example.org", "example.org"));
    try testing.expect(names_origin("https://Example.ORG", "example.org:443"));
    try testing.expect(names_origin("https://example.org:8443", "example.org:8443"));
    try testing.expect(names_origin("https://[::1]:8443", "[::1]:8443"));
    // Another scheme, host or port, and a port the authority does not name.
    try testing.expect(!names_origin("http://example.org", "example.org"));
    try testing.expect(!names_origin("https://example.net", "example.org"));
    try testing.expect(!names_origin("https://example.org.evil", "example.org"));
    try testing.expect(!names_origin("https://example.org:8443", "example.org"));
    try testing.expect(!names_origin("https://example.org", "example.org:8443"));
    try testing.expect(!names_origin("https://example.org:x", "example.org"));
    try testing.expect(!names_origin("https:/", "example.org"));
    // An authority whose host runs on into something other than a port names no origin.
    try testing.expect(!names_origin("https://[::1]", "[::1]x443"));
}
