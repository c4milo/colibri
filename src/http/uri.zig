//! The URI grammar of RFC 3986 Appendix A, for the parts HTTP messages carry:
//!   - a host and port, which RFC 9110 §7.2's Host and RFC 9112 §3.2.3's authority-form are;
//!   - an authority, which an http or https absolute-URI carries (RFC 9110 §4.2);
//!   - an absolute-path and query, which RFC 9112 §3.2.1's origin-form is (RFC 9110 §4.1);
//!   - an absolute-URI, which RFC 9112 §3.2.2's absolute-form is.
//!
//! Each function answers whether the octets match the rule and nothing more. None decodes a
//! percent-encoding or normalizes a URI: colibri normalizes none, which is why RFC 9113 §8.3.1's
//! SHOULD is refused (decision 51). The protocol module names the error a mismatch carries.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

const Reader = core.reader.Reader;

/// The octets of `pct-encoded = "%" HEXDIG HEXDIG` after its "%" (RFC 3986 §2.1).
const pct_digits_len = 2;

/// Most HEXDIG in `h16 = 1*4HEXDIG` (RFC 3986 §3.2.2).
const h16_len_max = 4;

/// The dec-octets of an IPv4address, and the most digits one has (RFC 3986 §3.2.2).
const ipv4_parts = 4;
const dec_octet_len_max = 3;

/// The groups an IPv4address stands for in an IPv6address, as `ls32` (RFC 3986 §3.2.2).
const ipv4_groups = 2;

/// The base of a dec-octet (RFC 3986 §3.2.2).
const decimal_radix = 10;

/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"` (RFC 3986 §2.3).
fn is_unreserved(octet: u8) bool {
    return std.ascii.isAlphanumeric(octet) or octet == '-' or octet == '.' or octet == '_' or octet == '~';
}

/// `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="` (RFC 3986 §2.2).
fn is_sub_delim(octet: u8) bool {
    return std.mem.indexOfScalar(u8, "!$&'()*+,;=", octet) != null;
}

/// What a run of octets other than a percent-encoding may hold.
const Class = enum {
    /// `reg-name = *( unreserved / pct-encoded / sub-delims )` (RFC 3986 §3.2.2).
    reg_name,
    /// `userinfo = *( unreserved / pct-encoded / sub-delims / ":" )` (RFC 3986 §3.2.1).
    userinfo,
    /// `pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`, and "/" between segments
    /// (RFC 3986 §3.3).
    path,
    /// `query = *( pchar / "/" / "?" )` (RFC 3986 §3.4).
    query,
};

fn in_class(class: Class, octet: u8) bool {
    if (is_unreserved(octet) or is_sub_delim(octet)) return true;
    return switch (class) {
        .reg_name => false,
        .userinfo => octet == ':',
        .path => octet == ':' or octet == '@' or octet == '/',
        .query => octet == ':' or octet == '@' or octet == '/' or octet == '?',
    };
}

/// True when every octet of `octets` is of `class` or starts a `pct-encoded` of `"%" HEXDIG
/// HEXDIG` (RFC 3986 §2.1).
fn matches(class: Class, octets: []const u8) bool {
    var reader = Reader.init(octets);
    // Bounded: each pass consumes at least one octet.
    for (0..octets.len) |_| {
        const octet = reader.read_byte() catch return true;
        if (octet != '%') {
            if (!in_class(class, octet)) return false;
            continue;
        }
        // RFC 3986 §2.1: pct-encoded = "%" HEXDIG HEXDIG.
        const digits = reader.take(pct_digits_len) catch return false;
        if (!std.ascii.isHex(digits[0]) or !std.ascii.isHex(digits[1])) return false;
    }
    return reader.remaining_len() == 0;
}

/// `port = *DIGIT` (RFC 3986 §3.2.3). An empty port matches.
pub fn is_port(octets: []const u8) bool {
    for (octets) |octet| {
        if (!std.ascii.isDigit(octet)) return false;
    }
    return true;
}

/// `host = IP-literal / IPv4address / reg-name` (RFC 3986 §3.2.2). Every IPv4address is also a
/// reg-name, so a host that is not an IP-literal is checked as a reg-name. An empty host matches,
/// because reg-name may be empty.
pub fn is_host(octets: []const u8) bool {
    if (std.mem.startsWith(u8, octets, literal_open)) return is_ip_literal(octets);
    return matches(.reg_name, octets);
}

/// The octets around an IP-literal (RFC 3986 §3.2.2).
const literal_open = "[";
const literal_close = "]";

/// `IP-literal = "[" ( IPv6address / IPvFuture ) "]"` (RFC 3986 §3.2.2).
fn is_ip_literal(octets: []const u8) bool {
    assert(std.mem.startsWith(u8, octets, literal_open));
    if (octets.len < literal_open.len + literal_close.len) return false;
    if (!std.mem.endsWith(u8, octets, literal_close)) return false;
    var reader = Reader.init(octets);
    _ = reader.take(literal_open.len) catch unreachable;
    const inner = reader.take(octets.len - literal_open.len - literal_close.len) catch unreachable;
    if (std.mem.startsWith(u8, inner, "v") or std.mem.startsWith(u8, inner, "V")) return is_ip_future(inner);
    return is_ipv6(inner);
}

/// `IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )` (RFC 3986 §3.2.2). ABNF
/// strings are case-insensitive (RFC 5234 §2.3), so "V" matches too.
fn is_ip_future(octets: []const u8) bool {
    var reader = Reader.init(octets);
    _ = reader.read_byte() catch unreachable;
    const version, const rest = std.mem.cutScalar(u8, reader.take_rest(), '.') orelse return false;
    if (version.len == 0 or rest.len == 0) return false;
    for (version) |octet| {
        if (!std.ascii.isHex(octet)) return false;
    }
    for (rest) |octet| {
        if (!is_unreserved(octet) and !is_sub_delim(octet) and octet != ':') return false;
    }
    return true;
}

/// Most 16-bit groups an IPv6address writes out (RFC 3986 §3.2.2).
const ipv6_groups: u32 = 8;

/// `IPv6address` (RFC 3986 §3.2.2): eight h16 groups, the last two of which may be an
/// IPv4address, with "::" standing once for one or more groups of zeros.
fn is_ipv6(octets: []const u8) bool {
    const double_colon = "::";
    const left, const right = std.mem.cut(u8, octets, double_colon) orelse {
        const groups = count_groups(octets, true) orelse return false;
        return groups == ipv6_groups;
    };
    // RFC 3986 §3.2.2: "::" appears once at most. A second one leaves an empty piece, which
    // `count_groups` refuses as no h16.
    const left_groups = if (left.len == 0) 0 else count_groups(left, false) orelse return false;
    const right_groups = if (right.len == 0) 0 else count_groups(right, true) orelse return false;
    // RFC 3986 §3.2.2: "::" stands for at least one group, so at most seven are written.
    return left_groups + right_groups < ipv6_groups;
}

/// Groups in a colon-separated run of `h16 = 1*4HEXDIG`, counting a trailing IPv4address as two
/// when `ipv4_last` allows one; or null when the run does not match.
fn count_groups(octets: []const u8, ipv4_last: bool) ?u32 {
    var groups: u32 = 0;
    var pieces = std.mem.splitScalar(u8, octets, ':');
    // Bounded: a run of n octets holds at most n + 1 pieces.
    for (0..octets.len + 1) |_| {
        const piece = pieces.next() orelse return groups;
        const ipv4_allowed = ipv4_last and pieces.peek() == null;
        groups += piece_groups(piece, ipv4_allowed) orelse return null;
    }
    return null;
}

/// The groups one piece of an IPv6address stands for: one for an h16, two for an IPv4address
/// where `ipv4_allowed`, or null for anything else.
fn piece_groups(piece: []const u8, ipv4_allowed: bool) ?u32 {
    if (ipv4_allowed and std.mem.indexOfScalar(u8, piece, '.') != null) {
        // RFC 3986 §3.2.2: ls32 = ( h16 ":" h16 ) / IPv4address.
        return if (is_ipv4(piece)) ipv4_groups else null;
    }
    // RFC 3986 §3.2.2: h16 = 1*4HEXDIG.
    if (piece.len == 0 or piece.len > h16_len_max) return null;
    for (piece) |octet| {
        if (!std.ascii.isHex(octet)) return null;
    }
    return 1;
}

/// `IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet`, where a dec-octet is 0 to
/// 255 with no leading zero (RFC 3986 §3.2.2).
fn is_ipv4(octets: []const u8) bool {
    var parts = std.mem.splitScalar(u8, octets, '.');
    for (0..ipv4_parts) |_| {
        const part = parts.next() orelse return false;
        if (!is_dec_octet(part)) return false;
    }
    return parts.next() == null;
}

fn is_dec_octet(octets: []const u8) bool {
    if (octets.len == 0 or octets.len > dec_octet_len_max) return false;
    for (octets) |octet| {
        if (!std.ascii.isDigit(octet)) return false;
    }
    // RFC 3986 §3.2.2: a dec-octet has no leading zero.
    if (octets.len > 1 and std.mem.startsWith(u8, octets, "0")) return false;
    const value = std.fmt.parseInt(u16, octets, decimal_radix) catch unreachable;
    return value <= std.math.maxInt(u8);
}

/// `uri-host [ ":" port ]` (RFC 9110 §7.2, RFC 3986 §3.2.2 and §3.2.3), the form of Host.
pub fn is_host_port(octets: []const u8) bool {
    const host, const port = split_host_port(octets) orelse return false;
    return is_host(host) and is_port(port orelse "");
}

/// A host and its port, split where RFC 3986 §3.2 splits them: after an IP-literal's "]", or at
/// the first ":", which no reg-name or IPv4address holds. Null when an IP-literal is followed by
/// anything but a ":" and a port.
pub fn split_host_port(octets: []const u8) ?struct { []const u8, ?[]const u8 } {
    if (std.mem.startsWith(u8, octets, literal_open)) {
        const end = std.mem.indexOfScalar(u8, octets, ']') orelse return null;
        var reader = Reader.init(octets);
        const host = reader.take(end + literal_close.len) catch unreachable;
        const separator = reader.read_byte() catch return .{ host, null };
        if (separator != ':') return null;
        return .{ host, reader.take_rest() };
    }
    const host, const port = std.mem.cutScalar(u8, octets, ':') orelse return .{ octets, null };
    return .{ host, port };
}

/// `authority = [ userinfo "@" ] host [ ":" port ]` (RFC 3986 §3.2). userinfo holds no "@", so
/// the first "@" ends it.
pub fn is_authority(octets: []const u8) bool {
    const host_port = if (std.mem.cutScalar(u8, octets, '@')) |parts| blk: {
        if (!matches(.userinfo, parts[0])) return false;
        break :blk parts[1];
    } else octets;
    return is_host_port(host_port);
}

/// `origin-form = absolute-path [ "?" query ]`, where `absolute-path = 1*( "/" segment )`
/// (RFC 9112 §3.2.1, RFC 9110 §4.1, RFC 3986 §3.3 and §3.4).
pub fn is_origin_form(octets: []const u8) bool {
    const path, const query = std.mem.cutScalar(u8, octets, '?') orelse .{ octets, "" };
    if (!std.mem.startsWith(u8, path, "/")) return false;
    return matches(.path, path) and matches(.query, query);
}

/// The parts of an `absolute-URI = scheme ":" hier-part [ "?" query ]` (RFC 3986 §4.3).
pub const AbsoluteUri = struct {
    scheme: []const u8,
    /// The authority when hier-part starts with "//", and null otherwise.
    authority: ?[]const u8,
};

/// The scheme and authority of `octets` when it is an absolute-URI (RFC 3986 §4.3), or null.
pub fn absolute_uri(octets: []const u8) ?AbsoluteUri {
    const scheme, const rest = std.mem.cutScalar(u8, octets, ':') orelse return null;
    if (!is_scheme(scheme)) return null;
    const hier_part, const query = std.mem.cutScalar(u8, rest, '?') orelse .{ rest, "" };
    if (!matches(.query, query)) return null;
    const double_slash = "//";
    if (!std.mem.startsWith(u8, hier_part, double_slash)) {
        // RFC 3986 §3: path-absolute, path-rootless or path-empty, all made of pchar and "/".
        if (!matches(.path, hier_part)) return null;
        return .{ .scheme = scheme, .authority = null };
    }
    // RFC 3986 §3: "//" authority path-abempty; the path starts at the first "/" after "//".
    var reader = Reader.init(hier_part);
    _ = reader.take(double_slash.len) catch unreachable;
    const after = reader.take_rest();
    const authority_len = std.mem.indexOfScalar(u8, after, '/') orelse after.len;
    reader = Reader.init(after);
    const authority = reader.take(authority_len) catch unreachable;
    if (!is_authority(authority) or !matches(.path, reader.take_rest())) return null;
    return .{ .scheme = scheme, .authority = authority };
}

/// `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986 §3.1).
fn is_scheme(octets: []const u8) bool {
    var reader = Reader.init(octets);
    const first = reader.read_byte() catch return false;
    if (!std.ascii.isAlphabetic(first)) return false;
    for (reader.take_rest()) |octet| {
        const allowed = std.ascii.isAlphanumeric(octet) or octet == '+' or octet == '-' or octet == '.';
        if (!allowed) return false;
    }
    return true;
}

const testing = std.testing;

test "RFC 3986 §3.2.2: a reg-name host takes unreserved, sub-delims and percent-encodings" {
    for ([_][]const u8{ "example.org", "", "a-b_c~d", "x%2Fy", "!$&'()*+,;=", "127.0.0.1" }) |host| {
        try testing.expect(is_host(host));
    }
    for ([_][]const u8{ "a b", "a@b", "a/b", "a%2", "a%zz", "a:b", "é" }) |host| {
        try testing.expect(!is_host(host));
    }
}

test "RFC 3986 §3.2.2: IPv6 literals, eight groups or fewer with one ::, an IPv4 tail allowed" {
    const valid = [_][]const u8{
        "[::]",                  "[::1]",             "[1::]",             "[2001:db8::8a2e:370:7334]",
        "[1:2:3:4:5:6:7:8]",     "[1:2:3:4:5:6:7::]", "[::2:3:4:5:6:7:8]", "[::ffff:192.0.2.1]",
        "[1:2:3:4:5:6:1.2.3.4]", "[vF.a:b]",          "[v1.x]",
    };
    for (valid) |host| try testing.expect(is_host(host));
    const invalid = [_][]const u8{
        "[]",              "[:]",        "[:::]",               "[1::2::3]",    "[1:2:3:4:5:6:7:8:9]",
        "[1:2:3:4:5:6:7]", "[12345::]",  "[1:2:3:4:5:6:7:8::]", "[:1::]",       "[1::2:]",
        "[g::]",           "[::1.2.3]",  "[::256.0.0.1]",       "[::01.2.3.4]", "[1.2.3.4::]",
        "[v.a]",           "[v1.]",      "[::1",                "::1]",         "[1:2:3:4:5:6:7:1.2.3.4]",
        "[::1.2.3.4.5]",   "[::1:2::3]",
    };
    for (invalid) |host| {
        if (is_host(host)) {
            std.debug.print("accepted {s}\n", .{host});
            return error.TestUnexpectedResult;
        }
    }
}

test "RFC 9110 §7.2: Host is uri-host with an optional port, and userinfo has no place in it" {
    for ([_][]const u8{ "example.org", "example.org:8080", "example.org:", "[::1]:443", "[::1]", "" }) |value| {
        try testing.expect(is_host_port(value));
    }
    for ([_][]const u8{ "user@example.org", "example.org:80:80", "example.org:8x", "[::1]x", "[::1]:4x", "a b" }) |value| {
        try testing.expect(!is_host_port(value));
    }
}

test "RFC 3986 §3.2: an authority may carry userinfo before an @" {
    try testing.expect(is_authority("user:pass@example.org:80"));
    try testing.expect(is_authority("example.org"));
    try testing.expect(!is_authority("us er@example.org"));
    try testing.expect(!is_authority("a@b@c"));
}

test "RFC 9112 §3.2.1: origin-form starts with / and holds pchar, / and a query" {
    for ([_][]const u8{ "/", "/where?q=now", "//", "/a:b@c/%20", "/?", "/p?a/b?c" }) |target| {
        try testing.expect(is_origin_form(target));
    }
    for ([_][]const u8{ "", "where", "/a b", "/a#frag", "/%g0", "?q" }) |target| {
        try testing.expect(!is_origin_form(target));
    }
}

test "RFC 9112 §3.2.2: an absolute-URI yields its scheme and authority" {
    const http_uri = absolute_uri("http://www.example.org/pub/WWW/TheProject.html").?;
    try testing.expectEqualStrings("http", http_uri.scheme);
    try testing.expectEqualStrings("www.example.org", http_uri.authority.?);
    const bare = absolute_uri("http://www.example.org:8001").?;
    try testing.expectEqualStrings("www.example.org:8001", bare.authority.?);
    const query = absolute_uri("https://a/b?c=d").?;
    try testing.expectEqualStrings("a", query.authority.?);
    const no_authority = absolute_uri("urn:isbn:0451450523").?;
    try testing.expectEqual(null, absolute_uri("http://a/?q#"));
    try testing.expectEqual(null, absolute_uri("http://a/?q\x7f"));
    try testing.expectEqual(null, no_authority.authority);
    for ([_][]const u8{ "", "http", "1http://a/", "http://a b/", "http://a/#f", "ht tp://a/", "http://[::1/" }) |target| {
        try testing.expectEqual(null, absolute_uri(target));
    }
}
