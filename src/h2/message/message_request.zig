//! Step 3 of the check order message.zig states, for a request (invariant 7): the request
//! pseudo-header rules of RFC 9113 §8.3.1 and the CONNECT rules of §8.5, over the `Seen` record
//! message_lines.zig filled. `check` runs them in the order message.zig lists them. Each rule
//! returns the first error it finds.
//!
//! Every error is one of message.zig's `Error`: a malformed message, which RFC 9113 §8.1.1 makes a
//! stream error of type PROTOCOL_ERROR. The method, the CONNECT token and the scheme compare as
//! RFC 9110 compares them: the method exactly (§9.1) and the scheme in any case (§4.2.3).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const message = @import("message.zig");
const message_lines = @import("message_lines.zig");

const Error = message.Error;
const FieldSection = http.FieldSection;
const Seen = message_lines.Seen;

/// The two schemes RFC 9113 §8.3.1 states the `:path` rules for.
const scheme_http = "http";
const scheme_https = "https";

/// The `:path` of a request in asterisk form (RFC 9113 §8.3.1).
const path_asterisk = "*";

/// What an absolute-path starts with: `absolute-path = 1*( "/" segment )` (RFC 9110 §4.1).
const path_separator = "/";

/// The octet between the host and the port of a CONNECT target (RFC 9110 §9.3.6).
const port_separator = ':';

/// Step 3 for a request whose lines `walk` accepted. Returns true when the request is CONNECT.
pub fn check(seen: Seen) Error!bool {
    assert(seen.status == null);
    // RFC 9113 §8.3.1: every request includes exactly one valid value for :method.
    const method = seen.method orelse return error.MethodMissing;
    // RFC 9113 §8.3.1: a valid value; RFC 9110 §9.1: method = token.
    http.method.validate(method) catch return error.MethodInvalid;
    const is_connect = http.method.standard(method) == .connect;
    if (is_connect) try check_connect(seen) else try check_target(seen, method);
    assert(!is_connect or (seen.scheme == null and seen.path == null and seen.authority != null));
    assert(is_connect or (seen.scheme != null and seen.path != null));
    return is_connect;
}

/// Step 3 for a CONNECT request (RFC 9113 §8.5).
fn check_connect(seen: Seen) Error!void {
    assert(seen.method != null);
    // RFC 9113 §8.5: the :scheme and :path pseudo-header fields must be omitted.
    if (seen.scheme != null or seen.path != null) return error.ConnectWithSchemeOrPath;
    // RFC 9113 §8.5: the :authority pseudo-header field contains the host and port to connect to.
    const authority = seen.authority orelse return error.ConnectWithoutAuthority;
    try check_connect_authority(authority);
}

/// A CONNECT `:authority`: a host, a colon and a port (RFC 9113 §8.5, RFC 9112 §3.2.3). The host
/// ends at the last colon, so an IPv6 literal such as `[::1]:443` keeps its own colons.
fn check_connect_authority(authority: []const u8) Error!void {
    assert(authority.len <= core.constants.field_value_len_max);
    // RFC 9113 §8.5: the authority-form of RFC 9112 §3.2.3, authority-form = uri-host ":" port.
    const host, const port = std.mem.cutScalarLast(u8, authority, port_separator) orelse
        return error.ConnectAuthorityInvalid;
    // RFC 9110 §9.3.6: the target is the host and port number of the tunnel destination.
    if (host.len == 0) return error.ConnectAuthorityInvalid;
    // RFC 9110 §9.3.6: a server must reject a CONNECT request that targets an empty port number.
    if (port.len == 0) return error.ConnectAuthorityInvalid;
    for (port) |octet| {
        // RFC 9110 §9.3.6: a server must reject an invalid port number, and a port number holds
        // decimal digits only.
        if (!std.ascii.isDigit(octet)) return error.ConnectAuthorityInvalid;
    }
}

/// Step 3 for every request but CONNECT (RFC 9113 §8.3.1).
fn check_target(seen: Seen, method: []const u8) Error!void {
    assert(seen.method != null);
    // RFC 9113 §8.3.1: exactly one valid value for :scheme, unless the request is CONNECT.
    const scheme = seen.scheme orelse return error.SchemeMissing;
    // RFC 9113 §8.3.1: :scheme holds the scheme portion of the target URI, which is never empty.
    if (scheme.len == 0) return error.SchemeInvalid;
    // RFC 9113 §8.3.1: exactly one valid value for :path, unless the request is CONNECT.
    const path = seen.path orelse return error.PathMissing;
    try check_path(method, scheme, path);
}

/// The `:path` rules of RFC 9113 §8.3.1 and RFC 9110 §7.1, for a non-empty `scheme`.
fn check_path(method: []const u8, scheme: []const u8, path: []const u8) Error!void {
    assert(scheme.len > 0);
    if (std.mem.eql(u8, path, path_asterisk)) {
        // RFC 9110 §7.1: the asterisk form must not be used with a method other than OPTIONS.
        if (http.method.standard(method) != .options) return error.PathInvalid;
        return;
    }
    if (!is_http_scheme(scheme)) return;
    // RFC 9113 §8.3.1: :path must not be empty for "http" or "https" URIs.
    if (path.len == 0) return error.PathEmpty;
    // RFC 9113 §8.3.1: :path is the absolute-path production, and RFC 9110 §4.1 defines
    // absolute-path = 1*( "/" segment ).
    if (!std.mem.startsWith(u8, path, path_separator)) return error.PathInvalid;
}

/// True for the two schemes RFC 9113 §8.3.1 names, in any case: RFC 9110 §4.2.3 makes the scheme
/// case-insensitive.
fn is_http_scheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, scheme_http) or
        std.ascii.eqlIgnoreCase(scheme, scheme_https);
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

/// A request of the pseudo-headers given, each left out when null, in RFC 9113 §8.3.1's order.
fn request_of(method: ?[]const u8, scheme: ?[]const u8, authority: ?[]const u8, path: ?[]const u8) !*const FieldSection {
    test_section.init();
    if (method) |value| try test_section.append(":method", value);
    if (scheme) |value| try test_section.append(":scheme", value);
    if (authority) |value| try test_section.append(":authority", value);
    if (path) |value| try test_section.append(":path", value);
    return &test_section;
}

fn expect_request(err: Error, section: *const FieldSection) !void {
    try testing.expectError(err, message.validate_request(section));
}

fn expect_accepted(section: *const FieldSection) !void {
    _ = try message.validate_request(section);
}

test "http2/8.1.2.3/1: an empty :path is PathEmpty for http or https in any case, and / and * pass" {
    try expect_request(error.PathEmpty, try request_of("GET", "http", "example.org", ""));
    try expect_request(error.PathEmpty, try request_of("GET", "HTTPS", "example.org", ""));
    try expect_accepted(try request_of("GET", "https", "example.org", "/"));
    try expect_accepted(try request_of("OPTIONS", "http", "example.org", "*"));
    // RFC 9113 §8.3.1 states the rule for http and https URIs only, compared as whole tokens.
    const other_scheme = try message.validate_request(try request_of("GET", "ftp", "example.org", ""));
    try testing.expectEqualStrings("", other_scheme.path.?);
    try expect_accepted(try request_of("GET", "httpx", "example.org", ""));
    try expect_accepted(try request_of("GET", "http2", "example.org", ""));
}

test "an http or https :path that does not start with / is PathInvalid, and a scheme outside them is not held to it" {
    try expect_request(error.PathInvalid, try request_of("GET", "https", "example.org", "foo"));
    try expect_request(error.PathInvalid, try request_of("GET", "HTTP", null, "?q=1"));
    try expect_accepted(try request_of("GET", "https", "example.org", "/foo?q=1"));
    try expect_accepted(try request_of("GET", "http", null, "//"));
    try expect_accepted(try request_of("GET", "httpsx", null, "foo"));
}

test "a :path of * is PathInvalid in a request other than OPTIONS, in any scheme (RFC 9110 §7.1)" {
    try expect_request(error.PathInvalid, try request_of("GET", "https", "example.org", "*"));
    try expect_request(error.PathInvalid, try request_of("options", "http", null, "*"));
    try expect_request(error.PathInvalid, try request_of("GET", "ftp", null, "*"));
    try expect_accepted(try request_of("OPTIONS", "ftp", null, "*"));
    try expect_accepted(try request_of("OPTIONS", "https", null, "/"));
}

test "only a :path of exactly * is the asterisk form: *x takes the rules of any other path" {
    try expect_request(error.PathInvalid, try request_of("OPTIONS", "https", null, "*x"));
    try expect_accepted(try request_of("GET", "ftp", null, "*x"));
    try expect_accepted(try request_of("GET", "ftp", null, "**"));
}

test "http2/8.1.2.3/2, /3, /4: a request without :method, :scheme or :path is refused, in that order" {
    try expect_request(error.MethodMissing, try request_of(null, "http", "example.org", "/"));
    try expect_request(error.SchemeMissing, try request_of("GET", null, "example.org", "/"));
    try expect_request(error.PathMissing, try request_of("GET", "http", "example.org", null));
    try expect_request(error.MethodMissing, try request_of(null, null, null, null));
    try expect_request(error.SchemeMissing, try request_of("GET", null, null, null));
    // RFC 9113 §8.3.1: a request with no authority information to convey omits :authority.
    const no_authority = try message.validate_request(try request_of("GET", "http", null, "/"));
    try testing.expectEqual(null, no_authority.authority);
}

test "an empty :scheme is SchemeInvalid, checked after :scheme is present and before :path is" {
    try expect_request(error.SchemeInvalid, try request_of("GET", "", "example.org", "/"));
    try expect_request(error.SchemeInvalid, try request_of("GET", "", null, null));
    try expect_request(error.SchemeInvalid, try request_of("GET", "", null, ""));
    try expect_accepted(try request_of("GET", "a", null, "/"));
}

test "a :method that is not a token is MethodInvalid, checked before the target rules" {
    try expect_request(error.MethodInvalid, try request_of("", "http", null, "/"));
    try expect_request(error.MethodInvalid, try request_of("GE(T", "http", null, "/"));
    try expect_request(error.MethodInvalid, try request_of("GE(T", null, null, null));
    try expect_request(error.MethodInvalid, try request_of("CONNECT(", "http", null, "/"));
    const patch = try message.validate_request(try request_of("PATCH", "http", null, "/"));
    try testing.expectEqualStrings("PATCH", patch.method);
}

test "only the exact token CONNECT is CONNECT: connect, CONNECTX and CONNEC take the target rules" {
    // The method token is case-sensitive (RFC 9110 §9.1).
    try expect_request(error.SchemeMissing, try request_of("connect", null, "example.org:443", null));
    try expect_request(error.SchemeMissing, try request_of("CONNECTX", null, "a:1", null));
    try expect_request(error.SchemeMissing, try request_of("CONNEC", null, "a:1", null));
    const extended = try message.validate_request(try request_of("CONNECTX", "https", "a:1", "/"));
    try testing.expect(!extended.is_connect);
}

test "a CONNECT request with :authority alone passes, and one with :scheme or :path is ConnectWithSchemeOrPath" {
    const connect = try message.validate_request(try request_of("CONNECT", null, "example.org:443", null));
    try testing.expect(connect.is_connect);
    try testing.expectEqualStrings("CONNECT", connect.method);
    try testing.expectEqualStrings("example.org:443", connect.authority.?);
    try testing.expectEqual(null, connect.scheme);
    try testing.expectEqual(null, connect.path);
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", "https", "example.org:443", null));
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", null, "example.org:443", "/"));
}

test "a CONNECT request without :authority is ConnectWithoutAuthority, checked after :scheme and :path" {
    try expect_request(error.ConnectWithoutAuthority, try request_of("CONNECT", null, null, null));
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", null, null, "/"));
    try expect_request(error.ConnectWithSchemeOrPath, try request_of("CONNECT", "", "", ""));
}

test "a CONNECT :authority without a host, a colon or a decimal port is ConnectAuthorityInvalid" {
    const refused = [_][]const u8{ "", "example.org", "example.org:", ":443", ":", "a:4x3", "a:44/", "a::", "[::1]", "a:\t1" };
    for (refused) |authority| {
        try expect_request(error.ConnectAuthorityInvalid, try request_of("CONNECT", null, authority, null));
    }
    const accepted = [_][]const u8{ "a:0", "a:9", "[::1]:443", "a:b:0123456789", "a:65536" };
    for (accepted) |authority| try expect_accepted(try request_of("CONNECT", null, authority, null));
}

test "check reports whether a request is CONNECT, over a record walk filled" {
    const connect = try message_lines.walk(try request_of("CONNECT", null, "a:1", null), .request);
    try testing.expect(try check(connect));
    const get = try message_lines.walk(try request_of("GET", "https", null, "/"), .request);
    try testing.expect(!try check(get));
}
