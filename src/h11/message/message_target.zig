//! The request-target's form (RFC 9112 §3.2) and the Host field a server holds a request to
//! (RFC 9112 §3.2, RFC 9110 §7.2), over a request line and field section `message` already read.
//! The grammar of each form and of Host is RFC 3986's, which `http.uri` checks.
//!
//! Which form a target takes follows from its first octet and the method:
//!   - CONNECT takes the authority-form alone (§3.2.3), and no other method takes it;
//!   - a target of "*" is the asterisk-form, which OPTIONS alone takes (§3.2.4);
//!   - a target starting with "/" is the origin-form (§3.2.1);
//!   - any other target is the absolute-form (§3.2.2), which a server MUST accept.
//!
//! An absolute-form http or https URI is held to RFC 9110 §4.2: a recipient MUST reject one with an
//! empty host (§4.2.1), and SHOULD treat userinfo as an error (§4.2.4). colibri takes the strict
//! side of the SHOULD.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const message_start = @import("message_start.zig");

const FieldSection = http.FieldSection;
const RequestLine = message_start.RequestLine;

pub const Error = error{
    /// A target that is no request-target of RFC 9112 §3.2, or a form its method does not take.
    TargetInvalid,
    /// An http or https absolute-form whose host is empty (RFC 9110 §4.2.1).
    TargetHostEmpty,
    /// An http or https absolute-form that carries userinfo (RFC 9110 §4.2.4).
    TargetUserinfo,
    /// An HTTP/1.1 request with no Host field (RFC 9112 §3.2).
    HostMissing,
    /// A request with more than one Host field line (RFC 9112 §3.2).
    HostRepeated,
    /// A Host value that is not `uri-host [ ":" port ]` (RFC 9112 §3.2, RFC 9110 §7.2).
    HostInvalid,
};

/// The four forms of RFC 9112 §3.2.
pub const Form = enum { origin, absolute, authority, asterisk };

/// The Host field's name (RFC 9110 §7.2). Field names compare case-insensitively (RFC 9110 §5.1).
const host_name = "Host";

/// The asterisk-form (RFC 9112 §3.2.4).
const asterisk = "*";

/// The two schemes RFC 9110 §4.2 defines.
const scheme_http = "http";
const scheme_https = "https";

/// The request-target's form, and the Host rules, for a request `message` read.
pub fn check(line: RequestLine, section: *const FieldSection) Error!Form {
    assert(line.target.len > 0);
    assert(line.version.major == 1);
    const form = try target_form(line);
    try check_host(line.version, section);
    return form;
}

fn target_form(line: RequestLine) Error!Form {
    const method = http.method.standard(line.method);
    if (method == .connect) {
        try check_authority_form(line.target);
        return .authority;
    }
    if (std.mem.eql(u8, line.target, asterisk)) {
        // RFC 9112 §3.2.4: the asterisk-form is only used for a server-wide OPTIONS request.
        if (method != .options) return error.TargetInvalid;
        return .asterisk;
    }
    if (std.mem.startsWith(u8, line.target, "/")) {
        // RFC 9112 §3.2.1: origin-form = absolute-path [ "?" query ].
        if (!http.uri.is_origin_form(line.target)) return error.TargetInvalid;
        return .origin;
    }
    try check_absolute_form(line.target);
    return .absolute;
}

/// `authority-form = uri-host ":" port` (RFC 9112 §3.2.3), for CONNECT.
fn check_authority_form(target: []const u8) Error!void {
    // RFC 9112 §3.2.3: a CONNECT request-target is only the host and port of the destination.
    const host, const port = http.uri.split_host_port(target) orelse return error.TargetInvalid;
    // RFC 9112 §3.2.3: uri-host ":" port, so the colon is required.
    const port_digits = port orelse return error.TargetInvalid;
    // RFC 9110 §9.3.6: a server MUST reject a CONNECT request targeting an empty or invalid port.
    if (port_digits.len == 0 or !http.uri.is_port(port_digits)) return error.TargetInvalid;
    // RFC 9110 §9.3.6: the target is the host and port of the tunnel destination, so a host.
    if (host.len == 0 or !http.uri.is_host(host)) return error.TargetInvalid;
}

/// `absolute-form = absolute-URI` (RFC 9112 §3.2.2), with RFC 9110 §4.2's rules for http and https.
fn check_absolute_form(target: []const u8) Error!void {
    // RFC 9112 §3.2.2: absolute-URI, as RFC 3986 §4.3 defines it.
    const uri = http.uri.absolute_uri(target) orelse return error.TargetInvalid;
    const is_http = std.ascii.eqlIgnoreCase(uri.scheme, scheme_http) or
        std.ascii.eqlIgnoreCase(uri.scheme, scheme_https);
    if (!is_http) return;
    // RFC 9110 §4.2.1 and §4.2.2: an http or https URI is "//" authority path-abempty.
    const authority = uri.authority orelse return error.TargetInvalid;
    // RFC 9110 §4.2.4: a recipient SHOULD treat userinfo in an http or https URI as an error.
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return error.TargetUserinfo;
    const host, _ = http.uri.split_host_port(authority) orelse unreachable;
    // RFC 9110 §4.2.1: a recipient MUST reject an http URI with an empty host as invalid.
    if (host.len == 0) return error.TargetHostEmpty;
}

/// RFC 9112 §3.2: a server MUST respond with 400 to an HTTP/1.1 request that lacks Host, and to
/// any request with more than one Host line or an invalid Host value.
fn check_host(version: message_start.Version, section: *const FieldSection) Error!void {
    var found: ?[]const u8 = null;
    var iterator = section.iterator();
    // Bounded by the section's lines.
    for (0..section.len()) |_| {
        const line = iterator.next() orelse break;
        if (!http.field.names_equal(line.name, host_name)) continue;
        // RFC 9112 §3.2: more than one Host header field line is a 400.
        if (found != null) return error.HostRepeated;
        found = line.value;
    }
    const value = found orelse {
        // RFC 9112 §3.2: an HTTP/1.1 request message that lacks Host is a 400. HTTP/1.0 has no
        // such rule.
        if (version.minor >= 1) return error.HostMissing;
        return;
    };
    // RFC 9110 §7.2: Host = uri-host [ ":" port ], so any other value is invalid (RFC 9112 §3.2).
    if (!http.uri.is_host_port(value)) return error.HostInvalid;
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

fn request(method: []const u8, target: []const u8, minor: u8, host: ?[]const u8) !Form {
    test_section.init();
    if (host) |value| try test_section.append("Host", value);
    const line: RequestLine = .{ .method = method, .target = target, .version = .{ .major = 1, .minor = minor } };
    return check(line, &test_section);
}

test "RFC 9112 §3.2: each target takes its form" {
    try testing.expectEqual(.origin, try request("GET", "/where?q=now", 1, "a"));
    try testing.expectEqual(.absolute, try request("GET", "http://www.example.org/pub", 1, "a"));
    try testing.expectEqual(.absolute, try request("GET", "urn:isbn:0451450523", 1, "a"));
    try testing.expectEqual(.authority, try request("CONNECT", "www.example.com:80", 1, "a"));
    try testing.expectEqual(.authority, try request("CONNECT", "[::1]:443", 1, "a"));
    try testing.expectEqual(.asterisk, try request("OPTIONS", "*", 1, "a"));
}

test "RFC 9112 §3.2.3 and RFC 9110 §9.3.6: CONNECT takes a host, a colon and a port, and nothing else" {
    for ([_][]const u8{ "www.example.com", "www.example.com:", ":80", "a:8x", "/", "*", "http://a/", "u@a:80", "[::1]" }) |target| {
        try testing.expectError(error.TargetInvalid, request("CONNECT", target, 1, "a"));
    }
}

test "RFC 9112 §3.2.4: the asterisk-form is OPTIONS's alone" {
    try testing.expectError(error.TargetInvalid, request("GET", "*", 1, "a"));
    try testing.expectError(error.TargetInvalid, request("options", "*", 1, "a"));
}

test "RFC 9112 §3.2.1: an origin-form holds pchar, / and a query, and nothing else" {
    try testing.expectError(error.TargetInvalid, request("GET", "/a#frag", 1, "a"));
    try testing.expectError(error.TargetInvalid, request("GET", "/a%zz", 1, "a"));
    try testing.expectError(error.TargetInvalid, request("GET", "/a\"b", 1, "a"));
}

test "RFC 9110 §4.2: an http or https absolute-form has an authority, a host and no userinfo" {
    try testing.expectError(error.TargetInvalid, request("GET", "http:/pub", 1, "a"));
    try testing.expectError(error.TargetHostEmpty, request("GET", "http:///pub", 1, "a"));
    try testing.expectError(error.TargetHostEmpty, request("GET", "HTTPS://:443/", 1, "a"));
    try testing.expectError(error.TargetUserinfo, request("GET", "https://user@example.org/", 1, "a"));
    try testing.expectError(error.TargetInvalid, request("GET", "www.example.org/pub", 1, "a"));
    // A scheme other than http and https is held to RFC 3986 alone.
    try testing.expectEqual(.absolute, try request("GET", "ftp://user@example.org/", 1, "a"));
}

test "RFC 9112 §3.2: Host is required of HTTP/1.1, once, with a valid value" {
    try testing.expectError(error.HostMissing, request("GET", "/", 1, null));
    try testing.expectEqual(.origin, try request("GET", "/", 0, null));
    try testing.expectEqual(.origin, try request("GET", "/", 1, ""));
    try testing.expectEqual(.origin, try request("GET", "/", 1, "[::1]:8080"));
    for ([_][]const u8{ "user@example.org", "example.org:80x", "a b", "example.org/" }) |host| {
        try testing.expectError(error.HostInvalid, request("GET", "/", 1, host));
        try testing.expectError(error.HostInvalid, request("GET", "/", 0, host));
    }
    test_section.init();
    try test_section.append("Host", "a");
    try test_section.append("host", "a");
    const line: RequestLine = .{ .method = "GET", .target = "/", .version = .{ .major = 1, .minor = 0 } };
    try testing.expectError(error.HostRepeated, check(line, &test_section));
}
