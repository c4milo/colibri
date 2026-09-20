//! The request and response rules RFC 9113 §8.3 and §8.5 share with RFC 9114 §4.3 and §4.4, over
//! the `Seen` record `message_lines.walk` filled ([decision 51](../../docs/decisions.md)).
//!
//! This module holds no verdict. Every rule returns a reason from `Error`, and the protocol
//! module names the error its RFC assigns: a stream error of PROTOCOL_ERROR for h2
//! (RFC 9113 §8.1.1), of H3_MESSAGE_ERROR for h3 (RFC 9114 §4.1.2).
//!
//! The method, the CONNECT token and the scheme compare as RFC 9110 compares them: the method
//! exactly (§9.1) and the scheme in any case (§4.2.3). Both protocols inherit that from RFC 9110,
//! which is why those two lines cite it and not a protocol section.
//!
//! Four rules of RFC 9114 §4.3.1 are **not** here, because RFC 9113 §8.3.1 does not state them:
//! the four MUSTs binding `:authority` to `Host`. RFC 9113 has one SHOULD there, and meeting it
//! needs URI normalization colibri's h2 does not implement. Decision 51 keeps them per protocol.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const method_module = @import("method.zig");
const message_lines = @import("message_lines.zig");

const Seen = message_lines.Seen;

/// Why a request is malformed. The protocol module maps each to its own error.
pub const Error = error{
    /// A request without `:method` (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
    MethodMissing,
    /// A `:method` that is not a token (RFC 9113 §8.3.1, RFC 9114 §4.3.1, RFC 9110 §9.1).
    MethodInvalid,
    /// A request other than CONNECT without `:scheme` (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
    SchemeMissing,
    /// A `:scheme` that is empty, and so is not the scheme portion of a target URI
    /// (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
    SchemeInvalid,
    /// A request other than CONNECT without `:path` (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
    PathMissing,
    /// An empty `:path` in a request for an http or https URI (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
    PathEmpty,
    /// A `:path` of `*` in a request other than OPTIONS (RFC 9110 §7.1), or a `:path` for an http
    /// or https URI that neither starts with `/` nor is `*` (RFC 9113 §8.3.1, RFC 9114 §4.3.1,
    /// RFC 9110 §4.1).
    PathInvalid,
    /// A CONNECT request with `:scheme` or `:path` (RFC 9113 §8.5, RFC 9114 §4.4).
    ConnectWithSchemeOrPath,
    /// A CONNECT request without `:authority` (RFC 9113 §8.5, RFC 9114 §4.4).
    ConnectWithoutAuthority,
    /// A CONNECT `:authority` that is not a non-empty host, a colon and a non-empty decimal port
    /// (RFC 9113 §8.5, RFC 9114 §4.4, RFC 9110 §9.3.6).
    ConnectAuthorityInvalid,
};

/// The two schemes RFC 9113 §8.3.1 and RFC 9114 §4.3.1 state the `:path` rules for.
const scheme_http = "http";
const scheme_https = "https";

/// The `:path` of a request in asterisk form (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
const path_asterisk = "*";

/// What an absolute-path starts with: `absolute-path = 1*( "/" segment )` (RFC 9110 §4.1).
const path_separator = "/";

/// The octet between the host and the port of a CONNECT target (RFC 9110 §9.3.6).
const port_separator = ':';

/// The rules of the kind, for a request whose lines `walk` accepted. Returns true for CONNECT.
pub fn check(seen: Seen) Error!bool {
    assert(seen.status == null);
    // RFC 9113 §8.3.1 and RFC 9114 §4.3.1: every request includes exactly one valid value
    // for :method.
    const method = seen.method orelse return error.MethodMissing;
    // RFC 9113 §8.3.1 and RFC 9114 §4.3.1: a valid value; RFC 9110 §9.1: method = token.
    method_module.validate(method) catch return error.MethodInvalid;
    const is_connect = method_module.standard(method) == .connect;
    if (is_connect) try check_connect(seen) else try check_target(seen, method);
    assert(!is_connect or (seen.scheme == null and seen.path == null and seen.authority != null));
    assert(is_connect or (seen.scheme != null and seen.path != null));
    return is_connect;
}

/// The rules of a CONNECT request (RFC 9113 §8.5, RFC 9114 §4.4).
fn check_connect(seen: Seen) Error!void {
    assert(seen.method != null);
    // RFC 9113 §8.5 and RFC 9114 §4.4: the :scheme and :path fields must be omitted.
    if (seen.scheme != null or seen.path != null) return error.ConnectWithSchemeOrPath;
    // RFC 9113 §8.5 and RFC 9114 §4.4: :authority contains the host and port to connect to.
    const authority = seen.authority orelse return error.ConnectWithoutAuthority;
    try check_connect_authority(authority);
}

/// A CONNECT `:authority`: a host, a colon and a port (RFC 9113 §8.5, RFC 9114 §4.4,
/// RFC 9112 §3.2.3). The host
/// ends at the last colon, so an IPv6 literal such as `[::1]:443` keeps its own colons.
fn check_connect_authority(authority: []const u8) Error!void {
    assert(authority.len <= core.constants.field_value_len_max);
    // RFC 9113 §8.5 and RFC 9114 §4.4: the authority-form of RFC 9112 §3.2.3,
    // authority-form = uri-host ":" port.
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

/// The rules of every request but CONNECT (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
fn check_target(seen: Seen, method: []const u8) Error!void {
    assert(seen.method != null);
    // RFC 9113 §8.3.1 and RFC 9114 §4.3.1: exactly one valid value for :scheme, unless the
    // request is CONNECT.
    const scheme = seen.scheme orelse return error.SchemeMissing;
    // RFC 9113 §8.3.1 and RFC 9114 §4.3.1: :scheme holds the scheme portion of the target URI,
    // which is never empty.
    if (scheme.len == 0) return error.SchemeInvalid;
    // RFC 9113 §8.3.1 and RFC 9114 §4.3.1: exactly one valid value for :path, unless the
    // request is CONNECT.
    const path = seen.path orelse return error.PathMissing;
    try check_path(method, scheme, path);
}

/// The `:path` rules of RFC 9113 §8.3.1, RFC 9114 §4.3.1 and RFC 9110 §7.1, for a non-empty
/// `scheme`.
fn check_path(method: []const u8, scheme: []const u8, path: []const u8) Error!void {
    assert(scheme.len > 0);
    if (std.mem.eql(u8, path, path_asterisk)) {
        // RFC 9110 §7.1: the asterisk form must not be used with a method other than OPTIONS.
        if (method_module.standard(method) != .options) return error.PathInvalid;
        return;
    }
    if (!is_http_scheme(scheme)) return;
    // RFC 9113 §8.3.1 and RFC 9114 §4.3.1: :path must not be empty for "http" or "https" URIs.
    if (path.len == 0) return error.PathEmpty;
    // RFC 9113 §8.3.1 and RFC 9114 §4.3.1: :path is the absolute-path production, and
    // RFC 9110 §4.1 defines
    // absolute-path = 1*( "/" segment ).
    if (!std.mem.startsWith(u8, path, path_separator)) return error.PathInvalid;
}

/// True for the two schemes both RFCs name, in any case: RFC 9110 §4.2.3 makes the scheme
/// case-insensitive.
fn is_http_scheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, scheme_http) or
        std.ascii.eqlIgnoreCase(scheme, scheme_https);
}
