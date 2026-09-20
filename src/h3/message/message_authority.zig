//! RFC 9114 §4.3.1's rules binding `:authority` to `Host`, which h3 has and h2 does not
//! ([decision 51](../../../docs/decisions.md)). RFC 9113 §8.3.1 states one SHOULD where this
//! states four MUSTs, and meeting that SHOULD needs URI normalization colibri's h2 does not
//! implement. So these rules are h3's and are not in `http`.
//!
//! Three of the four are checked. The fourth — "If the scheme does not have a mandatory authority
//! component and none is provided in the request target, the request MUST NOT contain the
//! :authority pseudo-header or Host header fields" — needs a registry saying which schemes have a
//! mandatory authority component. colibri knows that of "http" and "https" and of nothing else,
//! and RFC 9114 names no others, so a request in some third scheme is left alone rather than
//! guessed at.
//!
//! The comparison in the third is exact. RFC 9110 §4.2.3 makes a scheme case-insensitive and
//! RFC 3986 §3.2.2 makes a host case-insensitive, but normalizing an authority is more than
//! either, and colibri normalizes no URI anywhere (RFC 9113 §8.3.1's SHOULD is refused for the
//! same reason). Two values that differ only in case are therefore refused, which is the strict
//! side of a rule that leaves one.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");

const FieldSection = http.FieldSection;
const Seen = http.message_lines.Seen;

/// Why a request's authority is malformed. `message.zig` maps each to H3_MESSAGE_ERROR.
pub const Error = error{
    /// A request in a scheme with a mandatory authority component that carries neither
    /// `:authority` nor `Host` (RFC 9114 §4.3.1).
    AuthorityMissing,
    /// An `:authority` or a `Host` that is present and empty (RFC 9114 §4.3.1).
    AuthorityEmpty,
    /// An `:authority` and a `Host` that are both present and differ (RFC 9114 §4.3.1).
    AuthorityHostDiffer,
};

/// The field RFC 9110 §7.2 defines, which RFC 9114 §4.3.1 reads beside `:authority`. It is
/// lowercase because RFC 9114 §4.2 makes every field name lowercase and the shared line rules
/// have already refused any that is not.
pub const host_name = "host";

/// The two schemes RFC 9114 §4.3.1 names as having a mandatory authority component.
const scheme_http = "http";
const scheme_https = "https";

/// Checks a request whose lines and target rules already passed. `seen` carries `:authority` and
/// `section` is read for `Host`, because the shared rules see pseudo-headers alone.
pub fn check(section: *const FieldSection, seen: Seen) Error!void {
    assert(seen.status == null);
    // RFC 9114 §4.4: a CONNECT request omits :scheme, and its authority rules are §4.4's, which
    // `http.message_request` has already applied.
    const scheme = seen.scheme orelse return;
    // RFC 9114 §4.3.1: the rules below bind a scheme with a mandatory authority component,
    // "including http and https", which are the two colibri can name.
    if (!is_http_scheme(scheme)) return;
    const host = if (section.find(host_name)) |line| line.value else null;
    try check_present(seen.authority, host);
}

/// The three MUSTs, over the two values as the request carries them.
fn check_present(authority: ?[]const u8, host: ?[]const u8) Error!void {
    // RFC 9114 §4.3.1: the request MUST contain either an :authority pseudo-header field or a
    // Host header field.
    if (authority == null and host == null) return Error.AuthorityMissing;
    // RFC 9114 §4.3.1: if these fields are present, they MUST NOT be empty.
    if (authority) |value| if (value.len == 0) return Error.AuthorityEmpty;
    if (host) |value| if (value.len == 0) return Error.AuthorityEmpty;
    // RFC 9114 §4.3.1: if both fields are present, they MUST contain the same value.
    if (authority != null and host != null) {
        if (!std.mem.eql(u8, authority.?, host.?)) return Error.AuthorityHostDiffer;
    }
    assert(authority != null or host != null);
}

/// True for the two schemes RFC 9114 §4.3.1 names, in any case: RFC 9110 §4.2.3 makes the scheme
/// case-insensitive.
fn is_http_scheme(scheme: []const u8) bool {
    return std.ascii.eqlIgnoreCase(scheme, scheme_http) or
        std.ascii.eqlIgnoreCase(scheme, scheme_https);
}
