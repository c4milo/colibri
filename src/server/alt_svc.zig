//! The h3 endpoint a TCP connection advertises when its caller names one (decision 100, design §8
//! step 17b). RFC 9114 §3.1.1 lets an origin advertise h3 "via the Alt-Svc HTTP response header
//! field or the HTTP/2 ALTSVC frame". h11 sends the field on each final response (RFC 7838 §3), and
//! h2 sends one ALTSVC frame per connection, because RFC 7838 §3 says an h2 server "SHOULD instead
//! send an ALTSVC frame", as the owner ruled on 2026-09-28.
//!
//! Only a connection over TLS advertises: RFC 9114 §3.1.2 says h3 "cannot be used for direct
//! access to the authoritative server for a resource identified by an "http" URI", which is what a
//! cleartext connection serves.
const std = @import("std");
const assert = std.debug.assert;

/// An h3 endpoint on the origin's own host.
pub const Alternative = struct {
    /// The UDP port the h3 endpoint listens on.
    port: u16,
    /// Seconds a client may use the advertisement after the response (RFC 7838 §3.1's "ma").
    max_age_seconds: u32 = max_age_default_seconds,
};

/// RFC 7838 §3.1: an alternative "is considered fresh for 24 hours" unless "ma" says otherwise.
pub const max_age_default_seconds: u32 = 86_400;

/// The field's name, lowercase as h2 sends every name (RFC 9113 §8.2).
pub const field_name = "alt-svc";

/// Octets of the longest value `Advert` writes: the widest port and "ma".
pub const value_len_max = "h3=\":65535\"; ma=4294967295".len;

/// The value a connection advertises with, written once when the connection starts.
pub const Advert = struct {
    storage: [value_len_max]u8,
    /// Octets of the value, or 0 for a connection that advertises nothing.
    len: u8,
    /// h2: the ALTSVC frame is written. RFC 7838 §3: "A single ALTSVC frame can be sent for a
    /// connection; a new frame is not needed for every request."
    sent: bool,

    /// Writes the value naming `alternative` for a connection over TLS, or none.
    pub fn init(advert: *Advert, over_tls: bool, alternative: ?Alternative) void {
        advert.len = 0;
        advert.sent = false;
        // RFC 9114 §3.1.2: an "http" origin, served in cleartext, cannot be reached over h3.
        if (!over_tls) return;
        const named = alternative orelse return;
        // RFC 7838 §3: alternative = protocol-id "=" alt-authority, where the authority is a
        // quoted-string holding ":" port for the origin's host, and RFC 9114 §3.1.1 names h3 by its
        // ALPN token. RFC 7838 §3.1: "ma" carries the freshness in seconds.
        const written = std.fmt.bufPrint(&advert.storage, "h3=\":{d}\"; ma={d}", .{ named.port, named.max_age_seconds }) catch unreachable;
        assert(written.len > 0 and written.len <= value_len_max);
        advert.len = @intCast(written.len);
    }

    /// The Alt-Svc field value, or null for a connection that advertises nothing.
    pub fn value(advert: *const Advert) ?[]const u8 {
        if (advert.len == 0) return null;
        return advert.storage[0..advert.len];
    }
};

comptime {
    assert(value_len_max <= std.math.maxInt(u8));
}

const testing = std.testing;

test "RFC 7838 §3: a connection over TLS advertises h3 on its port with its max age" {
    var advert: Advert = undefined;
    advert.init(true, .{ .port = 8443, .max_age_seconds = 3600 });
    try testing.expectEqualStrings("h3=\":8443\"; ma=3600", advert.value().?);
    advert.init(true, .{ .port = 443 });
    try testing.expectEqualStrings("h3=\":443\"; ma=86400", advert.value().?);
    advert.init(true, .{ .port = std.math.maxInt(u16), .max_age_seconds = std.math.maxInt(u32) });
    try testing.expectEqual(value_len_max, advert.value().?.len);
}

test "RFC 9114 §3.1.2: a cleartext connection, or one with no alternative, advertises nothing" {
    var advert: Advert = undefined;
    advert.init(false, .{ .port = 443 });
    try testing.expectEqual(null, advert.value());
    advert.init(true, null);
    try testing.expectEqual(null, advert.value());
    try testing.expect(!advert.sent);
}
