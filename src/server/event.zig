//! What `Connection.receive` reports, the same for h11 and h2 (decision 100): a request's head,
//! its content, its trailer section, its end by cancellation, or that its response is done. Every
//! slice points into storage the connection or the caller holds, and stays valid until the next
//! call to `receive`.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");

/// A request's id: the h2 stream it arrived on, or for h11 its place on the connection, counting
/// from 1. A response names the request it answers by it.
pub const Id = u64;

/// The protocol serving a connection.
pub const Protocol = enum { h11, h2, h3 };

/// The HTTP version a request came in, numbered as RFC 9110 §2.5 numbers it: 1.0 or 1.1 for h11,
/// and 2.0 for h2.
pub const Version = struct {
    major: u8,
    minor: u8,
};

/// A field section, less the pseudo-header fields h2 places first (RFC 9113 §8.3).
pub const Fields = struct {
    section: *const http.FieldSection,
    /// The index of the first regular field line.
    first: u32,

    /// The section's regular field lines, skipping the pseudo-header fields at its front.
    pub fn of(section: *const http.FieldSection) Fields {
        var first: u32 = 0;
        // RFC 9113 §8.3: every pseudo-header field comes before the regular field lines.
        while (first < section.len() and is_pseudo(section.get(first).name)) first += 1;
        assert(first <= section.len());
        return .{ .section = section, .first = first };
    }

    /// The first regular field line named `name`, compared case-insensitively (RFC 9110 §5.1).
    pub fn find(fields: Fields, name: []const u8) ?http.field.Field {
        assert(!is_pseudo(name));
        return fields.section.find(name);
    }

    /// The regular field lines in arrival order.
    pub fn iterator(fields: Fields) http.field_section.Iterator {
        return .{ .section = fields.section, .index = fields.first };
    }

    /// How many regular field lines the section holds.
    pub fn len(fields: Fields) u32 {
        assert(fields.first <= fields.section.len());
        return fields.section.len() - fields.first;
    }
};

/// RFC 9113 §8.3: a pseudo-header field's name starts with a colon.
fn is_pseudo(name: []const u8) bool {
    return name.len > 0 and name[0] == ':';
}

/// A request's head.
pub const Request = struct {
    id: Id,
    method: []const u8,
    version: Version,
    /// The request-target as it arrived for h11 (RFC 9112 §3.2), and for h2 its `:path`, or
    /// CONNECT's `:authority` (RFC 9113 §8.3.1, §8.5).
    target: []const u8,
    /// h2's `:scheme`, or for h11 "https" over TLS and "http" in cleartext, or an absolute-form
    /// target's scheme (RFC 9112 §3.3). Null for CONNECT (RFC 9113 §8.5, RFC 9112 §3.2.3).
    scheme: ?[]const u8,
    /// h2's `:authority`, or for h11 an absolute-form target's authority, else the Host field
    /// (RFC 9112 §3.2.2, §3.3). Null when the request carries none.
    authority: ?[]const u8,
    /// h2's `:path`, or for h11 the target's path and query, `*` for the asterisk-form (RFC 9112
    /// §3.2). An absolute-form target with an empty path gives "/" (RFC 9110 §4.2.3). Null for
    /// CONNECT (RFC 9113 §8.5, RFC 9112 §3.2.3).
    path: ?[]const u8,
    fields: Fields,
    /// Whether the head ended the request, so no content follows.
    end: bool,
};

/// Octets of a request's content, and whether they end it. The last `body` of a request may carry
/// none.
pub const Body = struct {
    id: Id,
    octets: []const u8,
    end: bool,
};

/// A request's trailer section, which ends it (RFC 9110 §6.5).
pub const Trailers = struct {
    id: Id,
    fields: Fields,
};

/// A request ended before its response did: the peer reset its h2 stream, or colibri refused it
/// (RFC 9113 §6.4, §5.4.2). The id may be one no `request` event named, when the refusal came
/// before the head was read whole.
pub const Cancelled = struct {
    id: Id,
};

/// The response to a request is whole, and the server reads none of the caller's octets for it
/// again, so the caller may reuse the memory its body came from (decision 103). h11 and h2 report
/// it after the call that wrote the response's last octet. A request cancelled first gets none.
pub const Done = struct {
    id: Id,
};

pub const Event = union(enum) {
    request: Request,
    body: Body,
    trailers: Trailers,
    cancelled: Cancelled,
    done: Done,
};

/// What one `receive` call took and reported.
pub const Received = struct {
    /// Octets of the caller's input taken.
    consumed: usize,
    event: ?Event,
};
