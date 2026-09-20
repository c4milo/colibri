//! The checks RFC 9114 §4 applies to a decoded field section. Each entry point reads the section
//! as one kind of message and returns what it holds, or the `Error` that names why the message is
//! malformed. Nothing here reads a frame or tracks a stream.
//!
//! **Almost none of the rules are here.** RFC 9114 §4 restates most of RFC 9113 §8, so the rules
//! both state live in `http.message_lines` and `http.message_request` and return a reason; this
//! file names h3's errors for those reasons ([decision 51](../../../docs/decisions.md)). It is
//! the mirror of `src/h2/message/`, and the two share every rule they can rather than each
//! carrying a copy.
//!
//! Every `Error` is a malformed message, which RFC 9114 §4.1.2 makes a stream error of type
//! H3_MESSAGE_ERROR. `verdict` holds that code.
//!
//! **What is h3's alone, and why.** Decision 51 keeps five rules per protocol, and three of them
//! part here:
//!
//!   - `:authority` against `Host`. RFC 9114 §4.3.1 has four MUSTs where RFC 9113 §8.3.1 has one
//!     SHOULD, so `message_authority.zig` holds them and h2 has nothing like it.
//!   - A repeated pseudo-header name. RFC 9113 §8.3 forbids a repeat of any pseudo-header; RFC
//!     9114 §4.3.1 requires exactly one `:method`, `:scheme` and `:path` and says nothing of
//!     `:authority` or `:status`. colibri refuses every repeat, because §4.1.2 makes "invalid
//!     values for pseudo-header fields" malformed and two values where one is defined is that.
//!     Where a rule leaves a choice colibri takes the strict side.
//!   - A field value that starts or ends with SP or HTAB. RFC 9113 §8.2.1 states it and RFC 9114
//!     does not; it reaches h3 through RFC 9110 §5.5, whose `field-content` production admits
//!     whitespace only between two `field-vchar`. colibri refuses it, on the same strict side.
//!
//! The other two are h2's alone and are absent here: an informational response with END_STREAM,
//! which needs a flag h3 has no equivalent of, and `:protocol`, which RFC 8441 defines for h2.
//!
//! Not checked here:
//!   - whether content-length equals the sum of the DATA frame lengths (RFC 9114 §4.1.2). That
//!     check is the connection's, and `content_length` gives it the value;
//!   - the fourth MUST of §4.3.1, which `message_authority.zig` explains;
//!   - whether `:authority` holds the userinfo subcomponent §4.3.1 forbids. RFC 9113 §8.3.1
//!     states the same MUST and colibri's h2 does not check it either, so neither protocol does
//!     and the two stay consistent.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const message_authority = @import("message_authority.zig");

const FieldSection = http.FieldSection;
const Seen = http.message_lines.Seen;
const Status = http.status.Status;

pub const Error = error{
    /// A regular field name that is empty or holds an uppercase letter, a colon or another octet
    /// outside a token (RFC 9114 §4.2, §10.3).
    FieldNameInvalid,
    /// A field value that holds a character RFC 9110 §5.5 does not permit, or that starts or ends
    /// with SP or HTAB (RFC 9114 §10.3, RFC 9110 §5.5).
    FieldValueInvalid,
    /// A pseudo-header field after a regular field line (RFC 9114 §4.3).
    PseudoHeaderAfterRegular,
    /// A pseudo-header field name that appears twice (RFC 9114 §4.3.1, §4.1.2).
    PseudoHeaderRepeated,
    /// A pseudo-header field the message's kind does not define (RFC 9114 §4.3).
    PseudoHeaderUndefined,
    /// A pseudo-header field in a trailer section (RFC 9114 §4.3).
    PseudoHeaderInTrailers,
    /// A connection-specific field, or TE in a response or a trailer section (RFC 9114 §4.2).
    ConnectionSpecificField,
    /// TE in a request with a member other than "trailers" (RFC 9114 §4.2).
    TeNotTrailers,
    /// A request without `:method` (RFC 9114 §4.3.1).
    MethodMissing,
    /// A `:method` that is not a token (RFC 9114 §4.3.1, RFC 9110 §9.1).
    MethodInvalid,
    /// A request other than CONNECT without `:scheme` (RFC 9114 §4.3.1).
    SchemeMissing,
    /// A `:scheme` that is empty (RFC 9114 §4.3.1).
    SchemeInvalid,
    /// A request other than CONNECT without `:path` (RFC 9114 §4.3.1).
    PathMissing,
    /// An empty `:path` in a request for an http or https URI (RFC 9114 §4.3.1).
    PathEmpty,
    /// A `:path` of `*` in a request other than OPTIONS (RFC 9110 §7.1), or one for an http or
    /// https URI that neither starts with `/` nor is `*` (RFC 9114 §4.3.1, RFC 9110 §4.1).
    PathInvalid,
    /// A CONNECT request with `:scheme` or `:path` (RFC 9114 §4.4).
    ConnectWithSchemeOrPath,
    /// A CONNECT request without `:authority` (RFC 9114 §4.4).
    ConnectWithoutAuthority,
    /// A CONNECT `:authority` that is not a non-empty host, a colon and a non-empty decimal port
    /// (RFC 9114 §4.4, RFC 9110 §9.3.6).
    ConnectAuthorityInvalid,
    /// A request in a scheme with a mandatory authority component carrying neither `:authority`
    /// nor `Host` (RFC 9114 §4.3.1).
    AuthorityMissing,
    /// An `:authority` or a `Host` that is present and empty (RFC 9114 §4.3.1).
    AuthorityEmpty,
    /// An `:authority` and a `Host` that are both present and differ (RFC 9114 §4.3.1).
    AuthorityHostDiffer,
    /// A response without `:status` (RFC 9114 §4.3.2).
    StatusMissing,
    /// A `:status` that is not three digits from 100 to 599 (RFC 9114 §4.3.2, RFC 9110 §15).
    StatusInvalid,
    /// A content-length that disagrees with itself or does not fit a u64 (RFC 9114 §4.1.2,
    /// RFC 9110 §8.6).
    ContentLengthInvalid,
};

/// The stream error a malformed message carries. RFC 9114 §4.1.2: "Malformed requests or
/// responses that are detected MUST be treated as a stream error of type H3_MESSAGE_ERROR."
pub fn verdict(reason: Error) u64 {
    return switch (reason) {
        // Every rule this file names is a malformed message, and §4.1.2 gives them all one
        // stream error. The switch is over the whole set so a new reason must be answered here.
        else => constants.error_message_error,
    };
}

/// A request the section holds.
pub const Request = struct {
    /// The `:method` value, a token (RFC 9114 §4.3.1, RFC 9110 §9.1).
    method: []const u8,
    /// The `:scheme` value; null in a CONNECT request (RFC 9114 §4.4).
    scheme: ?[]const u8,
    /// The `:authority` value; null when the request carries none (RFC 9114 §4.3.1).
    authority: ?[]const u8,
    /// The `:path` value; null in a CONNECT request (RFC 9114 §4.4).
    path: ?[]const u8,
    /// The content-length, which the connection compares with the sum of the DATA frame lengths
    /// (RFC 9114 §4.1.2); null when the request carries none.
    content_length: ?u64,
    /// True when `method` is exactly CONNECT (RFC 9114 §4.4, RFC 9110 §9.1).
    is_connect: bool,
};

/// A response the section holds. `status.is_interim()` says whether a final response follows.
pub const Response = struct {
    /// The `:status` value (RFC 9114 §4.3.2).
    status: Status,
    /// The content-length, which the connection compares with the sum of the DATA frame lengths
    /// (RFC 9114 §4.1.2); null when the response carries none.
    content_length: ?u64,
};

/// Reads `section` as a request (RFC 9114 §4.3.1, §4.4).
pub fn validate_request(section: *const FieldSection) Error!Request {
    const seen = try walk(section, .request);
    const is_connect = try target(seen);
    try authority(section, seen);
    const length = try content_length_of(section);
    const method = seen.method.?;
    assert(is_connect == (http.method.standard(method) == .connect));
    assert(seen.status == null);
    return .{
        .method = method,
        .scheme = seen.scheme,
        .authority = seen.authority,
        .path = seen.path,
        .content_length = length,
        .is_connect = is_connect,
    };
}

/// Reads `section` as a response (RFC 9114 §4.3.2). There is no END_STREAM flag in h3, so the
/// rule RFC 9113 §8.1 states about an interim response carrying one has no counterpart here.
pub fn validate_response(section: *const FieldSection) Error!Response {
    const seen = try walk(section, .response);
    // RFC 9114 §4.3.2: :status MUST be included in all responses, interim responses included.
    const digits = seen.status orelse return error.StatusMissing;
    // RFC 9114 §4.1.2: an invalid value for a pseudo-header field is malformed; RFC 9110 §15:
    // three digits from 100 to 599.
    const status = Status.from_digits(digits) catch return error.StatusInvalid;
    const length = try content_length_of(section);
    assert(seen.method == null and seen.path == null);
    return .{ .status = status, .content_length = length };
}

/// Reads `section` as a trailer section: no pseudo-header field, and every line valid
/// (RFC 9114 §4.3, §4.2).
pub fn validate_trailers(section: *const FieldSection) Error!void {
    const seen = try walk(section, .trailers);
    assert(seen.method == null and seen.status == null);
    assert(seen.regular_seen == (section.len() > 0));
}

/// The line rules both RFCs state, with h3's errors named for the reasons `http` returns.
fn walk(section: *const FieldSection, kind: http.message_lines.Kind) Error!Seen {
    return http.message_lines.walk(section, kind) catch |reason| switch (reason) {
        // RFC 9114 §4.3: all pseudo-header fields appear before all regular fields.
        error.PseudoHeaderAfterRegular => error.PseudoHeaderAfterRegular,
        // RFC 9114 §4.3: pseudo-header fields must not appear in trailer sections.
        error.PseudoHeaderInTrailers => error.PseudoHeaderInTrailers,
        // RFC 9114 §4.3: an undefined pseudo-header, or one defined only for the other kind.
        error.PseudoHeaderUndefined => error.PseudoHeaderUndefined,
        // RFC 9114 §4.3.1 requires exactly one :method, :scheme and :path, and §4.1.2 makes an
        // invalid value for a pseudo-header field malformed. colibri refuses every repeat.
        error.PseudoHeaderRepeated => error.PseudoHeaderRepeated,
        // RFC 9114 §4.2 and §10.3: an invalid field name.
        error.FieldNameInvalid => error.FieldNameInvalid,
        // RFC 9114 §10.3: a character RFC 9110 §5.5 does not permit in a field value.
        error.FieldValueCharacter => error.FieldValueInvalid,
        // RFC 9110 §5.5: field-content admits SP and HTAB only between two field-vchar, so a
        // value starting or ending with one is not a field value. RFC 9114 states no rule of its
        // own, which is why this reason is separate and why the choice is made here.
        error.FieldValueWhitespace => error.FieldValueInvalid,
        // RFC 9114 §4.2: a connection-specific field, or TE outside a request.
        error.ConnectionSpecificField => error.ConnectionSpecificField,
        // RFC 9114 §4.2: TE with a member other than "trailers".
        error.TeNotTrailers => error.TeNotTrailers,
    };
}

/// The request target rules both RFCs state. Returns true when the request is CONNECT.
fn target(seen: Seen) Error!bool {
    return http.message_request.check(seen) catch |reason| switch (reason) {
        // RFC 9114 §4.3.1: every request includes exactly one valid value for :method.
        error.MethodMissing => error.MethodMissing,
        error.MethodInvalid => error.MethodInvalid,
        // RFC 9114 §4.4: a CONNECT request omits :scheme and :path and carries :authority.
        error.ConnectWithSchemeOrPath => error.ConnectWithSchemeOrPath,
        error.ConnectWithoutAuthority => error.ConnectWithoutAuthority,
        error.ConnectAuthorityInvalid => error.ConnectAuthorityInvalid,
        // RFC 9114 §4.3.1: every other request carries :scheme and :path.
        error.SchemeMissing => error.SchemeMissing,
        error.SchemeInvalid => error.SchemeInvalid,
        error.PathMissing => error.PathMissing,
        error.PathEmpty => error.PathEmpty,
        error.PathInvalid => error.PathInvalid,
    };
}

/// RFC 9114 §4.3.1's rules binding `:authority` to `Host`, which h2 has no counterpart for.
fn authority(section: *const FieldSection, seen: Seen) Error!void {
    return message_authority.check(section, seen) catch |reason| switch (reason) {
        error.AuthorityMissing => error.AuthorityMissing,
        error.AuthorityEmpty => error.AuthorityEmpty,
        error.AuthorityHostDiffer => error.AuthorityHostDiffer,
    };
}

/// The content-length `section` declares, or null when it declares none.
fn content_length_of(section: *const FieldSection) Error!?u64 {
    return http.content_length.from_section(section) catch |reason| switch (reason) {
        // RFC 9114 §4.1.2: a content-length that does not equal the sum of the DATA frame lengths
        // is malformed, and a value that is not 1*DIGIT (RFC 9110 §8.6) equals no sum.
        error.ContentLengthNotDigits => error.ContentLengthInvalid,
        // RFC 9114 §4.1.2: two different values cannot both equal the sum, and RFC 9110 §8.6 lets
        // a recipient reject a repeated value.
        error.ContentLengthDiffers => error.ContentLengthInvalid,
        // RFC 9110 §8.6: a recipient prevents parsing errors due to integer conversion overflows,
        // and colibri does so by refusing the value.
        error.ContentLengthTooLarge => error.ContentLengthInvalid,
    };
}

test {
    _ = @import("message_test.zig");
}
