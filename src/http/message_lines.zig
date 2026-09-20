//! The line-level message rules RFC 9113 §8 and RFC 9114 §4 both state, over a decoded field
//! section ([decision 51](../../docs/decisions.md)). `walk` reads the section twice in arrival
//! order and fills a `Seen` record, which `message_request.zig` reads for the rules of the kind.
//!
//! This module holds no verdict. Every rule returns a reason from `Error`, and the protocol
//! module names the error its RFC assigns: a stream error of PROTOCOL_ERROR for h2
//! (RFC 9113 §8.1.1), of H3_MESSAGE_ERROR for h3 (RFC 9114 §4.1.2). That is
//! [decision 15](../../docs/decisions.md)'s split, which `content_length.zig` already follows.
//!
//! The first pass applies the pseudo-header rules and the second the field rules. A pseudo-header
//! that breaks the first is therefore reported before a regular line that breaks the second, even
//! when the regular line arrived first. Within a pass, the first line that breaks a rule names the
//! reason.
//!
//! **Two reasons are one rule in h2 and two in h3, which is why `Error` splits them.** RFC 9113
//! §8.2.1 refuses a field value that holds a forbidden octet and one that starts or ends with SP
//! or HTAB, in two MUSTs, and h2 answers `FieldValueInvalid` to both. RFC 9114 states only the
//! first: HTAB does not appear in it, and §10.3's "a character not permitted in a field value" is
//! about which octets appear, not where they sit. So `FieldValueCharacter` and
//! `FieldValueWhitespace` are separate here and each protocol folds them as its RFC does.
//!
//! **One reason is shared detection and a per-protocol verdict.** A repeated pseudo-header name
//! must be found here, because finding it is how `Seen` stays a record of one value per name. But
//! RFC 9113 §8.3 forbids a repeat of any pseudo-header while RFC 9114 §4.3.1 requires exactly one
//! `:method`, `:scheme` and `:path` and says nothing about `:authority` or `:status`. So `walk`
//! reports it and the protocol decides, which is what decision 51 rules.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const field = @import("field.zig");
const field_section = @import("field_section.zig");
const connection_specific = @import("connection_specific.zig");

const Field = field.Field;
const FieldSection = field_section.FieldSection;

/// Why a section's lines are malformed. The protocol module maps each to its own error.
pub const Error = error{
    /// A pseudo-header field after a regular field line (RFC 9113 §8.3, RFC 9114 §4.3).
    PseudoHeaderAfterRegular,
    /// A pseudo-header field in a trailer section (RFC 9113 §8.1, RFC 9114 §4.3).
    PseudoHeaderInTrailers,
    /// A pseudo-header field the message's kind does not define: an unknown one, a request one in
    /// a response, or a response one in a request (RFC 9113 §8.3, RFC 9114 §4.3).
    PseudoHeaderUndefined,
    /// A pseudo-header field name that appears twice. RFC 9113 §8.3 forbids a repeat of any
    /// pseudo-header; RFC 9114 §4.3.1 requires exactly one `:method`, `:scheme` and `:path` and
    /// states nothing about `:authority` or `:status`, so the protocol decides (decision 51).
    PseudoHeaderRepeated,
    /// A regular field name that is empty or holds an uppercase letter, a colon or another octet
    /// outside a token (RFC 9113 §8.2.1, RFC 9114 §4.2 and §10.3).
    FieldNameInvalid,
    /// A field value that holds NUL, LF, CR or another control octet (RFC 9113 §8.2.1,
    /// RFC 9114 §10.3).
    FieldValueCharacter,
    /// A field value that starts or ends with SP or HTAB. RFC 9113 §8.2.1 states it; RFC 9114
    /// does not, and RFC 9110 §5.5 is where it reaches h3 (decision 51).
    FieldValueWhitespace,
    /// A connection-specific field, or TE in a response or a trailer section (RFC 9113 §8.2.2,
    /// RFC 9114 §4.2).
    ConnectionSpecificField,
    /// TE in a request with a member other than "trailers" (RFC 9113 §8.2.2, RFC 9114 §4.2).
    TeNotTrailers,
};

/// Which message a section holds. The kind decides which pseudo-headers are defined
/// (RFC 9113 §8.3, RFC 9114 §4.3) and whether TE may appear (RFC 9113 §8.2.2, RFC 9114 §4.2).
pub const Kind = enum { request, response, trailers };

/// The five pseudo-headers both RFCs define (RFC 9113 §8.3.1 and §8.3.2, RFC 9114 §4.3.1 and
/// §4.3.2).
const Pseudo = enum { method, scheme, authority, path, status };

/// One defined pseudo-header: its name as the RFCs spell it, and the kind it is defined for.
const Definition = struct { name: []const u8, pseudo: Pseudo, kind: Kind };

/// The five definitions, in the order the two RFCs give them. Both define the same five.
pub const definitions = [_]Definition{
    .{ .name = ":method", .pseudo = .method, .kind = .request },
    .{ .name = ":scheme", .pseudo = .scheme, .kind = .request },
    .{ .name = ":authority", .pseudo = .authority, .kind = .request },
    .{ .name = ":path", .pseudo = .path, .kind = .request },
    .{ .name = ":status", .pseudo = .status, .kind = .response },
};

/// The colon every pseudo-header name starts with (RFC 9113 §8.3, RFC 9114 §4.3).
const pseudo_header_prefix = ":";

/// What `walk` records. Every slice points into the section.
pub const Seen = struct {
    /// The `:method` value, or null when the section has none.
    method: ?[]const u8 = null,
    /// The `:scheme` value, or null.
    scheme: ?[]const u8 = null,
    /// The `:authority` value, or null.
    authority: ?[]const u8 = null,
    /// The `:path` value, or null.
    path: ?[]const u8 = null,
    /// The `:status` value, or null.
    status: ?[]const u8 = null,
    /// True once the first pass has read a regular line. No pseudo-header may follow one
    /// (RFC 9113 §8.3, RFC 9114 §4.3).
    regular_seen: bool = false,

    fn slot(seen: *Seen, pseudo: Pseudo) *?[]const u8 {
        return switch (pseudo) {
            .method => &seen.method,
            .scheme => &seen.scheme,
            .authority => &seen.authority,
            .path => &seen.path,
            .status => &seen.status,
        };
    }
};

/// Checks every line of `section`, as a message of `kind`, and records what the rules of the kind
/// read afterwards.
pub fn walk(section: *const FieldSection, kind: Kind) Error!Seen {
    assert(section.len() <= core.constants.field_count_max);
    var seen: Seen = .{};
    for (0..section.len()) |index| try check_pseudo_header(&seen, kind, section.get(@intCast(index)));
    for (0..section.len()) |index| try check_line(kind, section.get(@intCast(index)));
    const request_pseudo_seen = seen.method != null or seen.scheme != null or
        seen.authority != null or seen.path != null;
    assert(kind == .request or !request_pseudo_seen);
    assert(kind == .response or seen.status == null);
    return seen;
}

/// True for a name that starts with a colon, which both RFCs make a pseudo-header name
/// (RFC 9113 §8.3, RFC 9114 §4.3).
pub fn is_pseudo_header(name: []const u8) bool {
    return std.mem.startsWith(u8, name, pseudo_header_prefix);
}

/// The first pass for one line. A regular line only marks that one was seen. A pseudo-header must
/// come before every regular line, be defined for `kind`, and not repeat; its value is recorded.
fn check_pseudo_header(seen: *Seen, kind: Kind, line: Field) Error!void {
    if (!is_pseudo_header(line.name)) {
        seen.regular_seen = true;
        return;
    }
    // RFC 9113 §8.3 and RFC 9114 §4.3: all pseudo-header fields appear before all regular fields.
    if (seen.regular_seen) return error.PseudoHeaderAfterRegular;
    // RFC 9113 §8.1 and RFC 9114 §4.3: pseudo-header fields must not appear in trailer sections.
    if (kind == .trailers) return error.PseudoHeaderInTrailers;
    // RFC 9113 §8.3 and RFC 9114 §4.3: an undefined pseudo-header, or one defined only for the
    // other kind, is malformed.
    const slot = slot_of(seen, kind, line.name) orelse return error.PseudoHeaderUndefined;
    // RFC 9113 §8.3: the same pseudo-header field name must not appear more than once. RFC 9114
    // §4.3.1 states the narrower rule; the protocol decides what a repeat costs (decision 51).
    if (slot.* != null) return error.PseudoHeaderRepeated;
    slot.* = line.value;
    assert(slot.* != null and !seen.regular_seen);
}

/// The slot in `seen` for the pseudo-header `name` in a message of `kind`, or null when `kind`
/// does not define it. The comparison is exact, because both RFCs make every name lowercase
/// (RFC 9113 §8.2, RFC 9114 §4.2).
fn slot_of(seen: *Seen, kind: Kind, name: []const u8) ?*?[]const u8 {
    assert(kind != .trailers);
    assert(is_pseudo_header(name));
    for (definitions) |definition| {
        // RFC 9113 §8.3 and RFC 9114 §4.3: a pseudo-header field is valid only in the context it
        // is defined for.
        const defined = definition.kind == kind and std.mem.eql(u8, name, definition.name);
        if (defined) return seen.slot(definition.pseudo);
    }
    return null;
}

/// The second pass for one line. A pseudo-header's name was compared exactly in the first pass,
/// so only its value is read here.
fn check_line(kind: Kind, line: Field) Error!void {
    if (is_pseudo_header(line.name)) return check_value(line.value);
    try check_name(line.name);
    try check_value(line.value);
    try check_connection_specific(kind, line);
}

/// A regular field name (RFC 9113 §8.2.1, RFC 9114 §4.2 and §10.3).
pub fn check_name(name: []const u8) Error!void {
    assert(!is_pseudo_header(name));
    assert(name.len <= core.constants.field_name_len_max);
    for (name) |octet| {
        // RFC 9113 §8.2.1: a field name must not contain 0x41-0x5a, the uppercase letters.
        // RFC 9114 §4.2: a response containing uppercase characters in field names is malformed.
        if (std.ascii.isUpper(octet)) return error.FieldNameInvalid;
    }
    field.validate_name(name) catch |reason| switch (reason) {
        // RFC 9113 §8.2.1: no octet in 0x00-0x20 or 0x7f-0xff and no colon, and none of them is a
        // tchar. Any other octet outside a token fails RFC 9110 §5.1, which §8.2.1 asks a
        // recipient to check. RFC 9114 §10.3 makes the same check a MUST: "Requests or responses
        // containing invalid field names MUST be treated as malformed."
        error.FieldNameNotToken => return error.FieldNameInvalid,
        // Both reach RFC 9110 §5.1, and a token holds at least one tchar.
        error.FieldNameEmpty => return error.FieldNameInvalid,
        // `FieldSection.append` holds every name to `field_name_len_max`, asserted above.
        error.FieldNameTooLong => unreachable,
    };
}

/// A field value on any line (RFC 9113 §8.2.1, RFC 9114 §10.3). The two reasons are separate
/// because only the first is a rule RFC 9114 states; see this file's header.
pub fn check_value(value: []const u8) Error!void {
    assert(value.len <= core.constants.field_value_len_max);
    field.validate_value(value) catch |reason| switch (reason) {
        // RFC 9113 §8.2.1: a field value must not contain NUL, LF or CR at any position.
        // RFC 9114 §10.3: a value holding a character RFC 9110 §5.5 does not permit is malformed.
        error.FieldValueNulCarriageReturnOrLineFeed => return error.FieldValueCharacter,
        // RFC 9113 §8.2.1: a recipient checks a value against RFC 9110 §5.5, which admits no
        // other control octet. RFC 9114 §10.3 names the same production.
        error.FieldValueControl => return error.FieldValueCharacter,
        // RFC 9113 §8.2.1: a field value must not start with SP or HTAB. RFC 9114 states no such
        // rule, so this reason is the one a protocol may answer differently (decision 51).
        error.FieldValueLeadingWhitespace => return error.FieldValueWhitespace,
        // RFC 9113 §8.2.1: a field value must not end with SP or HTAB either, and RFC 9114 states
        // no such rule for that position either.
        error.FieldValueTrailingWhitespace => return error.FieldValueWhitespace,
        // `FieldSection.append` holds every value to `field_value_len_max`, asserted above.
        error.FieldValueTooLong => unreachable,
    };
}

/// The connection-specific rule, with its one exception for TE (RFC 9113 §8.2.2, RFC 9114 §4.2).
fn check_connection_specific(kind: Kind, line: Field) Error!void {
    const which = connection_specific.classify(line.name) orelse return;
    // RFC 9113 §8.2.2 and RFC 9114 §4.2: a message containing a connection-specific field is
    // malformed.
    if (which != .te) return error.ConnectionSpecificField;
    // RFC 9113 §8.2.2 and RFC 9114 §4.2: TE is the one exception, and only in a request.
    if (kind != .request) return error.ConnectionSpecificField;
    // RFC 9113 §8.2.2 and RFC 9114 §4.2: TE must not contain any value other than "trailers".
    if (!connection_specific.te_is_trailers(line.value)) return error.TeNotTrailers;
    assert(kind == .request and which == .te);
}
