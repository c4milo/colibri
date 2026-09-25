//! How long a message's body is (RFC 9112 §6.3), and which transfer codings it carries (§6.1, §7),
//! as decisions 88 and 91 rule. A server asks of a request, and a client of a response.
//!
//! §6.3's eight rules apply in order. Where they leave a choice, colibri takes the strict side:
//!   - Transfer-Encoding with Content-Length (rule 3) is refused, as §6.1 lets a server do and as
//!     §6.3 says such a message "ought to be handled as an error". A client refuses it too;
//!   - Transfer-Encoding in an HTTP/1.0 message is refused: §6.1 says to treat its framing as
//!     faulty;
//!   - chunked that is not the final coding is refused in a response as well as a request.
//!     §6.3 would read such a response until close, but decoding it would need chunked removed
//!     after a compression coding, which decision 91 does not decode.
//!
//! Decision 91 limits the codings: chunked, and at most one of gzip or deflate. A coding h11 does
//! not decode is `CodingUnsupported`, which RFC 9112 §6.1 has a server answer with 501.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const message_start = @import("message_start.zig");

const FieldSection = http.FieldSection;
const Version = message_start.Version;

pub const Error = error{
    /// Transfer-Encoding and Content-Length in one message (RFC 9112 §6.1, §6.3).
    TransferEncodingWithContentLength,
    /// Transfer-Encoding in an HTTP/1.0 message (RFC 9112 §6.1).
    TransferEncodingInHttp10,
    /// A Transfer-Encoding that names no coding, a member that is not a token, or a coding with
    /// parameters, which chunked, gzip and deflate define none of (RFC 9112 §7.1, §7.2).
    TransferEncodingInvalid,
    /// chunked applied more than once, or not as the final coding (RFC 9112 §6.1, §6.3).
    ChunkedNotLast,
    /// A coding h11 does not decode (RFC 9112 §6.1, decision 91).
    CodingUnsupported,
    /// More than one compression coding (decision 91).
    CodingsStacked,
    /// A Content-Length that is not one valid value (RFC 9112 §6.3, RFC 9110 §8.6).
    ContentLengthInvalid,
};

/// How a body is delimited (RFC 9112 §6.3).
pub const Length = union(enum) {
    /// No body.
    none,
    /// Content-Length octets.
    fixed: u64,
    /// The chunked coding, which ends itself (RFC 9112 §7.1).
    chunked,
    /// Every octet until the server closes the connection; a response only.
    close_delimited,
    /// The connection becomes a tunnel after the head; a 2xx response to CONNECT only.
    tunnel,
};

/// A compression coding under chunked, or none (decision 91).
pub const Coding = enum { none, gzip, deflate };

pub const Body = struct {
    length: Length,
    coding: Coding = .none,
};

/// What a client asked, which decides what a response's body can be (RFC 9112 §6.3).
pub const Asked = enum { head, connect, other };

/// The field names RFC 9112 §6.1 and RFC 9110 §8.6 define. Names compare case-insensitively.
const transfer_encoding_name = "Transfer-Encoding";

/// The codings of RFC 9112 §7.1 and §7.2, and the aliases §7.2 names.
const coding_chunked = "chunked";
const coding_gzip = "gzip";
const coding_gzip_alias = "x-gzip";
const coding_deflate = "deflate";

/// A request's body (RFC 9112 §6.3 rules 3 to 7).
pub fn request_body(version: Version, section: *const FieldSection) Error!Body {
    assert(version.major == 1);
    if (try transfer_codings(section)) |codings| {
        // RFC 9112 §6.1: an HTTP/1.0 message with Transfer-Encoding has faulty framing.
        if (version.minor == 0) return error.TransferEncodingInHttp10;
        try refuse_content_length(section);
        // RFC 9112 §6.3 rule 4: a request whose final coding is not chunked cannot be framed, and
        // the server MUST respond 400 and close.
        if (!codings.chunked_last) return error.ChunkedNotLast;
        return .{ .length = .chunked, .coding = codings.coding };
    }
    // RFC 9112 §6.3 rules 5 and 6.
    if (try content_length(section)) |octets| return .{ .length = .{ .fixed = octets } };
    // RFC 9112 §6.3 rule 7: a request with neither has no body.
    return .{ .length = .none };
}

/// A response's body (RFC 9112 §6.3 rules 1 to 6 and 8), to a request that asked `asked`.
pub fn response_body(asked: Asked, status: http.status.Status, version: Version, section: *const FieldSection) Error!Body {
    assert(version.major == 1);
    const code = status.code;
    const no_content = @intFromEnum(http.status.Code.no_content);
    const not_modified = @intFromEnum(http.status.Code.not_modified);
    const bodiless = asked == .head or status.is_interim() or code == no_content or code == not_modified;
    // RFC 9112 §6.3 rule 1: a response to HEAD, and a 1xx, 204 or 304, ends at the empty line.
    if (bodiless) return .{ .length = .none };
    // RFC 9112 §6.3 rule 2: a 2xx to CONNECT makes the connection a tunnel.
    if (asked == .connect and status.class() == .successful) return .{ .length = .tunnel };
    if (try transfer_codings(section)) |codings| {
        // RFC 9112 §6.1: an HTTP/1.0 message with Transfer-Encoding has faulty framing.
        if (version.minor == 0) return error.TransferEncodingInHttp10;
        try refuse_content_length(section);
        // RFC 9112 §6.3 rule 4: with no chunked, the body runs until the server closes.
        if (!codings.chunked) return .{ .length = .close_delimited, .coding = codings.coding };
        // RFC 9112 §6.3 rule 4: chunked that is not final would need decoding after a
        // compression coding, which colibri refuses.
        if (!codings.chunked_last) return error.ChunkedNotLast;
        return .{ .length = .chunked, .coding = codings.coding };
    }
    // RFC 9112 §6.3 rules 5 and 6.
    if (try content_length(section)) |octets| return .{ .length = .{ .fixed = octets } };
    // RFC 9112 §6.3 rule 8: a response with neither runs until the server closes.
    return .{ .length = .close_delimited };
}

/// RFC 9112 §6.3 rule 3: Transfer-Encoding with Content-Length "ought to be handled as an error",
/// and §6.1 lets a server reject it. colibri rejects it in either role.
fn refuse_content_length(section: *const FieldSection) Error!void {
    // RFC 9112 §6.1: a server MAY reject a request that contains both.
    if (section.find(http.content_length.name) != null) return error.TransferEncodingWithContentLength;
}

/// RFC 9112 §6.3 rule 5: an invalid Content-Length is an unrecoverable error, unless it is a
/// list of one valid value repeated, which `http.content_length` reads as that value.
fn content_length(section: *const FieldSection) Error!?u64 {
    // RFC 9112 §6.3 rule 5 and RFC 9110 §8.6.
    return http.content_length.from_section(section) catch return error.ContentLengthInvalid;
}

/// What a message's Transfer-Encoding lines say, combined in order (RFC 9110 §5.3).
const Codings = struct {
    /// chunked is one of the codings.
    chunked: bool = false,
    /// chunked is the final coding.
    chunked_last: bool = false,
    coding: Coding = .none,
};

/// Most members one field value holds: every member but the last takes a comma.
const members_max = core.constants.field_value_len_max + 1;

/// The codings every Transfer-Encoding line of `section` names, or null when there is none.
fn transfer_codings(section: *const FieldSection) Error!?Codings {
    var codings: Codings = .{};
    var found = false;
    var named = false;
    var iterator = section.iterator();
    // Bounded by the section's lines.
    for (0..section.len()) |_| {
        const line = iterator.next() orelse break;
        if (!http.field.names_equal(line.name, transfer_encoding_name)) continue;
        found = true;
        var members = std.mem.splitScalar(u8, line.value, ',');
        // Bounded by `members_max`, which a value of `field_value_len_max` octets cannot pass.
        for (0..members_max) |_| {
            const member = members.next() orelse break;
            const name = std.mem.trim(u8, member, " \t");
            // RFC 9110 §5.6.1.2: a recipient MUST accept and ignore empty list members.
            if (name.len == 0) continue;
            try add_coding(&codings, name);
            named = true;
        }
    }
    if (!found) return null;
    // RFC 9112 §6.1: Transfer-Encoding lists the codings applied, so one that lists none frames
    // nothing.
    if (!named) return error.TransferEncodingInvalid;
    return codings;
}

/// One member of a Transfer-Encoding list, after the codings before it.
fn add_coding(codings: *Codings, name: []const u8) Error!void {
    // RFC 9112 §6.1: a sender MUST NOT apply chunked more than once, and nothing follows chunked
    // when it frames the message (§6.3 rule 4).
    if (codings.chunked) return error.ChunkedNotLast;
    for (name) |octet| {
        // RFC 9112 §7.1 and §7.2: chunked, gzip and deflate define no parameters, and their
        // presence SHOULD be treated as an error; RFC 9110 §10.1.4: a coding name is a token.
        if (!http.field.is_tchar(octet)) return error.TransferEncodingInvalid;
    }
    if (std.ascii.eqlIgnoreCase(name, coding_chunked)) {
        codings.chunked = true;
        codings.chunked_last = true;
        return;
    }
    const coding: Coding = if (std.ascii.eqlIgnoreCase(name, coding_gzip) or std.ascii.eqlIgnoreCase(name, coding_gzip_alias))
        .gzip
    else if (std.ascii.eqlIgnoreCase(name, coding_deflate))
        .deflate
    else
        // RFC 9112 §6.1: a server SHOULD respond 501 to a coding it does not understand.
        return error.CodingUnsupported;
    // RFC 9112 §6.1 lets a message list several codings; decision 91 decodes one compression
    // coding at most, and refuses a second.
    if (codings.coding != .none) return error.CodingsStacked;
    codings.coding = coding;
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

const http11: Version = .{ .major = 1, .minor = 1 };
const http10: Version = .{ .major = 1, .minor = 0 };

fn section_of(fields: []const http.field.Field) !*const FieldSection {
    test_section.init();
    for (fields) |line| try test_section.append(line.name, line.value);
    return &test_section;
}

fn status_of(code: u16) http.status.Status {
    return http.status.Status.from_code(code) catch unreachable;
}

test "RFC 9112 §6.3: a request's body is chunked, fixed, or absent" {
    try testing.expectEqual(Body{ .length = .none }, try request_body(http11, try section_of(&.{})));
    try testing.expectEqual(Body{ .length = .{ .fixed = 5 } }, try request_body(http11, try section_of(&.{.{ .name = "content-length", .value = "5" }})));
    try testing.expectEqual(Body{ .length = .{ .fixed = 5 } }, try request_body(http10, try section_of(&.{.{ .name = "Content-Length", .value = "5, 5" }})));
    try testing.expectEqual(Body{ .length = .chunked }, try request_body(http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = "chunked" }})));
    try testing.expectEqual(Body{ .length = .chunked, .coding = .gzip }, try request_body(http11, try section_of(&.{.{ .name = "transfer-encoding", .value = "gzip, CHUNKED" }})));
}

test "RFC 9112 §6.3 rule 5: an invalid or disagreeing Content-Length is refused" {
    for ([_][]const u8{ "5, 6", "x", "-1", "", "99999999999999999999" }) |value| {
        try testing.expectError(error.ContentLengthInvalid, request_body(http11, try section_of(&.{.{ .name = "Content-Length", .value = value }})));
    }
    try testing.expectError(error.ContentLengthInvalid, request_body(http11, try section_of(&.{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Content-Length", .value = "6" },
    })));
}

test "RFC 9112 §6.1 and §6.3 rule 3: Transfer-Encoding with Content-Length, or in HTTP/1.0, is refused" {
    const both = try section_of(&.{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    });
    try testing.expectError(error.TransferEncodingWithContentLength, request_body(http11, both));
    try testing.expectError(error.TransferEncodingWithContentLength, response_body(.other, status_of(200), http11, both));
    const chunked = try section_of(&.{.{ .name = "Transfer-Encoding", .value = "chunked" }});
    try testing.expectError(error.TransferEncodingInHttp10, request_body(http10, chunked));
    try testing.expectError(error.TransferEncodingInHttp10, response_body(.other, status_of(200), http10, chunked));
}

test "RFC 9112 §6.3 rule 4: chunked is final and once, or the message is refused" {
    for ([_][]const u8{ "chunked, gzip", "chunked, chunked", "chunked,chunked", "gzip", "deflate" }) |value| {
        try testing.expectError(error.ChunkedNotLast, request_body(http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = value }})));
    }
    // Two lines combine into one list (RFC 9110 §5.3).
    try testing.expectError(error.ChunkedNotLast, request_body(http11, try section_of(&.{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    })));
    try testing.expectError(error.ChunkedNotLast, response_body(.other, status_of(200), http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = "chunked, gzip" }})));
}

test "the list takes empty members and whitespace, and refuses an empty list, parameters and non-tokens" {
    try testing.expectEqual(Body{ .length = .chunked, .coding = .deflate }, try request_body(http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = ", deflate ,\tchunked," }})));
    for ([_][]const u8{ "", " , ,", "chunked;q=1", "gzip;a=b, chunked", "\"chunked\"" }) |value| {
        try testing.expectError(error.TransferEncodingInvalid, request_body(http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = value }})));
    }
}

test "decision 91: gzip, x-gzip and deflate once, and nothing else" {
    try testing.expectEqual(Coding.gzip, (try request_body(http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = "x-gzip, chunked" }}))).coding);
    for ([_][]const u8{ "compress, chunked", "x-compress, chunked", "br, chunked", "identity, chunked" }) |value| {
        try testing.expectError(error.CodingUnsupported, request_body(http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = value }})));
    }
    try testing.expectError(error.CodingsStacked, request_body(http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = "deflate, gzip, chunked" }})));
}

test "RFC 9112 §6.3 rules 1 and 2: HEAD, 1xx, 204 and 304 have no body, and a 2xx to CONNECT tunnels" {
    const framed = try section_of(&.{.{ .name = "Content-Length", .value = "5" }});
    try testing.expectEqual(Length.none, (try response_body(.head, status_of(200), http11, framed)).length);
    for ([_]u16{ 100, 101, 199, 204, 304 }) |code| {
        try testing.expectEqual(Length.none, (try response_body(.other, status_of(code), http11, framed)).length);
    }
    try testing.expectEqual(Length.tunnel, (try response_body(.connect, status_of(200), http11, framed)).length);
    try testing.expectEqual(Length.tunnel, (try response_body(.connect, status_of(299), http11, framed)).length);
    try testing.expectEqual(Length{ .fixed = 5 }, (try response_body(.connect, status_of(407), http11, framed)).length);
    try testing.expectEqual(Length{ .fixed = 5 }, (try response_body(.other, status_of(205), http11, framed)).length);
}

test "RFC 9112 §6.3 rules 4 and 8: a response without chunked or a length runs until close" {
    try testing.expectEqual(Body{ .length = .close_delimited }, try response_body(.other, status_of(200), http11, try section_of(&.{})));
    try testing.expectEqual(Body{ .length = .close_delimited }, try response_body(.other, status_of(200), http10, try section_of(&.{})));
    try testing.expectEqual(Body{ .length = .close_delimited, .coding = .gzip }, try response_body(.other, status_of(200), http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = "gzip" }})));
    try testing.expectEqual(Body{ .length = .chunked }, try response_body(.other, status_of(500), http11, try section_of(&.{.{ .name = "Transfer-Encoding", .value = "chunked" }})));
}
