//! The rules of decision 101 (design §8 step 17e): the coding a request's Accept-Encoding accepts,
//! read as the request arrives, and what a final response the caller marks `codable` gets once the
//! caller writes its head. A connection applies them only when its configuration names codings and
//! an encoder pool.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");

const Coding = http.content_coding.Coding;
const Code = http.status.Code;

/// What a response needs to know of the request it answers.
pub const Asked = struct {
    /// The coding the server applies that the request's Accept-Encoding accepts with the highest
    /// weight, or null.
    accepted: ?Coding = null,
    method: Method = .other,
};

/// The methods whose responses decision 101 treats apart.
pub const Method = enum {
    /// RFC 9110 §9.3.2: a response to HEAD carries the fields a GET's would, and no content.
    head,
    /// RFC 9110 §9.3.6: a 2xx to CONNECT starts a tunnel, and has no content.
    connect,
    other,
};

/// What `request` asks of `codings`, the codings the server applies in its order of preference.
pub fn asked(codings: []const Coding, request: event.Request) Asked {
    return .{ .accepted = accepted(codings, request), .method = method_of(request.method) };
}

fn accepted(codings: []const Coding, request: event.Request) ?Coding {
    // Decision 101: an HTTP/1.0 request gets no coding.
    if (request.version.major == http_1_0.major and request.version.minor == http_1_0.minor) return null;
    // Decision 101: a request with no Accept-Encoding gets no coding, though RFC 9110 §12.5.3
    // permits one. With no line read, no coding has a weight, and `choose` finds none.
    var acceptance: http.content_coding.Acceptance = .{};
    var lines = request.fields.iterator();
    // Bounded by the section's lines.
    for (0..request.fields.len()) |_| {
        const line = lines.next() orelse break;
        if (!http.field.names_equal(line.name, accept_encoding)) continue;
        // RFC 9110 §12.5.3: a value its grammar refuses names no coding as acceptable, and the
        // content goes uncoded, which every recipient reads.
        http.content_coding.read_accept(&acceptance, line.value) catch return null;
    }
    return acceptance.choose(codings);
}

const http_1_0: event.Version = .{ .major = 1, .minor = 0 };
const accept_encoding = "accept-encoding";

fn method_of(method: []const u8) Method {
    // RFC 9110 §9.1: a method is case-sensitive.
    if (std.mem.eql(u8, method, "HEAD")) return .head;
    if (std.mem.eql(u8, method, "CONNECT")) return .connect;
    return .other;
}

/// What decision 101 does to one final response.
pub const Plan = struct {
    /// Add `Vary: accept-encoding`: Accept-Encoding chose the representation (RFC 9110 §12.5.5),
    /// coded or not, as in §8.8.3.3's example.
    vary: bool = false,
    /// The coding the representation is in, or null. Its fields lose Content-Length (RFC 9110
    /// §8.6), and a strong ETag becomes weak (§8.8.1, §8.8.3.3).
    coding: ?Coding = null,
    /// Add Content-Encoding naming `coding` (RFC 9110 §8.4).
    names_coding: bool = false,
    /// Content follows, coded through an encoder of the pool.
    encodes: bool = false,
};

/// What a final response to a request that asked `request` gets.
pub fn plan(request: Asked, response: event.Response) Plan {
    assert(response.status >= final_min);
    // Decision 101: only a response the caller marks is coded.
    if (!response.codable) return .{};
    if (!selected(request, response.status)) return .{};
    const coding = request.accepted orelse return .{ .vary = true };
    // RFC 9110 §15.4.5: a 304 carries the ETag and the Vary a 200 would, and no content.
    if (response.status == not_modified) return .{ .vary = true, .coding = coding };
    // RFC 9110 §9.3.2: a response to HEAD carries the fields a GET's would, and no content.
    if (request.method == .head) return .{ .vary = true, .coding = coding, .names_coding = true };
    // A response that ends with its head has no content to code.
    if (response.end) return .{ .vary = true };
    return .{ .vary = true, .coding = coding, .names_coding = true, .encodes = true };
}

/// Whether Accept-Encoding chooses the representation a final response with `status` carries.
fn selected(request: Asked, status: u16) bool {
    // Decision 101: a 206 is never coded, because its ranges are of the uncoded representation.
    if (status == partial_content) return false;
    // RFC 9110 §15.3.5: a 204 has no content.
    if (status == no_content) return false;
    // RFC 9110 §9.3.6: a 2xx to CONNECT starts a tunnel, and has no content.
    if (request.method == .connect and status < redirection_min) return false;
    return true;
}

const final_min: u16 = @intFromEnum(Code.ok);
const no_content: u16 = @intFromEnum(Code.no_content);
const partial_content: u16 = @intFromEnum(Code.partial_content);
const not_modified: u16 = @intFromEnum(Code.not_modified);
const redirection_min: u16 = @intFromEnum(Code.multiple_choices);

const testing = std.testing;

/// The codings the tests' server applies, gzip first.
const test_codings = [_]Coding{ .gzip, .deflate };
const test_http_1_1: event.Version = .{ .major = 1, .minor = 1 };

/// A request's field section, outside any stack frame. Test-only.
threadlocal var test_section: http.FieldSection align(@alignOf(http.FieldSection)) = undefined;

/// What a request with `method`, `version` and the field lines `lines` asks.
fn test_asked(method: []const u8, version: event.Version, lines: []const http.Field) !Asked {
    test_section.init();
    for (lines) |line| try test_section.append(line.name, line.value);
    return asked(&test_codings, .{
        .id = 1,
        .method = method,
        .version = version,
        .target = "/",
        .scheme = "https",
        .authority = "example.test",
        .path = "/",
        .fields = event.Fields.of(&test_section),
        .end = true,
    });
}

test "decision 101: Accept-Encoding chooses the coding, and every field line of it counts" {
    const both = [_]http.Field{.{ .name = "Accept-Encoding", .value = "deflate;q=0.5, gzip" }};
    try testing.expectEqual(Coding.gzip, (try test_asked("GET", test_http_1_1, &both)).accepted.?);
    // RFC 9110 §5.3: two lines are one list, and the first weight a coding gets is the one it keeps.
    const split = [_]http.Field{
        .{ .name = "accept-encoding", .value = "gzip;q=0" },
        .{ .name = "accept-encoding", .value = "gzip, deflate" },
    };
    try testing.expectEqual(Coding.deflate, (try test_asked("GET", test_http_1_1, &split)).accepted.?);
    const h2: event.Version = .{ .major = 2, .minor = 0 };
    try testing.expectEqual(Coding.gzip, (try test_asked("GET", h2, &both)).accepted.?);
}

test "decision 101: no Accept-Encoding, an HTTP/1.0 request or a value the grammar refuses, and no coding" {
    try testing.expectEqual(null, (try test_asked("GET", test_http_1_1, &.{})).accepted);
    const gzip = [_]http.Field{.{ .name = "accept-encoding", .value = "gzip" }};
    try testing.expectEqual(null, (try test_asked("GET", http_1_0, &gzip)).accepted);
    const broken = [_]http.Field{
        .{ .name = "accept-encoding", .value = "gzip" },
        .{ .name = "accept-encoding", .value = "deflate;q=2" },
    };
    try testing.expectEqual(null, (try test_asked("GET", test_http_1_1, &broken)).accepted);
    try testing.expectEqual(Method.head, (try test_asked("HEAD", test_http_1_1, &gzip)).method);
    try testing.expectEqual(Method.connect, (try test_asked("CONNECT", test_http_1_1, &gzip)).method);
    // RFC 9110 §9.1: a method is case-sensitive.
    try testing.expectEqual(Method.other, (try test_asked("head", test_http_1_1, &gzip)).method);
}

const test_gzip: Asked = .{ .accepted = .gzip };
const test_ok: u16 = 200;

test "decision 101: a marked response with content is coded, and only a marked one" {
    const coded = plan(test_gzip, .{ .status = test_ok, .end = false, .codable = true });
    try testing.expectEqual(Plan{ .vary = true, .coding = .gzip, .names_coding = true, .encodes = true }, coded);
    try testing.expectEqual(Plan{}, plan(test_gzip, .{ .status = test_ok, .end = false }));
    // RFC 9110 §8.8.3.3: a response Accept-Encoding chose varies on it, coded or not.
    const uncoded = plan(.{}, .{ .status = test_ok, .end = false, .codable = true });
    try testing.expectEqual(Plan{ .vary = true }, uncoded);
    try testing.expectEqual(Plan{ .vary = true }, plan(test_gzip, .{ .status = test_ok, .end = true, .codable = true }));
}

test "decision 101: a 206, a 204 and a 2xx to CONNECT stay as they are, and a 304 and HEAD get fields alone" {
    try testing.expectEqual(Plan{}, plan(test_gzip, .{ .status = partial_content, .end = false, .codable = true }));
    try testing.expectEqual(Plan{}, plan(test_gzip, .{ .status = no_content, .end = true, .codable = true }));
    const tunnel: Asked = .{ .accepted = .gzip, .method = .connect };
    try testing.expectEqual(Plan{}, plan(tunnel, .{ .status = test_ok, .end = false, .codable = true }));
    // RFC 9110 §9.3.6: a CONNECT refused is an ordinary response.
    const refused = plan(tunnel, .{ .status = redirection_min, .end = false, .codable = true });
    try testing.expect(refused.encodes);
    const unchanged = plan(test_gzip, .{ .status = not_modified, .end = true, .codable = true });
    try testing.expectEqual(Plan{ .vary = true, .coding = .gzip }, unchanged);
    const head: Asked = .{ .accepted = .gzip, .method = .head };
    const described = plan(head, .{ .status = test_ok, .end = false, .codable = true });
    try testing.expectEqual(Plan{ .vary = true, .coding = .gzip, .names_coding = true }, described);
}
