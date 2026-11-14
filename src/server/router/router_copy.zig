//! The router's copy of a request's header, for a function route whose request has a body
//! (decision 163 ruling 5, design §8 step 50e). A router copies only when `header_bytes` is above
//! 0. The root exports none of it.
//!
//! The engine's event points into storage that its next `receive` writes again. In h2 and h3, the
//! next HEADERS frame of any stream writes the connection's one field section again. A function
//! route gets its call when the body ends. So the router copies the header's live parts into the
//! request's entry at the request's event. The copy holds the section's live line records and
//! their octets. A part of the request that lies in those octets, or in the target, takes no more
//! room. The copy gives it the same offset in its own octets. Over h2 and h3 each part is a
//! pseudo-header field's value, so it takes none. One exception: a `:path` that starts with `?`
//! has the static "/" as its path, which takes one octet. Over h11 the copy holds the method and
//! the target after the lines, and each part that lies in neither, such as the scheme.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("../event.zig");

/// One line record of a section's `Slice`: its octets' offset and the lengths of its name and its
/// value. `http` keeps the type private, so the copy names it through the `Slice`.
const Line = std.meta.Elem(@FieldType(http.FieldSection.Slice, "lines"));

comptime {
    // The copy writes each line record as octets. A record with padding would copy octets that
    // no write set (non-negotiable 5), so its size is the sum of its fields' sizes.
    var fields_size: usize = 0;
    for (@typeInfo(Line).@"struct".fields) |field| fields_size += @sizeOf(field.type);
    assert(@sizeOf(Line) == fields_size);
}

/// Octets of one line record in a copy.
pub const line_record_len = @sizeOf(Line);

/// What `copy` refuses: the header's live parts do not fit the entry's `header_bytes`.
pub const Error = error{HeaderTooLarge};

/// The copy an entry holds: its octets, the `Slice` that the copy's `Headers` points to, and the
/// request, whose slices point into `octets`. With `header_bytes` 0 the router copies no header,
/// so the copy holds nothing (the owner's ruling of 2026-11-13).
pub fn Header(comptime header_bytes: usize) type {
    if (header_bytes == 0) return struct {};
    return struct {
        octets: [header_bytes]u8 = undefined,
        lines: http.FieldSection.Slice = .{ .octets = &.{}, .lines = &.{} },
        request: event.Request = undefined,
    };
}

comptime {
    // A router whose `header_bytes` is 0 calls each function route at the header, so its entries
    // spend no octet on a copy.
    assert(@sizeOf(Header(0)) == 0);
}

/// Copies `request`'s live parts into `octets`, and writes the copy into `into`, whose `Headers`
/// reads `lines`. The copy's `body` is `request.body` until the router sets it. A header whose
/// parts do not fit `octets` is refused, and the router answers it with 431. `into` is then not
/// to be read.
pub fn copy(request: *const event.Request, octets: []u8, lines: *http.FieldSection.Slice, into: *event.Request) Error!void {
    const section = request.headers.lines;
    assert(request.headers.first <= section.len());
    var used: usize = 0;
    const records = try append(octets, &used, std.mem.sliceAsBytes(section.lines));
    const names = try append(octets, &used, section.octets);
    lines.* = .{ .octets = names, .lines = std.mem.bytesAsSlice(Line, records) };
    // Over h2 and h3 each part is a pseudo-header field's value, so it lies in the section. Over
    // h11 the method and the target lie in the octets that the connection read.
    const target = moved(section.octets, names, request.target) orelse try append(octets, &used, request.target);
    const method = moved(section.octets, names, request.method) orelse try append(octets, &used, request.method);
    const places: Places = .{ .octets = octets, .section = section.octets, .names = names, .target = request.target, .target_copy = target };
    into.* = .{
        .id = request.id,
        .method = method,
        .version = request.version,
        .target = target,
        .scheme = try places.part(&used, request.scheme),
        .authority = try places.part(&used, request.authority),
        .path = try places.part(&used, request.path),
        .query = try places.part(&used, request.query),
        .headers = .{ .lines = lines, .first = request.headers.first },
        .body = request.body,
        .end = request.end,
    };
    assert(lines.len() == section.len());
    assert(used <= octets.len);
}

/// The two runs of octets that `copy` copied whole, the section's and the target's, each with its
/// copy, and the entry's octets.
const Places = struct {
    octets: []u8,
    section: []const u8,
    names: []const u8,
    target: []const u8,
    target_copy: []const u8,

    /// The copy of an optional part of the request. A part that lies in the section or in the
    /// target is read from that run's copy. Another part is copied after what the entry holds.
    inline fn part(places: *const Places, used: *usize, bytes: ?[]const u8) Error!?[]const u8 {
        const present = bytes orelse return null;
        if (moved(places.section, places.names, present)) |copied| return copied;
        if (moved(places.target, places.target_copy, present)) |copied| return copied;
        return try append(places.octets, used, present);
    }
};

/// Copies `bytes` into `octets` after its first `used` octets. Bytes that do not fit are refused
/// whole.
fn append(octets: []u8, used: *usize, bytes: []const u8) Error![]const u8 {
    assert(used.* <= octets.len);
    // RFC 6585 §5: header fields larger than the server takes get 431.
    if (bytes.len > octets.len - used.*) return error.HeaderTooLarge;
    const copied = octets[used.*..][0..bytes.len];
    @memcpy(copied, bytes);
    used.* += bytes.len;
    return copied;
}

/// The octets of `to` at the place where `bytes` lies in `from`, or null when `bytes` does not
/// lie in `from`. `to` is the copy of `from`. It reads the two addresses only to subtract them.
/// A part is a slice of the octets that the engine lent, or a static string. A part that is not
/// empty lies in `from` only when the engine cut it from `from`, because two objects share no
/// octet. An empty part gives no octets from either answer. So the copy follows from the
/// request's octets and its protocol, at every address: the owner's reading of non-negotiable 5
/// on 2026-11-14 (decision 163).
inline fn moved(from: []const u8, to: []const u8, bytes: []const u8) ?[]const u8 {
    assert(from.len == to.len);
    // A part that starts before `from` gives an offset past every length.
    const offset = @intFromPtr(bytes.ptr) -% @intFromPtr(from.ptr);
    if (offset > from.len or bytes.len > from.len - offset) return null;
    return to[offset..][0..bytes.len];
}

const testing = std.testing;

/// A section of two lines, and a request whose parts point into storage the test changes after
/// the copy, at the major version of h2. Test-only.
const test_lines_len = 2;
const test_major = 2;
threadlocal var test_section: http.FieldSection align(@alignOf(http.FieldSection)) = undefined;
threadlocal var test_slice: http.FieldSection.Slice align(@alignOf(http.FieldSection.Slice)) = undefined;
threadlocal var test_body: std.Io.Reader align(@alignOf(std.Io.Reader)) = event.failing_reader;

fn test_request(target: []u8) !event.Request {
    test_section.init();
    try test_section.append(":method", "POST");
    try test_section.append("x-name", "ada");
    test_slice = test_section.slice();
    const split = event.split_target(target);
    return .{
        .id = event.id_of(1),
        .method = "POST",
        .version = .{ .major = test_major, .minor = 0 },
        .target = target,
        .scheme = "https",
        .authority = null,
        .path = split.path,
        .query = split.query,
        .headers = .init(&test_slice),
        .body = &test_body,
        .end = false,
    };
}

/// Octets the copy of `test_request` takes: the line records and the lines' octets, then the
/// target, the method and the scheme. The path and the query lie in the target, so they take no
/// more.
fn test_bytes(target: []const u8) usize {
    const octets = ":method".len + "POST".len + "x-name".len + "ada".len;
    return test_lines_len * line_record_len + octets + target.len + "POST".len + "https".len;
}

/// The lines of a request's section over h2 and h3: its four pseudo-header fields, then one
/// regular line. Then the lines over h11: the Host line, and one more. Test-only.
const test_h2_fields = [_]http.Field{
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":authority", .value = "example.com" },
    .{ .name = ":path", .value = "/a/b?c=d" },
    .{ .name = "x-name", .value = "ada" },
};
const test_h11_fields = [_]http.Field{
    .{ .name = "host", .value = "example.com" },
    .{ .name = "x-name", .value = "ada" },
};

/// Writes `fields` into the section, as an engine does before a request's event.
fn test_write(fields: []const http.Field) !void {
    test_section.init();
    for (fields) |line| try test_section.append(line.name, line.value);
    test_slice = test_section.slice();
}

/// Writes each line of `fields` again with another value of the same length, as an engine's next
/// event does. Each value then holds other octets at the same place.
fn test_write_again(comptime fields: []const http.Field) !void {
    test_section.init();
    inline for (fields) |line| try test_section.append(line.name, "x" ** line.value.len);
    test_slice = test_section.slice();
}

/// Octets of the copy of a section that holds `fields`: a record for each line, then each line's
/// name and value.
fn test_section_bytes(fields: []const http.Field) usize {
    var octets = fields.len * line_record_len;
    for (fields) |line| octets += line.name.len + line.value.len;
    return octets;
}

test "decision 163 ruling 5: the copy reads as the request did after the engine wrote again" {
    var target = "/a/b?c=d".*;
    const request = try test_request(&target);
    var octets: [test_bytes("/a/b?c=d")]u8 = undefined;
    var lines: http.FieldSection.Slice = undefined;
    var copied: event.Request = undefined;
    try copy(&request, &octets, &lines, &copied);
    // The engine writes the section and the target again, as a later event does.
    test_section.init();
    try test_section.append(":method", "GET");
    try test_section.append("x-name", "bob");
    test_slice = test_section.slice();
    target = "/x/y?z=w".*;
    try testing.expectEqualStrings("ada", copied.headers.find("x-name").?.value);
    try testing.expectEqual(1, copied.headers.len());
    try testing.expectEqualStrings("POST", copied.method);
    try testing.expectEqualStrings("/a/b?c=d", copied.target);
    try testing.expectEqualStrings("/a/b", copied.path.?);
    try testing.expectEqualStrings("c=d", copied.query.?);
    try testing.expectEqualStrings("https", copied.scheme.?);
    try testing.expectEqual(null, copied.authority);
    try testing.expect(copied.body == &test_body);
}

test "RFC 6585 §5: a header one octet past the copy's octets is refused" {
    var target = "/a/b?c=d".*;
    const request = try test_request(&target);
    var octets: [test_bytes("/a/b?c=d") - 1]u8 = undefined;
    var lines: http.FieldSection.Slice = undefined;
    var copied: event.Request = undefined;
    try testing.expectError(error.HeaderTooLarge, copy(&request, &octets, &lines, &copied));
}

test "decision 163 ruling 5: a part that lies in the section or in the target takes no more room" {
    var unused = "/unused".*;
    var request = try test_request(&unused);
    // Over h2 and h3 each part of a request is a pseudo-header field's value in the section.
    try test_write(&test_h2_fields);
    const whole = test_section.find(":path").?.value;
    const split = event.split_target(whole);
    request.method = test_section.find(":method").?.value;
    request.scheme = test_section.find(":scheme").?.value;
    request.authority = test_section.find(":authority").?.value;
    request.target = whole;
    request.path = split.path;
    request.query = split.query;
    request.headers = .init(&test_slice);
    // The copy holds a record for each line and the section's octets, and no octet more.
    var octets: [test_section_bytes(&test_h2_fields)]u8 = undefined;
    var lines: http.FieldSection.Slice = undefined;
    var copied: event.Request = undefined;
    try copy(&request, &octets, &lines, &copied);
    try test_write_again(&test_h2_fields);
    try testing.expectEqualStrings("POST", copied.method);
    try testing.expectEqualStrings("https", copied.scheme.?);
    try testing.expectEqualStrings("example.com", copied.authority.?);
    try testing.expectEqualStrings("/a/b?c=d", copied.target);
    try testing.expectEqualStrings("/a/b", copied.path.?);
    try testing.expectEqualStrings("c=d", copied.query.?);
    try testing.expectEqualStrings("ada", copied.headers.find("x-name").?.value);
    try testing.expectEqual(1, copied.headers.len());
    // Each part reads the copy's octets, not the section's.
    try testing.expect(moved(&octets, &octets, copied.method) != null);
    try testing.expect(moved(&octets, &octets, copied.path.?) != null);
}

test "decision 163 ruling 5: the copy keeps each part of an h11 request after the next read" {
    // Over h11 the method and the target lie in the octets that the connection read. The
    // authority is the Host line's value. The scheme of this request lies in octets of its own.
    var read = "POST /a/b?c=d HTTP/1.1".*;
    var scheme = "https".*;
    var request = try test_request(read["POST ".len..][0.."/a/b?c=d".len]);
    try test_write(&test_h11_fields);
    request.method = read[0.."POST".len];
    request.scheme = &scheme;
    request.authority = test_section.find("host").?.value;
    request.headers = .init(&test_slice);
    // The copy holds the section, then the target, the method and the scheme, and no octet more.
    var octets: [test_section_bytes(&test_h11_fields) + "/a/b?c=d".len + "POST".len + "https".len]u8 = undefined;
    var lines: http.FieldSection.Slice = undefined;
    var copied: event.Request = undefined;
    try copy(&request, &octets, &lines, &copied);
    // The connection reads again, and the engine writes its section again.
    @memset(&read, 'x');
    @memset(&scheme, 'x');
    try test_write_again(&test_h11_fields);
    try testing.expectEqualStrings("POST", copied.method);
    try testing.expectEqualStrings("/a/b?c=d", copied.target);
    try testing.expectEqualStrings("/a/b", copied.path.?);
    try testing.expectEqualStrings("c=d", copied.query.?);
    try testing.expectEqualStrings("https", copied.scheme.?);
    try testing.expectEqualStrings("example.com", copied.authority.?);
    try testing.expectEqualStrings("example.com", copied.headers.find("host").?.value);
    try testing.expectEqual(test_h11_fields.len, copied.headers.len());
}

test "decision 163 ruling 5: moved finds octets inside a run, and no others" {
    const run = "0123456789";
    const to = "abcdefghij";
    try testing.expectEqualStrings("", moved(run, to, run[0..0]).?);
    try testing.expectEqualStrings("defg", moved(run, to, run[3..7]).?);
    try testing.expectEqualStrings("", moved(run, to, run[10..10]).?);
    const other = "0123456789abc";
    try testing.expectEqual(null, moved(run[0..5], to[0..5], other[0..3]));
    // A part that starts in the run and ends past it is not in it, nor one that starts before it.
    try testing.expectEqual(null, moved(run[0..5], to[0..5], run[3..8]));
    try testing.expectEqual(null, moved(run[2..5], to[2..5], run[0..3]));
}
