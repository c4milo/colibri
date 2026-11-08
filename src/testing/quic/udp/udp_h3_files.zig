//! What the UDP server's `h3` mode answers (design §8 step 17b), one table for each slot of its
//! `server.Engine`. A GET of a path under the directory the server serves is
//! answered 200 with the file, a HEAD 200 with its length alone, `/` 200 with a short body, and
//! any other path 404. Content a client sends is read and dropped.
//!
//! `write_body` copies nothing, so a response's content stays in place until its request is done
//! or cancelled (decision 103). A file is mapped read-only (`hq_file.map_read`), and the kernel
//! reads it in as QUIC sends it. `Mapped` keeps each file mapped from the first request that asks
//! for it until the run ends, so a later request makes no system call to read it. A file past
//! `h3_mapped_files_max` is mapped for its request alone.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("../../constants.zig");
const hq = @import("../hq/hq.zig");
const hq_file = @import("../hq/hq_file.zig");

/// The engine the `h3` mode serves through: as many connections as the UDP server holds, each
/// with its receive pool.
pub const Engine = server.Engine(.{
    .tcp_connections = 0,
    .quic_connections = constants.quic_connections_max,
    .receive_pool_len = constants.h3_receive_pool_len,
});

/// One request, from its head until it is done or cancelled.
const Answer = struct {
    in_use: bool = false,
    id: server.RequestId = .{ .connection = .{ .slot = 0, .generation = 0 }, .number = 0 },
    /// Whether the request was HEAD, whose response carries no content (RFC 9110 §9.3.2).
    head: bool = false,
    /// The request's path, copied: its field section is gone by the time the request ends.
    path: [constants.hq_request_len_max]u8 = undefined,
    path_len: usize = 0,
    /// Whether the response went out.
    answered: bool = false,
    /// The file the response carries when `Mapped` had no room for it, mapped until the request
    /// is over.
    mapping: ?[]const u8 = null,
};

/// The files the run keeps mapped, by path, shared by every connection's table. A path that names
/// no file is not kept, so each request for it tries to open the file again.
pub const Mapped = struct {
    paths: [constants.h3_mapped_files_max][constants.hq_request_len_max]u8 = undefined,
    path_lens: [constants.h3_mapped_files_max]usize = undefined,
    contents: [constants.h3_mapped_files_max][]const u8 = undefined,
    count: usize = 0,

    /// The content of `path` when a request asked for it before.
    fn find(mapped: *const Mapped, path: []const u8) ?[]const u8 {
        for (0..mapped.count) |index| {
            if (std.mem.eql(u8, mapped.paths[index][0..mapped.path_lens[index]], path)) return mapped.contents[index];
        }
        return null;
    }

    /// Keeps `content` mapped under `path`, or answers false when every place is taken.
    fn keep(mapped: *Mapped, path: []const u8, content: []const u8) bool {
        assert(path.len <= constants.hq_request_len_max);
        assert(mapped.find(path) == null);
        if (mapped.count == constants.h3_mapped_files_max) return false;
        @memcpy(mapped.paths[mapped.count][0..path.len], path);
        mapped.path_lens[mapped.count] = path.len;
        mapped.contents[mapped.count] = content;
        mapped.count += 1;
        return true;
    }
};

pub const Files = struct {
    www: []const u8,
    mapped: *Mapped,
    answers: [server.constants.limits.quic_requests_max]Answer,
    /// Responses answered with a file or the root body, which the engine reports.
    served: u64,

    pub fn init(files: *Files, www: []const u8, mapped: *Mapped) void {
        files.www = www;
        files.mapped = mapped;
        files.answers = @splat(.{});
        files.served = 0;
    }

    /// Empties the table of a connection that is over. Every request it reported has ended
    /// (INV-30), so no entry is in use and no file is mapped.
    pub fn reset(files: *Files) void {
        for (&files.answers) |*entry| assert(!entry.in_use);
        files.served = 0;
    }

    /// Acts on an event of a request of this table's connection, and answers each request whose
    /// content ended.
    pub fn on_event(files: *Files, engine: *Engine, reported: server.Event) void {
        switch (reported) {
            .request => |request| {
                files.take(request);
                // Decision 116 as amended: a head that ended its stream is the whole request.
                if (request.end) files.answer(engine, request.id);
            },
            .body => |body| if (body.end) files.answer(engine, body.id),
            .trailers => |trailers| files.answer(engine, trailers.id),
            .finished => |finished| files.release(finished.id),
            .writable => {},
            // The run reads `ended`. A QUIC connection owes no `send` or `close`, and the run never
            // shuts the engine down (decision 119).
            .send, .close, .ended, .closed => unreachable,
        }
    }

    /// Keeps a request's path until its end arrives. The server holds as many requests as the
    /// table has entries, and each request it reported ends in one `done` or `cancelled`, which
    /// releases its entry: so a free one is there.
    fn take(files: *Files, request: server.Request) void {
        const entry = files.free_entry() orelse unreachable;
        entry.* = .{ .in_use = true, .id = request.id, .head = std.mem.eql(u8, request.method, "HEAD") };
        // A CONNECT names no path (RFC 9114 §4.4), and a path too long for hq-interop's rule names
        // no file; both are answered 404.
        const path = request.path orelse return;
        if (path.len > entry.path.len) return;
        @memcpy(entry.path[0..path.len], path);
        entry.path_len = path.len;
    }

    /// Answers a request whose content ended: the root body, a file, or 404.
    fn answer(files: *Files, engine: *Engine, id: server.RequestId) void {
        const entry = files.entry_of(id) orelse return;
        if (entry.answered) return;
        entry.answered = true;
        const path = entry.path[0..entry.path_len];
        if (std.mem.eql(u8, path, "/")) return files.respond(engine, entry, constants.h3_root_body);
        const content = files.content_of(entry, path) orelse return respond_missing(engine, entry);
        files.respond(engine, entry, content);
    }

    /// The content of the file `path` names: the mapping `Mapped` kept, or the file mapped now and
    /// kept, or mapped for `entry`'s request alone when `Mapped` is full. Null when it names none.
    fn content_of(files: *Files, entry: *Answer, path: []const u8) ?[]const u8 {
        if (files.mapped.find(path)) |content| return content;
        const content = files.open(path) orelse return null;
        if (!files.mapped.keep(path, content)) entry.mapping = content;
        return content;
    }

    /// Maps the file `path` names read-only, or answers null when it names none. An empty file
    /// is answered with no content.
    fn open(files: *const Files, path: []const u8) ?[]const u8 {
        hq.check_path(path) catch return null;
        const opened = hq_file.open_read(files.www, path) orelse return null;
        defer hq_file.close(opened.descriptor);
        return hq_file.map_read(opened.descriptor, opened.len);
    }

    /// Answers 200 with `content`, whose octets stay where they are until the request is over.
    fn respond(files: *Files, engine: *Engine, entry: *Answer, content: []const u8) void {
        assert(entry.in_use and entry.answered);
        var digits: [content_length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable;
        const fields = [_]server.Header{.{ .name = "content-length", .value = length }};
        // RFC 9110 §9.3.2: a response to HEAD carries no content.
        const carries = !entry.head and content.len > 0;
        engine.respond(entry.id, .{ .status = @enumFromInt(ok), .headers = &fields, .end = !carries }) catch return engine.cancel(entry.id);
        if (carries) _ = engine.write_body(entry.id, .{ .bytes = content, .end = true }) catch return engine.cancel(entry.id);
        files.served += 1;
    }

    /// Releases the entry of a request that ended, and unmaps its file.
    fn release(files: *Files, id: server.RequestId) void {
        const entry = files.entry_of(id) orelse return;
        if (entry.mapping) |mapping| hq_file.unmap(mapping);
        entry.* = .{};
    }

    fn free_entry(files: *Files) ?*Answer {
        for (&files.answers) |*entry| {
            if (!entry.in_use) return entry;
        }
        return null;
    }

    fn entry_of(files: *Files, id: server.RequestId) ?*Answer {
        for (&files.answers) |*entry| {
            if (entry.in_use and entry.id.number == id.number) return entry;
        }
        return null;
    }
};

/// RFC 9110 §15.5.5: 404 (Not Found), with no content. A response the server would not take is
/// cancelled, and its `cancelled` releases the entry.
fn respond_missing(engine: *Engine, entry: *Answer) void {
    assert(entry.in_use and entry.answered);
    const fields = [_]server.Header{.{ .name = "content-length", .value = "0" }};
    engine.respond(entry.id, .{ .status = @enumFromInt(not_found), .headers = &fields, .end = true }) catch engine.cancel(entry.id);
}

const ok: u16 = 200;
const not_found: u16 = 404;
/// The digits of the longest content-length a file can have.
const content_length_digits_max: usize = 20;

const testing = std.testing;

test "design §8 step 29d: a file a request asked for before is answered from the mapping kept" {
    var mapped: Mapped = .{};
    const content = "colibri\n";
    try testing.expectEqual(null, mapped.find("/colibri.txt"));
    try testing.expect(mapped.keep("/colibri.txt", content));
    // The same octets, not a copy: no later request maps the file again.
    try testing.expectEqual(content.ptr, mapped.find("/colibri.txt").?.ptr);
    try testing.expectEqual(null, mapped.find("/colibri"));
    try testing.expectEqual(null, mapped.find("/colibri.txt2"));
}

test "design §8 step 29d: a full table keeps no more files, and keeps the ones it holds" {
    var mapped: Mapped = .{};
    var names: [constants.h3_mapped_files_max][8]u8 = undefined;
    for (&names, 0..) |*name, index| {
        const path = std.fmt.bufPrint(name, "/{d}", .{index}) catch unreachable;
        try testing.expect(mapped.keep(path, "x"));
    }
    try testing.expect(!mapped.keep("/past", "y"));
    try testing.expectEqual(null, mapped.find("/past"));
    try testing.expectEqualStrings("x", mapped.find("/0").?);
}

/// The table the test of `content_of` reads through, outside any stack frame, and the directory it
/// writes its file into, which `zig build` makes before any test runs.
var test_files: Files align(@alignOf(Files)) = undefined;
var test_mapped: Mapped align(@alignOf(Mapped)) = .{};
const test_directory = ".zig-cache";
const test_path = "/udp_h3_files_test.txt";

test "design §8 step 29d: a file is mapped once, and a later request reads the mapping kept" {
    test_files.init(test_directory, &test_mapped);
    const descriptor = hq_file.create(test_directory, test_path) orelse return error.TestUnexpectedResult;
    const written = hq_file.write_all(descriptor, "colibri\n");
    hq_file.close(descriptor);
    try testing.expect(written);
    var entry: Answer = .{ .in_use = true };
    const first = files_content(&entry) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("colibri\n", first);
    try testing.expectEqual(null, entry.mapping);
    // With the file gone, only the mapping kept can answer.
    try testing.expectEqual(0, std.c.unlink(test_directory ++ test_path));
    const again = files_content(&entry) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(first.ptr, again.ptr);
    try testing.expectEqual(null, test_files.content_of(&entry, "/udp_h3_files_missing.txt"));
}

fn files_content(entry: *Answer) ?[]const u8 {
    return test_files.content_of(entry, test_path);
}
