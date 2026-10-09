//! What the UDP server's `h3` mode answers (design §8 step 17b), one table for each slot of its
//! `server.Endpoint`. A GET of a path under the directory the server serves is
//! answered 200 with the file, a HEAD 200 with its length alone, `/` 200 with a short body, and
//! any other path 404. Content a client sends is read and dropped.
//!
//! `write_body` copies nothing, so a response's content stays in place until its request is done
//! or cancelled (decision 103). A file is mapped read-only for that long (`hq_file.map_read`), and
//! the kernel reads it in as QUIC sends it.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("../../constants.zig");
const hq = @import("../hq/hq.zig");
const hq_file = @import("../hq/hq_file.zig");

/// The endpoint the `h3` mode serves through: as many connections as the UDP server holds, each
/// with its receive pool.
pub const Endpoint = server.EndpointOf(.{
    .tcp_connections = 0,
    .quic_connections = constants.quic_connections_max,
    .receive_pool_len = constants.h3_receive_pool_len,
});

/// One request, from its head until it is done or cancelled.
const Answer = struct {
    in_use: bool = false,
    id: server.Id = .{ .connection = .{ .slot = 0, .generation = 0 }, .number = 0 },
    /// Whether the request was HEAD, whose response carries no content (RFC 9110 §9.3.2).
    head: bool = false,
    /// The request's path, copied: its field section is gone by the time the request ends.
    path: [constants.hq_request_len_max]u8 = undefined,
    path_len: usize = 0,
    /// Whether the response went out.
    answered: bool = false,
    /// The file the response carries, mapped until the request is over.
    mapping: ?[]const u8 = null,
};

pub const Files = struct {
    www: []const u8,
    answers: [server.constants.quic_requests_max]Answer,
    /// Responses answered with a file or the root body, which the endpoint reports.
    served: u64,

    pub fn init(files: *Files, www: []const u8) void {
        files.www = www;
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
    pub fn on_event(files: *Files, endpoint: *Endpoint, reported: server.Event) void {
        switch (reported) {
            .request => |request| files.take(request),
            .body => |body| if (body.end) files.answer(endpoint, body.id),
            .trailers => |trailers| files.answer(endpoint, trailers.id),
            .cancelled => |cancelled| files.release(cancelled.id),
            .done => |done| files.release(done.id),
            .writable => {},
            // The run reads `ended`. A QUIC connection owes no `send` or `close`, and the run never
            // shuts the endpoint down (decision 119).
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
    fn answer(files: *Files, endpoint: *Endpoint, id: server.Id) void {
        const entry = files.entry_of(id) orelse return;
        if (entry.answered) return;
        entry.answered = true;
        const path = entry.path[0..entry.path_len];
        if (std.mem.eql(u8, path, "/")) return files.respond(endpoint, entry, constants.h3_root_body);
        const content = files.open(path) orelse return respond_missing(endpoint, entry);
        entry.mapping = content;
        files.respond(endpoint, entry, content);
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
    fn respond(files: *Files, endpoint: *Endpoint, entry: *Answer, content: []const u8) void {
        assert(entry.in_use and entry.answered);
        var digits: [content_length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable;
        const fields = [_]server.Field{.{ .name = "content-length", .value = length }};
        // RFC 9110 §9.3.2: a response to HEAD carries no content.
        const carries = !entry.head and content.len > 0;
        endpoint.respond(entry.id, .{ .status = ok, .fields = &fields, .end = !carries }) catch return endpoint.cancel(entry.id);
        if (carries) _ = endpoint.write_body(entry.id, .{ .octets = content, .end = true }) catch return endpoint.cancel(entry.id);
        files.served += 1;
    }

    /// Releases the entry of a request that ended, and unmaps its file.
    fn release(files: *Files, id: server.Id) void {
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

    fn entry_of(files: *Files, id: server.Id) ?*Answer {
        for (&files.answers) |*entry| {
            if (entry.in_use and entry.id.number == id.number) return entry;
        }
        return null;
    }
};

/// RFC 9110 §15.5.5: 404 (Not Found), with no content. A response the server would not take is
/// cancelled, and its `cancelled` releases the entry.
fn respond_missing(endpoint: *Endpoint, entry: *Answer) void {
    assert(entry.in_use and entry.answered);
    const fields = [_]server.Field{.{ .name = "content-length", .value = "0" }};
    endpoint.respond(entry.id, .{ .status = not_found, .fields = &fields, .end = true }) catch endpoint.cancel(entry.id);
}

const ok: u16 = 200;
const not_found: u16 = 404;
/// The digits of the longest content-length a file can have.
const content_length_digits_max: usize = 20;
