//! What the UDP server's `h3` mode answers (design §8 step 17b), one table for each connection,
//! over colibri's `server` module. A GET of a path under the directory the server serves is
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

/// One request, from its head until it is done or cancelled.
const Answer = struct {
    in_use: bool = false,
    id: u64 = 0,
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

    /// Reads every event `connection` has and answers each request whose content ended. False
    /// when the connection failed.
    pub fn serve(files: *Files, connection: *server.QuicConnection, now_ns: u64) bool {
        for (0..constants.h3_serve_events_max) |_| {
            const received = connection.receive(now_ns) catch return false;
            const reported = received.event orelse return true;
            files.on_event(connection, reported);
        }
        return true;
    }

    fn on_event(files: *Files, connection: *server.QuicConnection, reported: server.Event) void {
        switch (reported) {
            .request => |request| files.take(request),
            .body => |body| if (body.end) files.answer(connection, body.id),
            .trailers => |trailers| files.answer(connection, trailers.id),
            .cancelled => |cancelled| files.release(cancelled.id),
            .done => |done| files.release(done.id),
        }
    }

    /// Keeps a request's path until its end arrives. The server holds as many requests as the
    /// table has entries, and each request it reported ends in `done`, in `cancelled`, or in a
    /// cancel of the table's own, each of which releases its entry: so a free one is there.
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
    fn answer(files: *Files, connection: *server.QuicConnection, id: u64) void {
        const entry = files.entry_of(id) orelse return;
        if (entry.answered) return;
        entry.answered = true;
        const path = entry.path[0..entry.path_len];
        if (std.mem.eql(u8, path, "/")) return files.respond(connection, entry, constants.h3_root_body);
        const content = files.open(path) orelse return files.respond_missing(connection, entry);
        entry.mapping = content;
        files.respond(connection, entry, content);
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
    fn respond(files: *Files, connection: *server.QuicConnection, entry: *Answer, content: []const u8) void {
        assert(entry.in_use and entry.answered);
        var digits: [content_length_digits_max]u8 = undefined;
        const length = std.fmt.bufPrint(&digits, "{d}", .{content.len}) catch unreachable;
        const fields = [_]server.Field{.{ .name = "content-length", .value = length }};
        // RFC 9110 §9.3.2: a response to HEAD carries no content.
        const carries = !entry.head and content.len > 0;
        connection.respond(entry.id, ok, &fields, !carries) catch return files.abandon(connection, entry);
        if (carries) _ = connection.write_body(entry.id, content, true) catch return files.abandon(connection, entry);
        files.served += 1;
    }

    /// RFC 9110 §15.5.5: 404 (Not Found), with no content.
    fn respond_missing(files: *Files, connection: *server.QuicConnection, entry: *Answer) void {
        assert(entry.in_use and entry.answered);
        const fields = [_]server.Field{.{ .name = "content-length", .value = "0" }};
        connection.respond(entry.id, not_found, &fields, true) catch files.abandon(connection, entry);
    }

    /// Cancels a request whose response the server would not take. The server reports nothing
    /// more of it, so its entry is released here.
    fn abandon(files: *Files, connection: *server.QuicConnection, entry: *Answer) void {
        connection.cancel(entry.id);
        files.release(entry.id);
    }

    fn release(files: *Files, id: u64) void {
        const entry = files.entry_of(id) orelse return;
        if (entry.mapping) |mapping| hq_file.unmap(mapping);
        entry.* = .{};
    }

    /// Unmaps every file, when the connection is over.
    pub fn release_all(files: *Files) void {
        for (&files.answers) |*entry| {
            if (entry.in_use) files.release(entry.id);
        }
    }

    fn free_entry(files: *Files) ?*Answer {
        for (&files.answers) |*entry| {
            if (!entry.in_use) return entry;
        }
        return null;
    }

    fn entry_of(files: *Files, id: u64) ?*Answer {
        for (&files.answers) |*entry| {
            if (entry.in_use and entry.id == id) return entry;
        }
        return null;
    }
};

const ok: u16 = 200;
const not_found: u16 = 404;
/// The digits of the longest content-length a file can have.
const content_length_digits_max: usize = 20;
