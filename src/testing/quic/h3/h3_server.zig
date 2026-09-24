//! The h3 server of design §9's UDP QUIC endpoint (design §8 step 12): the server h3spec,
//! `h2load --h3` and the QUIC Interop Runner's `http3` case talk to.
//!
//! It serves the directory hq-interop serves. A request's `:path` names a file under it, held to
//! hq-interop's path rule. A GET is answered 200 with the file as content, and a HEAD 200 with the
//! file's length and no content. A path that names no file is answered 404. `/` is answered 200
//! with a short body of its own, as design §9's h2 server answers it, which is what `h2load`
//! asks for. Content the client sends is read and dropped.
//!
//! The response's frames are kept per stream until the stream closes (decision 79), and its
//! content is read from the file through the stream provider whenever `quic` sends or resends it
//! (decision 57), as hq-interop's is.
//!
//! A peer that breaks a rule of the whole connection makes `h3` close it with the rule's code
//! (RFC 9114 §8). That is the answer h3spec checks for, so the server notes it and goes on.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../../constants.zig");
const hq = @import("../hq/hq.zig");
const hq_file = @import("../hq/hq_file.zig");

const Writer = quic.core.Writer;
const FieldSection = h3.http.FieldSection;
const StreamId = quic.stream.StreamId;
const StreamProvider = quic.stream.StreamProvider;

/// What the endpoint's QPACK decoder advertises, so the peer's encoder uses a dynamic table.
const qpack_settings: h3.qpack.decoder.Settings = .{
    .max_table_capacity = constants.h3_qpack_capacity,
    .blocked_streams = constants.h3_qpack_blocked_streams,
};

pub const Error = h3.connection.SendError || quic.connection_stream_send.Error || h3.http.field_section.AppendError;

/// What a response's content is read from.
const Content = union(enum) {
    none,
    file: hq_file.Descriptor,
    /// `constants.h3_root_body`.
    root,
};

/// One request stream, from its request's header section until the stream closes.
const Response = struct {
    id: u64,
    /// The request's path, copied: its field section is gone by the time the request ends.
    path: [constants.hq_request_len_max]u8 = undefined,
    path_len: usize = 0,
    /// Whether the request was HEAD, whose response carries no content (RFC 9110 §9.3.2).
    head: bool = false,
    /// Whether the response went out.
    answered: bool = false,
    /// Its HEADERS frame and its DATA frame's header.
    prefix: [constants.h3_response_prefix_len_max]u8 = undefined,
    prefix_len: usize = 0,
    content: Content = .none,
    content_len: u64 = 0,

    fn path_of(response: *const Response) []const u8 {
        return response.path[0..response.path_len];
    }
};

pub const Server = struct {
    www: []const u8,
    connection: h3.Connection,
    started: bool,
    /// The code the connection closed with, once `h3` closed it.
    failure: ?u64,
    responses: [h3.constants.request_streams_max]?Response,
    body: [constants.hq_read_len]u8,
    section: FieldSection,
    /// Responses answered with a file or the root body, which the endpoint reports.
    served: u64,

    pub fn init(server: *Server, www: []const u8, grease: u64) void {
        server.www = www;
        server.connection.init(.{ .role = .server, .grease = grease, .qpack = qpack_settings });
        server.started = false;
        server.failure = null;
        server.responses = @splat(null);
        server.served = 0;
    }

    /// The provider `quic` reads through: h3's own streams from h3, and each response from its
    /// frames and its file (decision 79).
    pub fn provider(server: *Server) StreamProvider {
        return server.connection.provider(.{ .context = server, .vtable = &vtable });
    }

    /// What a datagram may have changed: start h3 once the handshake completes, read every event,
    /// and free the streams that closed.
    pub fn step(server: *Server, transport: *quic.Connection) Error!void {
        if (server.failure != null) return;
        if (!server.started) {
            if (!transport.handshake_complete) return;
            server.connection.start(transport) catch return server.note_failure();
            server.started = true;
        }
        // Bounded: every event reads at least one frame or content octet the client sent, and
        // one datagram carries a bounded number of them.
        for (0..constants.hq_read_len) |_| {
            const event = server.connection.receive(transport, &server.body) catch return server.note_failure();
            try server.on_event(transport, event orelse break);
        }
        server.release_closed(transport);
    }

    fn note_failure(server: *Server) void {
        server.failure = server.connection.failure;
        std.debug.print("quic-udp: h3 closed the connection with 0x{x}\n", .{server.failure.?});
    }

    fn on_event(server: *Server, transport: *quic.Connection, event: h3.connection.Event) Error!void {
        switch (event) {
            .request => |held| server.take(held.stream_id, held.request),
            .end => |id| if (server.find(id)) |response| try server.answer(transport, response),
            .reset, .refused => |held| server.release(held.stream_id),
            // Content and trailers the client sends are read and dropped; the rest asks nothing.
            .data, .trailers, .settings, .goaway => {},
            // A server reads requests; `h3` refuses a response on a request stream.
            .response => unreachable,
        }
    }

    /// Keeps a request's path until its end arrives.
    fn take(server: *Server, id: u64, request: h3.message.Request) void {
        const slot = server.free_slot() orelse unreachable; // The server grants as many streams as it has slots.
        slot.* = .{ .id = id, .head = std.mem.eql(u8, request.method, "HEAD") };
        const response = &slot.*.?;
        // A CONNECT names no path (RFC 9114 §4.4), and one too long for hq-interop's rule names no
        // file; both are answered 404.
        const path = request.path orelse return;
        if (path.len > response.path.len) return;
        @memcpy(response.path[0..path.len], path);
        response.path_len = path.len;
    }

    /// Writes the response to a request that has ended, and tells `quic` how far it reaches.
    fn answer(server: *Server, transport: *quic.Connection, response: *Response) Error!void {
        if (response.answered) return;
        response.answered = true;
        server.open_content(response);
        const found = response.content != .none;
        var length_digits: [content_length_digits_max]u8 = undefined;
        server.section.init();
        try server.section.append(":status", if (found) "200" else "404");
        try server.section.append("content-length", std.fmt.bufPrint(&length_digits, "{d}", .{response.content_len}) catch unreachable);
        var writer = Writer.init(&response.prefix);
        try server.connection.write_response(transport, response.id, &server.section, &.{}, &writer);
        // RFC 9110 §9.3.2: a response to HEAD carries no content.
        if (response.head) response.content_len = 0;
        if (response.content_len > 0) try h3.connection.write_data_header(response.content_len, &writer);
        response.prefix_len = writer.written().len;
        if (found) server.served += 1;
        try quic.connection_stream_send.supply(transport, .{ .value = response.id }, response.prefix_len + response.content_len, true);
    }

    /// Opens what the request's path names: the root body, a file, or nothing.
    fn open_content(server: *Server, response: *Response) void {
        const path = response.path_of();
        if (std.mem.eql(u8, path, "/")) {
            response.content = .root;
            response.content_len = constants.h3_root_body.len;
            return;
        }
        hq.check_path(path) catch return;
        const opened = hq_file.open_read(server.www, path) orelse return;
        response.content = .{ .file = opened.descriptor };
        response.content_len = opened.len;
    }

    fn find(server: *Server, id: u64) ?*Response {
        for (&server.responses) |*slot| {
            if (slot.*) |*held| {
                if (held.id == id) return held;
            }
        }
        return null;
    }

    fn free_slot(server: *Server) ?*?Response {
        for (&server.responses) |*slot| {
            if (slot.* == null) return slot;
        }
        return null;
    }

    fn release(server: *Server, id: u64) void {
        for (&server.responses) |*slot| {
            const held = slot.* orelse continue;
            if (held.id != id) continue;
            if (held.content == .file) hq_file.close(held.content.file);
            slot.* = null;
        }
    }

    /// Frees the responses whose streams closed: nothing on them is sent again, so the file can
    /// close (RFC 9000 §3.1, §3.2).
    fn release_closed(server: *Server, transport: *quic.Connection) void {
        for (&server.responses) |*slot| {
            const held = slot.* orelse continue;
            if (transport.streams.lookup(.{ .value = held.id }) == .live) continue;
            server.release(held.id);
        }
    }

    /// Closes every file still open, when the connection ends.
    pub fn deinit(server: *Server) void {
        for (&server.responses) |*slot| {
            const held = slot.* orelse continue;
            server.release(held.id);
        }
    }
};

/// The digits of the longest content-length a file can have.
const content_length_digits_max: usize = 20;

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_response };

/// A response's octets from `offset`: its kept frames, then its content, as many as fit. Every
/// call at one offset answers the same octets, which RFC 9000 §2.2 asks of a retransmission.
fn read_response(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const server: *Server = @ptrCast(@alignCast(context));
    const response = server.find(stream_id) orelse return 0;
    var written: usize = 0;
    if (offset < response.prefix_len) {
        const from: usize = @intCast(offset);
        written = @min(output.len, response.prefix_len - from);
        @memcpy(output[0..written], response.prefix[from..][0..written]);
    }
    if (written == output.len) return written;
    return written + read_content(response, offset + written - response.prefix_len, output[written..]);
}

/// The response's content from `content_offset`, as much as fits.
fn read_content(response: *const Response, content_offset: u64, output: []u8) usize {
    if (content_offset >= response.content_len) return 0;
    const room = output[0..@intCast(@min(output.len, response.content_len - content_offset))];
    return switch (response.content) {
        .file => |descriptor| hq_file.read_at(descriptor, content_offset, room),
        .root => blk: {
            const rest = constants.h3_root_body[@intCast(content_offset)..];
            @memcpy(room[0..@min(room.len, rest.len)], rest[0..@min(room.len, rest.len)]);
            break :blk @min(room.len, rest.len);
        },
        .none => 0,
    };
}
