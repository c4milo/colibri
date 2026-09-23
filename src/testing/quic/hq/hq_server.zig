//! The hq-interop server of design §9's UDP QUIC endpoint (design §8 step 9e, piece 11).
//!
//! Each bidirectional stream the client opens carries one request line and the end of the
//! client's side (`hq.zig`). Once the line is whole, the server answers on the same stream with
//! the file it names and ends its own side. A request it cannot answer — malformed, too long, or
//! naming no file — gets its stream reset. colibri reads the file's octets back through the
//! stream provider whenever it sends or resends them (decision 57), so the file stays open until
//! the stream closes.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../../constants.zig");
const hq = @import("hq.zig");
const hq_file = @import("hq_file.zig");

const Connection = quic.Connection;
const StreamId = quic.stream.StreamId;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

pub const Error = quic.connection_stream_send.Error;

comptime {
    // A slot per stream the client may have open at once, which the server's own
    // `initial_max_streams_bidi` sets and colibri's stream table bounds.
    assert(constants.hq_requests_max <= quic.constants.streams_per_connection_max);
}

/// One stream the client opened.
const Request = struct {
    in_use: bool = false,
    id: StreamId = .{ .value = 0 },
    line: [constants.hq_request_len_max]u8 = undefined,
    line_len: usize = 0,
    /// Whether the request has had its answer: a file supplied, or the stream reset.
    answered: bool = false,
    /// The file being sent, or `none` when the answer was a reset.
    file: hq_file.Descriptor = hq_file.none,
};

pub const Server = struct {
    /// The directory the server serves, which every path is joined to.
    www: []const u8,
    requests: [constants.hq_requests_max]Request,
    /// The index of the next of the client's bidirectional streams no slot has taken (RFC 9000
    /// §2.1). The client opens them in order, so every one below it is taken or done.
    next_index: u64,
    /// Requests answered with a file, which the endpoint reports.
    served: u64,

    pub fn init(server: *Server, www: []const u8) void {
        server.www = www;
        for (&server.requests) |*request| request.* = .{};
        server.next_index = 0;
        server.served = 0;
    }

    pub fn provider(server: *Server) StreamProvider {
        return .{ .context = server, .vtable = &vtable };
    }

    /// What a datagram may have changed: streams the client opened, request lines that arrived
    /// whole, and streams that closed.
    pub fn step(server: *Server, connection: *Connection) Error!void {
        server.take_opened(connection);
        for (&server.requests) |*request| {
            if (!request.in_use) continue;
            if (request.answered) {
                release_if_closed(connection, request);
            } else {
                try server.read_line(connection, request);
            }
        }
    }

    /// Gives a slot to each stream the client opened since the last step.
    fn take_opened(server: *Server, connection: *Connection) void {
        // Bounded by the slots: the client cannot have more open than the server allows.
        for (0..server.requests.len) |_| {
            const id = StreamId.of(.client, .bidirectional, server.next_index);
            switch (connection.streams.lookup(id)) {
                .unopened => return,
                // Opened and already over, reset by the client before a step saw it.
                .closed => {},
                .live => {
                    const slot = server.free_slot() orelse return;
                    slot.* = .{ .in_use = true, .id = id };
                },
            }
            server.next_index += 1;
        }
    }

    fn free_slot(server: *Server) ?*Request {
        for (&server.requests) |*request| {
            if (!request.in_use) return request;
        }
        return null;
    }

    /// Reads what has arrived of the request line, and answers once the client's side ended.
    fn read_line(server: *Server, connection: *Connection, request: *Request) Error!void {
        const room = request.line[request.line_len..];
        const read = quic.connection_stream_read.read(connection, request.id, room) catch {
            // The client reset the stream, so there is no request to answer.
            request.* = .{};
            return;
        };
        request.line_len += read.len;
        if (read.fin) return server.answer(connection, request);
        // A line that fills the buffer before the client ends its side is longer than
        // `hq_request_len_max`. RFC 9000 §3.5: STOP_SENDING asks the client to stop sending it.
        if (request.line_len == request.line.len) {
            try quic.connection_stream_send.stop_sending(connection, request.id, constants.hq_refused_error_code);
            try refuse(connection, request);
        }
    }

    fn answer(server: *Server, connection: *Connection, request: *Request) Error!void {
        const path = hq.read_request(request.line[0..request.line_len]) catch return refuse(connection, request);
        const opened = hq_file.open_read(server.www, path) orelse return refuse(connection, request);
        request.file = opened.descriptor;
        request.answered = true;
        server.served += 1;
        try quic.connection_stream_send.supply(connection, request.id, opened.len, true);
    }

    fn find(server: *Server, stream_id: u64) ?*Request {
        for (&server.requests) |*request| {
            if (request.in_use and request.id.value == stream_id) return request;
        }
        return null;
    }
};

/// Resets the stream of a request the server will not answer (RFC 9000 §3.1).
fn refuse(connection: *Connection, request: *Request) Error!void {
    request.answered = true;
    try quic.connection_stream_send.reset(connection, request.id, constants.hq_refused_error_code);
}

/// Frees a slot whose stream closed, which it does once both sides are over (RFC 9000 §3.1,
/// §3.2): nothing on it will be sent again, so the file can close.
fn release_if_closed(connection: *Connection, request: *Request) void {
    if (connection.streams.lookup(request.id) == .live) return;
    if (request.file != hq_file.none) hq_file.close(request.file);
    request.* = .{};
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_file };

/// The octets of a stream's file from `offset`, as many as fit. Every call at one offset answers
/// the same octets, which RFC 9000 §2.2 asks of a retransmission.
fn read_file(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const server: *Server = @ptrCast(@alignCast(context));
    const request = server.find(stream_id) orelse return 0;
    if (request.file == hq_file.none) return 0;
    return hq_file.read_at(request.file, offset, output);
}
