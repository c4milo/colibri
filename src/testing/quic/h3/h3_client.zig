//! The h3 client of design §9's UDP QUIC endpoint (design §8 step 12), which the QUIC Interop
//! Runner's `http3` case runs.
//!
//! Once the handshake completes it starts h3 and sends one GET per path, in order, so the `i`th
//! path rides the client's `i`th bidirectional stream (RFC 9000 §2.1). A server that allows fewer
//! streams than there are paths gets the rest as its MAX_STREAMS frames allow (§4.6). Each 200
//! response's content is written to the file of the same name in the downloads directory. Any
//! other status, a reset, or a refused stream fails the run.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../../constants.zig");
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

pub const Error = h3.connection.Error || h3.connection.SendError || h3.http.field_section.AppendError ||
    quic.connection_stream_send.Error || error{
    /// A file in the downloads directory could not be created or written.
    DownloadRefused,
    /// A response other than 200, a reset, a refused stream or a GOAWAY.
    ResponseRefused,
};

/// One path's request: its HEADERS frame, kept until the stream closes (decision 79), and the
/// download its response goes into.
const Request = struct {
    prefix: [constants.h3_request_prefix_len_max]u8 = undefined,
    prefix_len: usize = 0,
    file: hq_file.Descriptor = hq_file.none,
    finished: bool = false,
};

pub const Client = struct {
    downloads: []const u8,
    paths: []const []const u8,
    /// The `:authority` of every request: the host name the certificate names (RFC 9114 §3.3).
    authority: []const u8,
    connection: h3.Connection,
    started: bool,
    requests: [constants.hq_paths_max]Request,
    /// How many paths have a stream, and how many have arrived whole.
    opened: usize,
    finished_count: usize,
    /// Octets of every response's content, which the endpoint reports.
    received_len: u64,
    body: [constants.hq_read_len]u8,
    section: FieldSection,

    pub fn init(client: *Client, downloads: []const u8, paths: []const []const u8, authority: []const u8, grease: u64) void {
        assert(paths.len > 0 and paths.len <= constants.hq_paths_max);
        client.downloads = downloads;
        client.paths = paths;
        client.authority = authority;
        client.connection.init(.{ .role = .client, .grease = grease, .qpack = qpack_settings });
        client.started = false;
        client.opened = 0;
        client.finished_count = 0;
        client.received_len = 0;
        for (client.requests[0..paths.len]) |*request| request.* = .{};
    }

    pub fn provider(client: *Client) StreamProvider {
        return client.connection.provider(.{ .context = client, .vtable = &vtable });
    }

    pub fn is_done(client: *const Client) bool {
        return client.finished_count == client.paths.len;
    }

    /// What a datagram may have changed: start h3 once the handshake completes, send the requests
    /// the server's limit allows, and read every event.
    pub fn step(client: *Client, transport: *quic.Connection) Error!void {
        if (!client.started) {
            if (!transport.handshake_complete) return;
            try client.connection.start(transport);
            client.started = true;
        }
        try client.send_requests(transport);
        // Bounded: every event reads at least one frame or content octet the server sent.
        for (0..constants.hq_read_len) |_| {
            const event = try client.connection.receive(transport, &client.body) orelse return;
            try client.on_event(event);
        }
    }

    fn send_requests(client: *Client, transport: *quic.Connection) Error!void {
        // Bounded by the paths.
        while (client.opened < client.paths.len) {
            const index = client.opened;
            const path = client.paths[index];
            const request = &client.requests[index];
            client.section.init();
            try client.section.append(":method", "GET");
            try client.section.append(":scheme", "https");
            try client.section.append(":authority", client.authority);
            try client.section.append(":path", path);
            var writer = Writer.init(&request.prefix);
            const id = client.connection.write_request(transport, &client.section, &.{}, &writer) catch |failure| switch (failure) {
                // RFC 9000 §4.6: past the server's limit the rest wait for its MAX_STREAMS.
                error.StreamsExhausted => return,
                else => return failure,
            };
            assert(StreamId.index(.{ .value = id }) == index);
            request.prefix_len = writer.written().len;
            request.file = hq_file.create(client.downloads, path) orelse return error.DownloadRefused;
            try quic.connection_stream_send.supply(transport, .{ .value = id }, request.prefix_len, true);
            client.opened += 1;
        }
    }

    fn on_event(client: *Client, event: h3.connection.Event) Error!void {
        switch (event) {
            .response => |held| {
                // An interim response comes before the final one (RFC 9114 §4.1).
                if (held.response.status.is_interim()) return;
                if (held.response.status.code != ok_status) return error.ResponseRefused;
            },
            .data => |held| {
                const request = client.request_of(held.stream_id);
                if (!hq_file.write_all(request.file, held.octets)) return error.DownloadRefused;
                client.received_len += held.octets.len;
            },
            .end => |id| {
                const request = client.request_of(id);
                hq_file.close(request.file);
                request.file = hq_file.none;
                request.finished = true;
                client.finished_count += 1;
            },
            .settings, .trailers => {},
            .reset, .refused, .goaway, .request => return error.ResponseRefused,
        }
    }

    fn request_of(client: *Client, stream_id: u64) *Request {
        const index: usize = @intCast(StreamId.index(.{ .value = stream_id }));
        assert(index < client.opened);
        return &client.requests[index];
    }
};

/// RFC 9110 §15.3.1.
const ok_status: u16 = 200;

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_request };

/// A request stream's HEADERS frame from `offset`, which the client keeps until the stream closes.
fn read_request(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const client: *Client = @ptrCast(@alignCast(context));
    const request = client.request_of(stream_id);
    if (offset >= request.prefix_len) return 0;
    const from: usize = @intCast(offset);
    const len = @min(output.len, request.prefix_len - from);
    @memcpy(output[0..len], request.prefix[from..][0..len]);
    return len;
}
