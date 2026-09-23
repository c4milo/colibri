//! The hq-interop client of design §9's UDP QUIC endpoint (design §8 step 9e, piece 11).
//!
//! Once the handshake completes it opens one bidirectional stream per path, in order, so the
//! `i`th path rides the client's `i`th bidirectional stream (RFC 9000 §2.1). Each stream carries
//! the request line and the end of the client's side (`hq.zig`), and the server's answer is
//! written to the file of the same name in the downloads directory. A server that allows fewer
//! streams than there are paths gets the rest as its MAX_STREAMS frames allow (RFC 9000 §4.6).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../../constants.zig");
const hq = @import("hq.zig");
const hq_file = @import("hq_file.zig");

const Connection = quic.Connection;
const StreamId = quic.stream.StreamId;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

pub const Error = quic.connection_stream_send.Error || quic.connection_stream_read.Error || error{
    /// A file in the downloads directory could not be created or written.
    DownloadRefused,
};

/// Reads one stream may take in one step: enough to empty the receive pool, which bounds what the
/// server can have sent ahead of the client's reads (decision 61).
const reads_per_step_max = quic.constants.receive_pool_len_default / constants.hq_read_len + 1;

pub const Client = struct {
    downloads: []const u8,
    /// The paths to fetch, each already checked by `hq.write_request`.
    paths: []const []const u8,
    /// Each path's download, open until its stream's last octet arrives.
    files: [constants.hq_paths_max]hq_file.Descriptor,
    finished: [constants.hq_paths_max]bool,
    /// How many paths have a stream, and how many have arrived whole.
    opened: usize,
    finished_count: usize,
    /// Octets of every response, which the endpoint reports.
    received_len: u64,
    buffer: [constants.hq_read_len]u8,

    pub fn init(client: *Client, downloads: []const u8, paths: []const []const u8) void {
        assert(paths.len > 0 and paths.len <= constants.hq_paths_max);
        client.downloads = downloads;
        client.paths = paths;
        client.files = @splat(hq_file.none);
        client.finished = @splat(false);
        client.opened = 0;
        client.finished_count = 0;
        client.received_len = 0;
    }

    pub fn provider(client: *Client) StreamProvider {
        return .{ .context = client, .vtable = &vtable };
    }

    pub fn is_done(client: *const Client) bool {
        return client.finished_count == client.paths.len;
    }

    /// What a datagram may have changed: streams the server now allows, and answers that arrived.
    pub fn step(client: *Client, connection: *Connection) Error!void {
        if (!connection.handshake_complete) return;
        try client.open_requests(connection);
        for (0..client.opened) |index| {
            if (!client.finished[index]) try client.read_answer(connection, index);
        }
    }

    /// Opens a stream for each path that has none, while the server's limit allows.
    fn open_requests(client: *Client, connection: *Connection) Error!void {
        // Bounded by the paths.
        while (client.opened < client.paths.len) {
            // RFC 9000 §4.6: past the server's limit the rest wait for its MAX_STREAMS.
            const id = quic.connection_stream_send.open(connection, .bidirectional) catch return;
            assert(id.index() == client.opened);
            const path = client.paths[client.opened];
            client.files[client.opened] = hq_file.create(client.downloads, path) orelse return error.DownloadRefused;
            var line: [constants.hq_request_len_max]u8 = undefined;
            const request = hq.write_request(path, &line) catch unreachable;
            try quic.connection_stream_send.supply(connection, id, request.len, true);
            client.opened += 1;
        }
    }

    /// Writes what has arrived of one answer to its file, and closes it at the stream's end.
    fn read_answer(client: *Client, connection: *Connection, index: usize) Error!void {
        const id = StreamId.of(.client, .bidirectional, index);
        for (0..reads_per_step_max) |_| {
            const read = try quic.connection_stream_read.read(connection, id, &client.buffer);
            if (!hq_file.write_all(client.files[index], client.buffer[0..read.len])) return error.DownloadRefused;
            client.received_len += read.len;
            if (read.fin) {
                hq_file.close(client.files[index]);
                client.files[index] = hq_file.none;
                client.finished[index] = true;
                client.finished_count += 1;
                return;
            }
            if (read.len == 0) return;
        }
    }
};

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_request };

/// The request line of the stream's path from `offset`, as many octets as fit.
fn read_request(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const client: *Client = @ptrCast(@alignCast(context));
    const index: usize = @intCast(StreamId.index(.{ .value = stream_id }));
    assert(index < client.opened);
    var line: [constants.hq_request_len_max]u8 = undefined;
    const request = hq.write_request(client.paths[index], &line) catch unreachable;
    if (offset >= request.len) return 0;
    const rest = request[@intCast(offset)..];
    const len = @min(rest.len, output.len);
    @memcpy(output[0..len], rest[0..len]);
    return len;
}
