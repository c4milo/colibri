//! The counted-cost check of design §8 step 6: what one request costs, in calls across colibri's
//! boundary and octets moved through them, committed as exact numbers.
//!
//! What it counts is what a caller can see from outside, because the library counts nothing
//! itself: CLAUDE.md's performance rules forbid a statistic that costs a branch on the per-frame
//! path. So the numbers here are calls to `receive` and `write_pending`, the octets each carried,
//! and — over TLS — the calls to the provider and the octets it copied, which the null provider of
//! `null_provider.zig` counts because it is the simulator's and not the library's.
//!
//! Allocations are not counted. [Decision 35](../../docs/decisions.md) makes them zero and
//! `tools/lint/heap.zig` holds it.
//!
//! A change to any number fails `zig build test` until the new one is committed on purpose. That
//! is the whole point: design §11.5 makes this the cheap layer, and `bench/` the expensive one.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const sim = @import("sim");
const constants = sim.constants;

const h2_constants = h2.constants;

/// What one scenario cost.
pub const Cost = struct {
    /// Calls to `receive`. Each one consumes at most one frame (decision 39), so this is the
    /// number of frames the caller fed plus the call that told it to stop.
    receive_calls: u32 = 0,
    /// Calls to `write_pending`. Each is one write the caller would have made.
    write_calls: u32 = 0,
    /// Octets the caller handed to `receive` and that it consumed.
    octets_in: u32 = 0,
    /// Octets `write_pending` and the send path wrote into the caller's buffer.
    octets_out: u32 = 0,
    /// Calls to the provider's `decrypt_record` and `encrypt_record`, zero without one.
    provider_calls: u32 = 0,
};

/// One request and its response at a server, in cleartext, prior knowledge. The numbers below are
/// the committed cost of that exchange.
pub const server_cleartext: Cost = .{
    .receive_calls = 4,
    .write_calls = 3,
    .octets_in = 58,
    .octets_out = 58,
    .provider_calls = 0,
};

/// One request out and its response in at a client, in cleartext.
pub const client_cleartext: Cost = .{
    .receive_calls = 3,
    .write_calls = 3,
    .octets_in = 19,
    .octets_out = 100,
    .provider_calls = 0,
};

/// The same exchange at a server, with the null TLS provider under it. The provider calls are the
/// crossings of the vtable: one `decrypt_record` per record the peer sent, one `encrypt_record`
/// for the response.
pub const server_tls: Cost = .{
    .receive_calls = 4,
    .write_calls = 3,
    .octets_in = 58,
    .octets_out = 58,
    .provider_calls = 2,
};

/// The storage a scenario needs, which the caller places (decision 35).
pub const Storage = struct {
    connection: h2.Connection,
    provider: sim.NullProvider,
    input: [constants.cost_check_buffer_len]u8,
    output: [constants.cost_check_buffer_len]u8,
    scratch: [constants.cost_check_buffer_len]u8,

    pub const zeroed: Storage = .{
        .connection = undefined,
        .provider = .{},
        .input = @splat(0),
        .output = @splat(0),
        .scratch = @splat(0),
    };
};

/// Feeds `input` frame by frame, writing what the connection owes before each read, and counts
/// what it took (design §4.1).
fn drive(storage: *Storage, input: []const u8, cost: *Cost) !void {
    var offset: usize = 0;
    // The loop is bounded by the octets fed: every turn consumes one or ends the loop
    // (non-negotiable 4).
    for (0..constants.cost_check_buffer_len) |_| {
        if (storage.connection.has_pending()) {
            const written = storage.connection.write_pending(&storage.output, 0);
            cost.write_calls += 1;
            cost.octets_out += @intCast(written);
        }
        const received = try storage.connection.receive(input[offset..], 0);
        cost.receive_calls += 1;
        if (received.consumed == 0) break;
        offset += received.consumed;
        cost.octets_in += @intCast(received.consumed);
    }
    assert(offset == input.len);
}

/// Builds the octets a client sends: the preface, its SETTINGS and one request that ends its
/// stream (RFC 9113 §3.4, §6.5, §8.3.1).
fn client_octets(storage: *Storage) []const u8 {
    var writer = sim.core.Writer.init(&storage.scratch);
    writer.write_bytes(h2_constants.client_preface) catch unreachable;
    write_frame(&writer, h2_constants.frame_type_settings, 0, 0, &.{});
    var block: [constants.cost_check_buffer_len]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2_constants.header_table_size_initial, .never);
    var block_writer = sim.core.Writer.init(&block);
    encoder.begin_block(&block_writer) catch unreachable;
    encoder.write_field(&block_writer, ":method", "GET", .without_indexing) catch unreachable;
    encoder.write_field(&block_writer, ":scheme", "https", .without_indexing) catch unreachable;
    encoder.write_field(&block_writer, ":path", "/", .without_indexing) catch unreachable;
    encoder.write_field(&block_writer, ":authority", "example.com", .without_indexing) catch unreachable;
    encoder.commit_block();
    const flags = h2_constants.flag_end_headers | h2_constants.flag_end_stream;
    write_frame(&writer, h2_constants.frame_type_headers, flags, 1, block_writer.written());
    return writer.written();
}

/// Builds the octets a server sends back: its SETTINGS and one response that ends the stream.
fn server_octets(storage: *Storage) []const u8 {
    var writer = sim.core.Writer.init(&storage.scratch);
    write_frame(&writer, h2_constants.frame_type_settings, 0, 0, &.{});
    var block: [constants.cost_check_buffer_len]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(h2_constants.header_table_size_initial, .never);
    var block_writer = sim.core.Writer.init(&block);
    encoder.begin_block(&block_writer) catch unreachable;
    encoder.write_field(&block_writer, ":status", "200", .without_indexing) catch unreachable;
    encoder.commit_block();
    const flags = h2_constants.flag_end_headers | h2_constants.flag_end_stream;
    write_frame(&writer, h2_constants.frame_type_headers, flags, 1, block_writer.written());
    return writer.written();
}

/// One frame header and its payload (RFC 9113 §4.1).
fn write_frame(writer: *sim.core.Writer, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) void {
    h2.frame.write_header(writer, .{
        .length = @intCast(payload.len),
        .type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    }) catch unreachable;
    writer.write_bytes(payload) catch unreachable;
}

/// What one request and its response cost at a cleartext server.
pub fn measure_server_cleartext(storage: *Storage) !Cost {
    var cost: Cost = .{};
    storage.connection.init(.server);
    const octets = client_octets(storage);
    @memcpy(storage.input[0..octets.len], octets);
    try drive(storage, storage.input[0..octets.len], &cost);
    const written = try storage.connection.write_response(&storage.output, 1, 200, &.{}, true);
    cost.write_calls += 1;
    cost.octets_out += @intCast(written);
    return cost;
}

/// What one request and its response cost at a cleartext client.
pub fn measure_client_cleartext(storage: *Storage) !Cost {
    var cost: Cost = .{};
    storage.connection.init(.client);
    const sent = try storage.connection.write_request(&storage.output, .{
        .method = "GET",
        .scheme = "https",
        .path = "/",
        .authority = "example.com",
    }, &.{}, true);
    cost.write_calls += 1;
    cost.octets_out += @intCast(sent.written);
    const octets = server_octets(storage);
    @memcpy(storage.input[0..octets.len], octets);
    try drive(storage, storage.input[0..octets.len], &cost);
    return cost;
}

/// What one request and its response cost at a server running over the null provider. The peer's
/// octets arrive as one record, which is the cheapest shape and the one the number is for.
pub fn measure_server_tls(storage: *Storage) !Cost {
    var cost: Cost = .{};
    storage.provider = .{};
    storage.connection.init(.server);
    try h2.connection_tls.attach(&storage.connection, storage.provider.provider());
    const octets = client_octets(storage);
    var record: [constants.cost_check_buffer_len]u8 = undefined;
    const record_len = try sim.null_provider.write_application_record(&record, octets);
    var plaintext: [constants.cost_check_buffer_len]u8 = undefined;
    const opened = try h2.connection_tls.decrypt(&storage.connection, record[0..record_len], &plaintext, 0);
    cost.provider_calls += 1;
    @memcpy(storage.input[0..opened.plaintext_len], plaintext[0..opened.plaintext_len]);
    try drive(storage, storage.input[0..opened.plaintext_len], &cost);
    const written = try storage.connection.write_response(&storage.output, 1, 200, &.{}, true);
    cost.write_calls += 1;
    cost.octets_out += @intCast(written);
    // The response leaves as one record, which is one more crossing of the vtable.
    _ = try h2.connection_tls.encrypt(&storage.connection, storage.output[0..written], &record, 0);
    cost.provider_calls += 1;
    return cost;
}

var check_storage: Storage = .zeroed;

test "the cost of one request at a cleartext server is what the tree says it is" {
    const measured = try measure_server_cleartext(&check_storage);
    try std.testing.expectEqual(server_cleartext, measured);
}

test "the cost of one request at a cleartext client is what the tree says it is" {
    const measured = try measure_client_cleartext(&check_storage);
    try std.testing.expectEqual(client_cleartext, measured);
}

test "the cost of one request at a server over TLS is what the tree says it is" {
    sim.NullProvider.install();
    const measured = try measure_server_tls(&check_storage);
    try std.testing.expectEqual(server_tls, measured);
}
