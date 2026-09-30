//! What the client's tests share: the connection they drive, the exchanges it carries, and a peer
//! in the same process that answers it: h2's or h11's server side in cleartext, and over TLS a
//! `tls.record.Server` over the test identity of `src/testing/testdata/`. The session sources are
//! SplitMix64 from a seed, so every run draws the same octets. Test-only.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const http = @import("http");
const h2 = @import("h2");
const tls = @import("tls");
const testdata = @import("testdata");
const connection_module = @import("connection.zig");
const event = @import("../event.zig");

pub const Connection = connection_module.Connection;
pub const Config = connection_module.Config;
pub const HttpExchange = event.HttpExchange;
pub const Event = event.Event;
pub const Field = event.Field;

pub const leaf = testdata.leaf;
pub const root = testdata.root;
pub const root_name = testdata.root_name;
pub const root_spki = testdata.root_spki;
pub const private_key: *const [tls.constants.p256_private_key_len]u8 = testdata.private_key;
pub const public_key: *const [tls.constants.p256_public_key_len]u8 = testdata.public_key;

/// The instant the tests judge the chain at. Any instant inside the identity's validity works,
/// from `testdata.not_before_seconds` to `testdata.not_after_seconds`.
pub const now_seconds: u64 = testdata.now_seconds;
/// The CPU answer the tests pass: the build target's, since a test runs where it was built.
pub const aes_instructions: tls.AesInstructions = if (testdata.aes_instructions_present) .present else .absent;
/// The instant each call passes, in nanoseconds. The tests hold it still.
pub const now_ns: u64 = 1_000_000;
pub const authority = "localhost";

pub const chain = [_][]const u8{ leaf, root };
pub const anchors = [_]tls.Anchor{.{ .subject = root_name, .spki = root_spki }};
pub const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_key_octet);
pub const ticket_key: [tls.constants.server_key_len]u8 = @splat(ticket_key_octet);
const cookie_key_octet: u8 = 0x07;
const ticket_key_octet: u8 = 0x0b;

/// The ALPN lists: the client's preference, h2 first (decision 88), and each a server selects from.
pub const protocols_both = [_][]const u8{ "h2", "http/1.1" };
pub const protocols_h11 = [_][]const u8{"http/1.1"};
pub const protocols_h2 = [_][]const u8{"h2"};

/// Room for everything one test's connection sends, and for what its peer sends.
pub const buffer_len: usize = 262_144;
/// Events one test collects at most, and rounds of moving octets it takes at most.
pub const events_max: usize = 64;
const rounds_max: usize = 64;

/// The connection the tests drive, its configuration, and the octets in flight each way, outside
/// any stack frame.
pub var connection: Connection align(@alignOf(Connection)) = undefined;
pub var config: Config align(@alignOf(Config)) = .{ .authority = authority };
pub var to_peer: [buffer_len]u8 = undefined;
pub var to_peer_len: usize = 0;
pub var to_client: [buffer_len]u8 = undefined;
pub var to_client_len: usize = 0;
/// The events the last `drive` collected, in order.
pub var events: [events_max]Event align(@alignOf(Event)) = undefined;
pub var events_len: usize = 0;

/// The peers: h2's and h11's server side, and the TLS server under either.
pub var peer_h2: h2.Connection align(@alignOf(h2.Connection)) = undefined;
pub var peer_h11: h11.connection.Connection align(@alignOf(h11.connection.Connection)) = undefined;

/// A cleartext connection speaking `protocol`, and a peer of the same protocol, with nothing read
/// or written.
pub fn start_cleartext(protocol: connection_module.Protocol) !void {
    try start_configured(.{ .authority = authority, .cleartext = protocol });
}

/// The decoder pool the coding tests give a connection, and the codings it offers, gzip first
/// (decision 101).
pub const Pool = h11.coding.Pool(pool_decoders);
pub var pool: Pool align(@alignOf(Pool)) = .{};
pub const codings = [_]http.content_coding.Coding{ .gzip, .deflate };
const pool_decoders: usize = 2;

/// As `start_cleartext`, with the client offering `codings` and decoding with `pool`, every
/// decoder free.
pub fn start_coding(protocol: connection_module.Protocol) !void {
    try start_offering(protocol, &codings);
}

/// As `start_coding`, with the client offering `offered`.
pub fn start_offering(protocol: connection_module.Protocol, offered: []const http.content_coding.Coding) !void {
    const storage = pool.storage();
    storage.reset(.none());
    try start_configured(.{ .authority = authority, .cleartext = protocol, .codings = offered, .decoders = storage });
}

fn start_configured(value: Config) !void {
    config = value;
    const protocol = value.cleartext;
    try connection.init(&config, stream.random(), 0, null);
    to_peer_len = 0;
    to_client_len = 0;
    events_len = 0;
    switch (protocol) {
        .h2 => peer_h2.init(.server),
        .h11 => peer_h11.init(.server, .{}),
        .h3 => unreachable,
    }
}

/// Sends what the client owes to the peer's buffer.
pub fn client_send() void {
    to_peer_len += connection.send(to_peer[to_peer_len..], now_ns);
}

/// Reads what the peer sent until the client consumes nothing and reports nothing, and keeps the
/// events.
pub fn client_receive() !void {
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..buffer_len + events_max) |_| {
        const received = connection.receive(to_client[0..to_client_len], now_ns);
        std.mem.copyForwards(u8, &to_client, to_client[received.consumed..to_client_len]);
        to_client_len -= received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
    }
    return error.TestUnexpectedResult;
}

/// The first event of `tag` the client reported, or null.
pub fn find(tag: std.meta.Tag(Event)) ?Event {
    for (events[0..events_len]) |reported| {
        if (reported == tag) return reported;
    }
    return null;
}

/// How many events of `tag` the client reported.
pub fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

/// The h2 peer's events, which `peer_h2_read` fills.
pub var peer_events: [events_max]h2.Event align(@alignOf(h2.Event)) = undefined;
pub var peer_events_len: usize = 0;

/// The h2 peer reads every whole frame the client sent, keeps its events, and writes what it owes.
pub fn peer_h2_read() !void {
    var consumed: usize = 0;
    for (0..rounds_max * rounds_max) |_| {
        const received = try peer_h2.receive(to_peer[consumed..to_peer_len], now_ns);
        if (received.consumed == 0) {
            if (!peer_h2.has_pending()) break;
            peer_h2_owe();
            continue;
        }
        consumed += received.consumed;
        if (received.event) |peer_event| {
            if (peer_events_len == peer_events.len) return error.TestUnexpectedResult;
            peer_events[peer_events_len] = peer_event;
            peer_events_len += 1;
        }
    }
    std.mem.copyForwards(u8, &to_peer, to_peer[consumed..to_peer_len]);
    to_peer_len -= consumed;
    peer_h2_owe();
}

/// Writes what the h2 peer owes on its own, such as its SETTINGS and acknowledgments.
pub fn peer_h2_owe() void {
    to_client_len += peer_h2.write_pending(to_client[to_client_len..], now_ns);
}

/// Rounds `pump_h2` moves octets both ways: enough for a preface, its acknowledgment, a request
/// and its answer, and the window updates of a large content.
const pump_rounds: usize = 8;

/// Moves octets both ways a few rounds, over an h2 peer that answers nothing by itself.
pub fn pump_h2() !void {
    for (0..pump_rounds) |_| {
        client_send();
        try peer_h2_read();
        try client_receive();
    }
}

/// The h2 peer answers stream `stream_id` with `status`, `fields`, `content` and END_STREAM.
pub fn peer_h2_answer(stream_id: u32, status: u16, fields: []const h2.hpack.Field, content: []const u8) !void {
    const head_end = content.len == 0;
    to_client_len += try peer_h2.write_response(to_client[to_client_len..], stream_id, status, fields, head_end);
    if (head_end) return;
    const sent = try peer_h2.write_data(to_client[to_client_len..], stream_id, content, true);
    assert(sent.consumed == content.len);
    to_client_len += sent.written;
}

/// The h11 peer's requests, which `peer_h11_read` counts.
pub var peer_requests: usize = 0;

/// The h11 peer reads every request head and body the client sent.
pub fn peer_h11_read() !void {
    var consumed: usize = 0;
    for (0..to_peer_len + 1) |_| {
        const received = try peer_h11.receive(to_peer[consumed..to_peer_len], &.{});
        consumed += received.consumed;
        const peer_event = received.event orelse break;
        if (peer_event == .request) peer_requests += 1;
    }
    std.mem.copyForwards(u8, &to_peer, to_peer[consumed..to_peer_len]);
    to_peer_len -= consumed;
}

/// The h11 peer answers the request it read with `status`, `fields` and `content`.
pub fn peer_h11_answer(status: u16, fields: []const Field, content: []const u8) !void {
    to_client_len += try peer_h11.write_response(to_client[to_client_len..], status, "", fields);
    if (peer_h11.writer.open()) {
        if (content.len > 0) to_client_len += try peer_h11.write_body(to_client[to_client_len..], content);
        to_client_len += try peer_h11.write_end(to_client[to_client_len..], &.{});
    }
}

/// The source the sessions of the tests draw from.
pub var stream: Stream align(@alignOf(Stream)) = .{ .state = seed };

/// The seed the tests use.
pub const seed: u64 = 0x636c_6965_6e74_2121;

pub const Stream = struct {
    state: u64,

    /// The source a session draws from, which points at this stream: the stream outlives the
    /// session.
    pub fn random(self: *Stream) tls.Random {
        return tls.Random.init(self, fill);
    }

    fn fill(self: *Stream, buffer: []u8) void {
        for (buffer) |*octet| {
            self.state +%= increment;
            var mixed = self.state;
            mixed = (mixed ^ (mixed >> shift_first)) *% multiplier_first;
            mixed = (mixed ^ (mixed >> shift_second)) *% multiplier_second;
            octet.* = @truncate(mixed ^ (mixed >> shift_third));
        }
    }
};

/// SplitMix64's increment, multipliers and shifts.
const increment: u64 = 0x9e37_79b9_7f4a_7c15;
const multiplier_first: u64 = 0xbf58_476d_1ce4_e5b9;
const multiplier_second: u64 = 0x94d0_49bb_1331_11eb;
const shift_first: u6 = 30;
const shift_second: u6 = 27;
const shift_third: u6 = 31;
