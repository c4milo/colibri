//! The tests of the channel to one origin (`channel.zig`, `channel_events.zig`) over TCP: the
//! channel asks for the transport, carries each exchange on the connection it opened, and ends once
//! shut down, against h2's server side in the same process.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const channel_module = @import("channel.zig");
const connection_module = @import("../connection/connection.zig");
const event = @import("../event.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Channel = channel_module.Channel;
const HttpExchange = event.HttpExchange;
const Event = channel_module.Event;

/// The channel the tests drive, its configuration and the events it reported, outside any stack
/// frame. Test-only.
var channel: Channel align(@alignOf(Channel)) = undefined;
var tcp_config: connection_module.Config align(@alignOf(connection_module.Config)) = undefined;
var config: channel_module.Config align(@alignOf(channel_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;

const ok: u16 = 200;
const https_port: u16 = 443;
const fallback_delay_ns: u64 = 250_000_000;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const other_octet: u8 = 0x7e;
const other_host: [ipv4_len]u8 = @splat(other_octet);
const addresses = [_]channel_module.Address{channel_module.Address.of(&loopback, 0)};
const two_addresses = [_]channel_module.Address{ channel_module.Address.of(&loopback, 0), channel_module.Address.of(&other_host, 0) };
/// Whether `collect` starts a TCP connection an `open` event asks for.
var starts: bool = true;
const unstarted_octet: u8 = 0x01;
/// Rounds of moving octets a test takes at most.
const rounds: usize = 8;

/// A channel with no QUIC configured, whose TCP connections speak h2 in cleartext.
fn start_tcp_only() void {
    start_at(&addresses);
}

fn start_at(to: []const channel_module.Address) void {
    tcp_config = .{ .authority = support.authority, .versions = support.only(.h2) };
    config = .{ .tcp = &tcp_config, .fallback_delay_ns = fallback_delay_ns };
    // Every octet 1, so each flag of a connection the channel never started reads as set, and a
    // read of one shows.
    @memset(std.mem.asBytes(&channel), unstarted_octet);
    channel.init(&config, .{ .addresses = to, .port = https_port }, null);
    starts = true;
    support.peer_h2.init(.server);
    support.to_peer_len = 0;
    support.to_client_len = 0;
    support.peer_events_len = 0;
    events_len = 0;
}

/// Reports every event the channel owes, taking what the peer sent, starts a transport an `open`
/// event asks for, and keeps the events.
fn collect() !void {
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.buffer_len + support.events_max) |_| {
        const input: channel_module.Input = if (support.to_client_len > 0) .{ .stream = support.to_client[0..support.to_client_len] } else .none;
        const received = channel.receive(input, support.now_ns);
        std.mem.copyForwards(u8, &support.to_client, support.to_client[received.consumed..support.to_client_len]);
        support.to_client_len -= received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open and starts) try channel.start_tcp(support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

/// Moves octets both ways for a few rounds.
fn pump() !void {
    for (0..rounds) |_| {
        support.to_peer_len += channel.send_stream(support.to_peer[support.to_peer_len..], support.now_ns);
        try support.peer_h2_read();
        try collect();
    }
}

/// The first event of `tag` the channel reported, or null.
fn find(tag: std.meta.Tag(Event)) ?Event {
    const index = index_of(tag) orelse return null;
    return events[index];
}

fn index_of(tag: std.meta.Tag(Event)) ?usize {
    for (events[0..events_len], 0..) |reported, index| {
        if (reported == tag) return index;
    }
    return null;
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

fn get(body: []u8) HttpExchange {
    return .{ .method = "GET", .path = "/", .body = body };
}

test "decision 100: with no QUIC configured, the channel opens TCP and carries an exchange on it" {
    start_tcp_only();
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    const id = try channel.request(&exchange);
    try collect();
    // RFC 9110 §4.2.2: with no HTTPS record, the connection goes to the origin's port.
    const opened = find(.open).?.open;
    try testing.expectEqual(channel_module.Transport.tcp, opened.transport);
    try testing.expectEqual(https_port, opened.to.port);
    try pump();
    try testing.expectEqual(event.Protocol.h2, find(.connected).?.connected);
    try support.peer_h2_answer(1, ok, &.{}, "hello");
    try collect();
    const finished = find(.finished).?.finished;
    try testing.expectEqual(id, finished.id);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings("hello", exchange.content_received());
    // The channel is not closed until its caller shuts it down.
    try testing.expectEqual(null, find(.closed));
}

test "decision 100: a shut-down channel drains its connection, asks for its close, and reports closed" {
    start_tcp_only();
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try channel.request(&exchange);
    try pump();
    channel.shutdown();
    try support.peer_h2_answer(1, ok, &.{}, "hello");
    try pump();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(channel_module.Transport.tcp, find(.close).?.close);
    // The channel closes once, after its transports did.
    try testing.expectEqual(1, count(.closed));
    try testing.expect(index_of(.close).? < index_of(.closed).?);
    try testing.expectEqual(channel_module.Phase.closed, channel.phase(.tcp));
    // It ended after its last exchange, not on a failure.
    try testing.expect(!channel.tcp.failed);
}

test "RFC 9113 §8.7: a transport the caller closed moves the exchange it had not written to a new connection" {
    start_tcp_only();
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    // The exchange waits in the connection, unwritten, when the caller's transport closes.
    channel.transport_closed(.tcp);
    try collect();
    try testing.expectEqual(null, find(.finished));
    try testing.expectEqual(2, count(.open));
    try pump();
    try support.peer_h2_answer(1, ok, &.{}, "hello");
    try collect();
    try testing.expectEqual(.response, exchange.outcome);
}

test "RFC 9113 §8.7: a transport the caller closed ends its written exchange closed, and asks for no close" {
    start_tcp_only();
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try pump();
    channel.transport_closed(.tcp);
    try collect();
    try testing.expectEqual(.closed, exchange.outcome);
    try testing.expectEqual(&exchange, find(.finished).?.finished.exchange);
    try testing.expectEqual(null, find(.close));
    try testing.expectEqual(channel_module.Phase.closed, channel.phase(.tcp));
}

test "a channel holds exchanges_max exchanges at once, and refuses one more" {
    start_tcp_only();
    var exchanges: [constants.exchanges_max + 1]HttpExchange = @splat(get(&bodies[0]));
    for (exchanges[0..constants.exchanges_max]) |*exchange| _ = try channel.request(exchange);
    try testing.expectError(error.Full, channel.request(&exchanges[constants.exchanges_max]));
}

test "what a transport with no running connection read is dropped" {
    start_tcp_only();
    var octets: [ipv4_len]u8 = @splat(host_octet);
    const datagram = channel.receive(.{ .datagram = .{ .octets = &octets } }, support.now_ns);
    try testing.expectEqual(octets.len, datagram.consumed);
    try testing.expectEqual(null, datagram.event);
    const stream = channel.receive(.{ .stream = &octets }, support.now_ns);
    try testing.expectEqual(octets.len, stream.consumed);
    try testing.expectEqual(null, stream.event);
}

test "a transport that failed before its handshake completed tries the next address next time" {
    start_at(&two_addresses);
    starts = false;
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    try testing.expect(find(.open).?.open.to.same_host(&two_addresses[0]));
    // The caller's connection failed, so no transport is left, and the exchange ends refused.
    channel.transport_closed(.tcp);
    try collect();
    try testing.expectEqual(.refused, exchange.outcome);
    events_len = 0;
    _ = try channel.request(&exchange);
    try collect();
    try testing.expect(find(.open).?.open.to.same_host(&two_addresses[1]));
}
