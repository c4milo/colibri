//! The tests of a pool of several TCP slots (decision 125): a second h11 connection opens for an
//! exchange that no open connection has room for, a waiting exchange goes to the connection that
//! frees, a slot that fails is not opened again in the same wait, and no second connection opens
//! beside an h2 one (RFC 9113 §9.1). `set_values` gives the connections that open after it new
//! addresses. The responses are octets the tests write themselves.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const pool_module = @import("pool.zig");
const protocols_module = @import("../protocols.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = pool_module.Event;
const Pool = pool_module.PoolOf(.{ .quic = false });
const ConnectionHandle = pool_module.ConnectionHandle;

/// A pool of two TCP slots, and room for the exchanges of each test.
const slots_count: u16 = 2;
const requests_count: u16 = 4;
const two_slots: pool_module.Options = .{ .tcp_connections = slots_count, .requests = requests_count };

/// The pool the tests drive, its memory, its configuration and the events it reported, outside
/// any stack frame. Test-only.
var pool: Pool align(@alignOf(Pool)) = undefined;
var pool_memory: [Pool.memory_bytes(two_slots)]u8 align(Pool.memory_alignment) = undefined;
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 3;
const body_len: usize = 64;
/// Where a test reads what a connection wrote. Test-only.
var wire: [support.buffer_len]u8 = undefined;
/// Whether `collect` starts each connection an `open` asks for.
var starts: bool = true;

const http_port: u16 = 80;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};
/// Two more hosts, which `set_values` gives the pool, and two h3 alternatives. Test-only.
const second_octet: u8 = 0x0a;
const third_octet: u8 = 0x0b;
const second_host: [ipv4_len]u8 = @splat(second_octet);
const third_host: [ipv4_len]u8 = @splat(third_octet);
const new_addresses = [_]pool_module.Address{ pool_module.Address.of(&second_host, 0), pool_module.Address.of(&third_host, 0) };
const learned_port: u16 = 8443;
const named_port: u16 = 9443;
const learned: pool_module.Alternative = .{ .port = learned_port, .fresh_until_ns = support.now_ns + 1 };
const named: pool_module.Alternative = .{ .port = named_port, .fresh_until_ns = support.now_ns + 1 };
const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
/// A response after which the server closes the connection (RFC 9112 §9.6). Test-only.
const closing_response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi";

/// A pool of `two_slots` in cleartext, which speaks the versions `versions` allows.
fn start(versions: protocols_module.Protocols) !void {
    config = .{ .authority = support.authority, .protocols = versions };
    try pool.init(&pool_memory, &config, .{ .addresses = &addresses, .port = http_port }, two_slots, null);
    events_len = 0;
    starts = true;
}

/// Reports every event the pool owes with no octets, starts each connection an `open` asks for
/// while `starts`, and keeps the events.
fn collect() !void {
    // Bounded: each pass reports an event, and they are finite.
    for (0..support.events_max) |_| {
        const reported = pool.receive(.none, support.now_ns).event orelse return;
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open and starts) try pool.start_tcp(reported.open.connection, support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

/// Passes `octets` to the pool as what the socket of `connection` read, and keeps the events.
fn give(connection: ConnectionHandle, octets: []const u8) !void {
    var held: [support.buffer_len]u8 = undefined;
    @memcpy(held[0..octets.len], octets);
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or reports an event.
    for (0..octets.len + support.events_max) |_| {
        const rest = held[consumed..octets.len];
        const input: pool_module.Input = if (rest.len > 0) .{ .stream = .{ .connection = connection, .bytes = rest } } else .none;
        const received = pool.receive(input, support.now_ns);
        consumed += received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open and starts) try pool.start_tcp(reported.open.connection, support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

/// What `connection` writes now.
fn sent(connection: ConnectionHandle) []const u8 {
    return wire[0..pool.send_stream(connection, &wire, support.now_ns)];
}

/// The `n`th event of `tag` the pool reported, counted from 0, or null.
fn find(tag: std.meta.Tag(Event), n: usize) ?Event {
    var seen: usize = 0;
    for (events[0..events_len]) |reported| {
        if (reported != tag) continue;
        if (seen == n) return reported;
        seen += 1;
    }
    return null;
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

fn get(body: []u8, path: []const u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = path }, .response = .{ .body = body } };
}

test "decision 125: a second exchange opens a second h11 connection, once the first connected" {
    try start(.{ .h2 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    var second = get(&bodies[1], "/b");
    _ = try pool.request(&first.request, &first.response);
    _ = try pool.request(&second.request, &second.response);
    // Until TCP carries the exchanges, one TCP handshake runs at a time (RFC 9113 §9.1).
    starts = false;
    try collect();
    try testing.expectEqual(1, count(.open));
    const one = find(.open, 0).?.open.connection;
    starts = true;
    try pool.start_tcp(one, support.stream.random(), 0, null);
    try collect();
    // h11 in a pool of two slots takes one exchange at a time, so the second waits for a second
    // connection, in the other slot.
    try testing.expectEqual(2, count(.open));
    const two = find(.open, 1).?.open.connection;
    try testing.expect(one.slot != two.slot);
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /a HTTP/1.1"));
    try testing.expect(std.mem.startsWith(u8, sent(two), "GET /b HTTP/1.1"));
    try give(one, response);
    try give(two, response);
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expectEqual(.response, second.response.outcome);
}

test "decision 125: an exchange that waits for room goes to the connection that frees" {
    try start(.{ .h2 = false, .h3 = false });
    var exchanges = [_]Exchange{ get(&bodies[0], "/a"), get(&bodies[1], "/b"), get(&bodies[2], "/c") };
    for (&exchanges) |*exchange| _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    const one = find(.open, 0).?.open.connection;
    const two = find(.open, 1).?.open.connection;
    // Both slots hold a connection, so the third exchange waits, and nothing more opens.
    try testing.expectEqual(2, count(.open));
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /a HTTP/1.1"));
    try testing.expect(std.mem.startsWith(u8, sent(two), "GET /b HTTP/1.1"));
    try testing.expectEqual(.pending, exchanges[2].response.outcome);
    try give(one, response);
    try testing.expectEqual(.response, exchanges[0].response.outcome);
    // The first connection's room freed, and it takes the third exchange.
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /c HTTP/1.1"));
    try testing.expectEqual(2, count(.open));
}

test "decision 125: a slot whose connect failed opens again only after an exchange left the wait" {
    try start(.{ .h2 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    var second = get(&bodies[1], "/b");
    _ = try pool.request(&first.request, &first.response);
    _ = try pool.request(&second.request, &second.response);
    starts = false;
    try collect();
    const one = find(.open, 0).?.open.connection;
    try pool.start_tcp(one, support.stream.random(), 0, null);
    // The second slot's connect fails, and the attempt holds it tried.
    try collect();
    const failed = find(.open, 1).?.open.connection;
    pool.transport_closed(failed);
    try collect();
    try testing.expectEqual(2, count(.open));
    // Decision 125 ruling 5: while the first connection is open, the second exchange waits.
    try testing.expectEqual(.pending, second.response.outcome);
    _ = sent(one);
    try give(one, response);
    try testing.expectEqual(.response, first.response.outcome);
    // The second exchange left the wait on the first connection, which ends the attempt, so a
    // third exchange may open the failed slot again.
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /b HTTP/1.1"));
    var third = get(&bodies[2], "/c");
    _ = try pool.request(&third.request, &third.response);
    starts = true;
    try collect();
    try testing.expectEqual(3, count(.open));
    try testing.expectEqual(failed.slot, find(.open, 2).?.open.connection.slot);
}

test "decision 125: a waiting exchange goes to the connection a cancelled exchange freed" {
    try start(.{ .h2 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    var second = get(&bodies[1], "/b");
    const first_id = try pool.request(&first.request, &first.response);
    _ = try pool.request(&second.request, &second.response);
    starts = false;
    try collect();
    const one = find(.open, 0).?.open.connection;
    try pool.start_tcp(one, support.stream.random(), 0, null);
    try collect();
    pool.transport_closed(find(.open, 1).?.open.connection);
    try collect();
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /a HTTP/1.1"));
    // The connection reads the cancelled exchange's response and drops it, which reports no event
    // and frees its room.
    pool.cancel(first_id);
    try give(one, response);
    try testing.expectEqual(.pending, first.response.outcome);
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /b HTTP/1.1"));
    try give(one, response);
    try testing.expectEqual(.response, second.response.outcome);
}

/// Whether `open` goes to `host`, at the origin's port.
fn expect_to(open: pool_module.Open, host: []const u8) !void {
    try testing.expectEqualSlices(u8, host, open.to.octets[0..open.to.len]);
    try testing.expectEqual(http_port, open.to.port);
}

test "decision 125 ruling 8: a connection that opens after set_values goes to a new address" {
    try start(.{ .h2 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    var second = get(&bodies[1], "/b");
    _ = try pool.request(&first.request, &first.response);
    try collect();
    const one = find(.open, 0).?.open;
    try expect_to(one, &loopback);
    pool.set_values(.{ .addresses = &new_addresses, .port = http_port });
    _ = try pool.request(&second.request, &second.response);
    try collect();
    try expect_to(find(.open, 1).?.open, &second_host);
    // The open connection keeps its exchange.
    try testing.expect(std.mem.startsWith(u8, sent(one.connection), "GET /a HTTP/1.1"));
    try give(one.connection, response);
    try testing.expectEqual(.response, first.response.outcome);
}

test "decision 125 ruling 8: set_values restarts the address list at its first address" {
    try start(.{ .h2 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    _ = try pool.request(&first.request, &first.response);
    starts = false;
    try collect();
    // The connect fails, so the next connection would try the next address.
    pool.transport_closed(find(.open, 0).?.open.connection);
    pool.set_values(.{ .addresses = &new_addresses, .port = http_port });
    try collect();
    try expect_to(find(.open, 1).?.open, &second_host);
}

test "decision 125 ruling 8: a connect to an old address that fails after set_values skips no new one" {
    try start(.{ .h2 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    _ = try pool.request(&first.request, &first.response);
    starts = false;
    try collect();
    pool.set_values(.{ .addresses = &new_addresses, .port = http_port });
    pool.transport_closed(find(.open, 0).?.open.connection);
    try collect();
    try expect_to(find(.open, 1).?.open, &second_host);
}

test "decision 125 ruling 8: an open still owed when set_values comes goes to a new address" {
    try start(.{ .h2 = false, .h3 = false });
    var exchanges = [_]Exchange{ get(&bodies[0], "/a"), get(&bodies[1], "/b"), get(&bodies[2], "/c") };
    for (&exchanges) |*exchange| _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    const one = find(.open, 0).?.open.connection;
    _ = sent(one);
    // The first connection ends after its response, and its slot opens again for the third
    // exchange. The `close` goes out first, and the `open` is still owed after it.
    var held: [support.buffer_len]u8 = undefined;
    @memcpy(held[0..closing_response.len], closing_response);
    var consumed: usize = 0;
    for (0..closing_response.len + support.events_max) |_| {
        const rest = held[consumed..closing_response.len];
        const input: pool_module.Input = if (rest.len > 0) .{ .stream = .{ .connection = one, .bytes = rest } } else .none;
        const received = pool.receive(input, support.now_ns);
        consumed += received.consumed;
        const reported = received.event orelse continue;
        if (reported == .close) break;
    } else return error.TestUnexpectedResult;
    pool.set_values(.{ .addresses = &new_addresses, .port = http_port });
    try collect();
    try expect_to(find(.open, 2).?.open, &second_host);
}

/// Three hosts, a pool of three slots, and its memory. Test-only.
const three_slots: pool_module.Options = .{ .tcp_connections = slots_count + 1, .requests = requests_count };
const three_addresses = [_]pool_module.Address{ pool_module.Address.of(&loopback, 0), pool_module.Address.of(&second_host, 0), pool_module.Address.of(&third_host, 0) };
var three_memory: [Pool.memory_bytes(three_slots)]u8 align(Pool.memory_alignment) = undefined;

test "decision 125: two connections to one address that both fail skip no other address" {
    config = .{ .authority = support.authority, .protocols = .{ .h2 = false, .h3 = false } };
    try pool.init(&three_memory, &config, .{ .addresses = &three_addresses, .port = http_port }, three_slots, null);
    events_len = 0;
    var exchanges = [_]Exchange{ get(&bodies[0], "/a"), get(&bodies[1], "/b"), get(&bodies[2], "/c") };
    for (&exchanges) |*exchange| _ = try pool.request(&exchange.request, &exchange.response);
    starts = false;
    try collect();
    const one = find(.open, 0).?.open.connection;
    try pool.start_tcp(one, support.stream.random(), 0, null);
    // The first connection carries the first exchange, and two more open, both to the first
    // address. Both fail.
    try collect();
    try expect_to(find(.open, 1).?.open, &loopback);
    try expect_to(find(.open, 2).?.open, &loopback);
    pool.transport_closed(find(.open, 1).?.open.connection);
    pool.transport_closed(find(.open, 2).?.open.connection);
    try collect();
    // The first connection's exchange ends, and it takes the second. The third waits, and the
    // next connection goes to the second address.
    _ = sent(one);
    try give(one, response);
    try expect_to(find(.open, 3).?.open, &second_host);
}

test "decision 125 ruling 8: set_values keeps the h3 alternative unless the values name one" {
    config = .{ .authority = support.authority, .protocols = .{ .h2 = false, .h3 = false } };
    try pool.init(&pool_memory, &config, .{ .addresses = &addresses, .port = http_port, .alternative = learned }, two_slots, null);
    pool.set_values(.{ .addresses = &new_addresses, .port = http_port });
    try testing.expectEqual(learned, pool.alternative().?);
    pool.set_values(.{ .addresses = &new_addresses, .port = http_port, .alternative = named });
    try testing.expectEqual(named, pool.alternative().?);
}

test "decision 125: an exchange that moves gives a blocked connection its next send" {
    try start(.{ .h2 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    var second = get(&bodies[1], "/b");
    _ = try pool.request(&first.request, &first.response);
    _ = try pool.request(&second.request, &second.response);
    try collect();
    const one = find(.open, 0).?.open.connection;
    const two = find(.open, 1).?.open.connection;
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /a HTTP/1.1"));
    try testing.expect(std.mem.startsWith(u8, sent(two), "GET /b HTTP/1.1"));
    try give(two, response);
    // A call that writes nothing blocks the idle connection's next `send`.
    try testing.expectEqual(0, sent(two).len);
    const sends = count(.send);
    // RFC 9110 §9.2.2: the first connection fails before any of its response, so its GET moves to
    // the second, which then owes it.
    pool.transport_closed(one);
    try collect();
    try testing.expectEqual(sends + 1, count(.send));
    try testing.expect(std.mem.startsWith(u8, sent(two), "GET /a HTTP/1.1"));
}

test "decision 125: a shut-down pool keeps its connections while an exchange waits for one" {
    try start(.{ .h2 = false, .h3 = false });
    var exchanges = [_]Exchange{ get(&bodies[0], "/a"), get(&bodies[1], "/b"), get(&bodies[2], "/c") };
    for (&exchanges) |*exchange| _ = try pool.request(&exchange.request, &exchange.response);
    // The model's Drain: a shut-down pool drains a connection only once no exchange waits.
    pool.shutdown();
    try collect();
    const one = find(.open, 0).?.open.connection;
    const two = find(.open, 1).?.open.connection;
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /a HTTP/1.1"));
    try testing.expect(std.mem.startsWith(u8, sent(two), "GET /b HTTP/1.1"));
    try give(one, response);
    try testing.expect(std.mem.startsWith(u8, sent(one), "GET /c HTTP/1.1"));
    try give(two, response);
    try give(one, response);
    for (&exchanges) |*exchange| try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqual(2, count(.open));
}

test "RFC 9113 §9.1: a pool of two slots opens no second h2 connection" {
    try start(.{ .h11 = false, .h3 = false });
    var first = get(&bodies[0], "/a");
    var second = get(&bodies[1], "/b");
    _ = try pool.request(&first.request, &first.response);
    _ = try pool.request(&second.request, &second.response);
    try collect();
    try testing.expectEqual(1, count(.open));
    try testing.expectEqual(pool_module.Protocol.h2, find(.connected, 0).?.connected.protocol);
}
