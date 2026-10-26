//! The tests of one worker of the test-only server (`server_worker.zig`), in cleartext. They call
//! `handle` with events they make and never arm a socket, so no operation is submitted and no
//! loop runs: a peer that leaves, a deadline, a slot that serves a new socket while its last one
//! still sends, a send that makes room, the echo of two sockets, and a read of events that stops
//! at its bound.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");
const server_mode = @import("server_mode.zig");
const server_socket = @import("server_socket.zig");
const server_worker = @import("server_worker.zig");

const testing = std.testing;
const Worker = server_worker.Worker;
const Kind = server_socket.Kind;
const handle = server_worker.handle;
const workers = &server_worker.workers;

/// The descriptor of the tests' sockets, which nothing reads. Test-only.
const test_descriptor: u32 = 0;
const get = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
const get_close = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
/// What every request gets. Test-only.
const response = "HTTP/1.1 200 OK\r\ncontent-type: " ++ constants.response_content_type ++
    "\r\ncontent-length: " ++ constants.response_content_length ++ "\r\n\r\n" ++ constants.response_body;
const response_closing = "HTTP/1.1 200 OK\r\ncontent-type: " ++ constants.response_content_type ++
    "\r\ncontent-length: " ++ constants.response_content_length ++ "\r\nConnection: close\r\n\r\n" ++ constants.response_body;

/// The final event of an operation of `kind` on the socket at `index` that succeeded with `count`.
/// Test-only.
fn event_of(index: usize, kind: Kind, count: u32) rotor.Event {
    return rotor.Event.success(server_socket.user_data(index, kind), count);
}

/// Starts worker 0 in the mode `server_mode` holds, with no socket, and returns it. Test-only.
fn fresh_worker() !*Worker {
    try server_worker.start(0);
    return &workers[0];
}

/// Hands the worker an accepted socket at `now_ns`, and returns the entry it took. Test-only.
fn accept(worker: *Worker, now_ns: u64) usize {
    const index = server_worker.free_socket(worker).?;
    handle(worker, &.{rotor.Event.success(server_worker.accept_user_data, test_descriptor)}, null, now_ns);
    assert(worker.sockets[index].live);
    return index;
}

/// Hands the socket at `index` `octets` as what its receive read. Test-only.
fn deliver(worker: *Worker, index: usize, octets: []const u8, now_ns: u64) void {
    @memcpy(worker.sockets[index].received[0..octets.len], octets);
    handle(worker, &.{event_of(index, .receive, @intCast(octets.len))}, null, now_ns);
}

/// What the socket at `index` holds to send. Test-only.
fn staged(worker: *Worker, index: usize) []const u8 {
    return worker.sockets[index].output[0..worker.sockets[index].output_len];
}

test "with port 0, every worker's listener has the port the kernel chose for the first" {
    const count = 3;
    const bound = try server_worker.bind_listeners(0, count);
    defer for (workers[0..count]) |*worker| rotor.sync.close_now(worker.listener);
    try testing.expect(bound != 0);
    for (workers[0..count]) |*worker| {
        try testing.expectEqual(bound, (try rotor.sync.local_address(worker.listener)).port);
    }
}

test "a peer that closes first ends its connection, and its socket and its slot are free again" {
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    const connection = worker.session.entries[index].handle;
    try testing.expect(worker.session.entries[index].attached);
    try testing.expect(worker.session.endpoint.live[connection.slot]);
    // The turn that accepted the socket arms it, with its first receive.
    try testing.expect(worker.touched.isSet(index));
    // A receive of no octets is the peer closing its side: the endpoint hears
    // `transport_closed`, reports the connection's `ended`, and frees its slot.
    handle(worker, &.{event_of(index, .receive, 0)}, null, constants.tick_ns);
    try testing.expect(worker.sockets[index].failed);
    try testing.expect(!worker.session.entries[index].attached);
    try testing.expect(!worker.session.endpoint.live[connection.slot]);
    try testing.expectEqual(null, worker.session.entry_of[connection.slot]);
    // The socket is the worker's until Rotor's close of it, its last operation.
    try testing.expect(worker.sockets[index].live);
    handle(worker, &.{event_of(index, .close, 0)}, null, constants.tick_ns);
    try testing.expect(!worker.sockets[index].live);
    try testing.expectEqual(index, server_worker.free_socket(worker).?);
}

test "decision 110: a silent connection is closed once its deadline is handed to the endpoint" {
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    const deadline_ns = worker.session.deadline_ns().?;
    // Before the deadline the endpoint is not handed the instant, and nothing changes.
    handle(worker, &.{}, deadline_ns, deadline_ns - 1);
    try testing.expectEqual(0, worker.session.now_ns);
    try testing.expect(!worker.sockets[index].closing);
    handle(worker, &.{}, deadline_ns, deadline_ns);
    try testing.expect(worker.sockets[index].closing);
    try testing.expect(!worker.session.entries[index].attached);
    try testing.expectEqual(0, worker.sockets[index].output_len);
}

test "the tick waits until the endpoint's deadline, and not at all while work is left" {
    const worker = try fresh_worker();
    const far_ns = rotor.constants.wait_ns_max + constants.tick_ns;
    try testing.expectEqual(rotor.constants.wait_ns_max, server_worker.wait_ns(worker, null, 0));
    try testing.expectEqual(rotor.constants.wait_ns_max, server_worker.wait_ns(worker, far_ns, 0));
    try testing.expectEqual(constants.tick_ns, server_worker.wait_ns(worker, far_ns, rotor.constants.wait_ns_max));
    // A deadline that has passed is handed over at once.
    try testing.expectEqual(0, server_worker.wait_ns(worker, constants.tick_ns, far_ns));
    // An entry that waits for a step keeps the tick from waiting.
    worker.session.mark(0);
    try testing.expectEqual(0, server_worker.wait_ns(worker, null, 0));
    try testing.expectEqual(@as(?usize, 0), worker.session.next_pending());
    try testing.expectEqual(rotor.constants.wait_ns_max, server_worker.wait_ns(worker, null, 0));
}

test "with every socket taken, a slot serves a new socket while its last one still sends" {
    const worker = try fresh_worker();
    for (0..constants.connections_per_worker_max) |_| _ = accept(worker, 0);
    try testing.expectEqual(null, server_worker.free_socket(worker));
    // The first socket's connection ends with its response, which the socket has not sent: no
    // send's event arrived. Its slot is free, and the socket is not.
    const first = worker.session.entries[0].handle;
    deliver(worker, 0, get_close, constants.tick_ns);
    try testing.expect(worker.sockets[0].closing and worker.sockets[0].live);
    try testing.expect(!worker.session.endpoint.live[first.slot]);
    try testing.expectEqualStrings(response_closing, staged(worker, 0));
    // Another socket's peer leaves, and Rotor closes it: one socket is free, and the endpoint
    // hands out the slot freed first, the first socket's.
    const other: usize = 5;
    handle(worker, &.{ event_of(other, .receive, 0), event_of(other, .close, 0) }, null, constants.tick_ns);
    try testing.expectEqual(other, accept(worker, constants.tick_ns));
    const second = worker.session.entries[other].handle;
    try testing.expectEqual(first.slot, second.slot);
    try testing.expect(first.generation != second.generation);
    // The new connection's events name the first socket's slot, and reach the new socket.
    deliver(worker, other, get, constants.tick_ns);
    try testing.expectEqualStrings(response, staged(worker, other));
    try testing.expectEqualStrings(response_closing, staged(worker, 0));
    // The first socket's send fails late. Its connection ended, so the endpoint hears nothing,
    // and the connection now in its slot stays.
    handle(worker, &.{rotor.Event.failure(server_socket.user_data(0, .send), .connection_reset)}, null, constants.tick_ns);
    try testing.expect(worker.sockets[0].failed);
    try testing.expect(worker.session.entries[other].attached);
    try testing.expect(worker.session.endpoint.live[second.slot]);
}

test "a socket whose send made room takes the rest its connection owes" {
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    const socket = &worker.sockets[index];
    // The socket holds octets it has not sent, with room for a few more.
    const room_len = 10;
    socket.output_len = socket.output.len - room_len;
    deliver(worker, index, get, constants.tick_ns);
    try testing.expectEqual(socket.output.len, socket.output_len);
    try testing.expectEqualStrings(response[0..room_len], socket.output[socket.output.len - room_len ..]);
    // The send takes every octet, so the buffer starts again, and the connection's send, which
    // filled its room, goes on.
    handle(worker, &.{event_of(index, .send, @intCast(socket.output.len))}, null, constants.tick_ns);
    try testing.expectEqualStrings(response[room_len..], staged(worker, index));
}

test "a socket with no room to send holds its input until a send makes room" {
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    const socket = &worker.sockets[index];
    // A peer that reads nothing: the socket's output is full, so its request is not read.
    socket.output_len = socket.output.len;
    deliver(worker, index, get, constants.tick_ns);
    try testing.expectEqual(get.len, socket.input_len);
    try testing.expectEqual(0, worker.session.entries[index].answers.owed_count);
    handle(worker, &.{event_of(index, .send, @intCast(socket.output.len))}, null, constants.tick_ns);
    try testing.expectEqual(0, socket.input_len);
    try testing.expectEqualStrings(response, staged(worker, index));
}

test "the echo mode returns each of a worker's sockets its own request" {
    // `--echo` with `--h11`, as the HTTP Garden runs the server.
    server_mode.echo_mode = true;
    server_mode.versions = .{ .h2 = false };
    defer server_mode.echo_mode = false;
    defer server_mode.versions = .{};
    const worker = try fresh_worker();
    const first = accept(worker, 0);
    const second = accept(worker, 0);
    // The first socket's head arrives, then the second's whole request, then the first's content.
    deliver(worker, first, "POST /one HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n", constants.tick_ns);
    try testing.expectEqual(0, staged(worker, first).len);
    deliver(worker, second, "GET /two HTTP/1.1\r\nHost: b\r\n\r\n", constants.tick_ns);
    // "/two", and no content.
    try testing.expect(std.mem.indexOf(u8, staged(worker, second), "\"uri\":\"L3R3bw==\"") != null);
    try testing.expect(std.mem.endsWith(u8, staged(worker, second), "\"body\":\"\"}"));
    deliver(worker, first, "abc", constants.tick_ns);
    // "/one", and "abc".
    try testing.expect(std.mem.indexOf(u8, staged(worker, first), "\"uri\":\"L29uZQ==\"") != null);
    try testing.expect(std.mem.endsWith(u8, staged(worker, first), "\"body\":\"YWJj\"}"));
}

test "steps that stop at their bound are taken again until the response is whole" {
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    // One event a loop: no step ends in one pass, and the worker steps the entry again.
    worker.session.events_max = 1;
    deliver(worker, index, get_close, constants.tick_ns);
    try testing.expect(worker.session.settled());
    try testing.expectEqualStrings(response_closing, staged(worker, index));
    try testing.expect(worker.sockets[index].closing);
    try testing.expect(!worker.session.entries[index].attached);
}

test "a read of the endpoint's events that stops at its bound goes on in the next turn" {
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    deliver(worker, index, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n", constants.tick_ns);
    // One event a read. The peer leaves, which owes two events: its request's `cancelled` and its
    // connection's `ended`. Its socket failed, so no step of its entry reads the endpoint's
    // events: the worker does, in this turn and the next, with no deadline due.
    worker.session.events_max = 1;
    handle(worker, &.{event_of(index, .receive, 0)}, null, constants.tick_ns);
    try testing.expect(!worker.session.settled());
    try testing.expectEqual(0, server_worker.wait_ns(worker, null, constants.tick_ns));
    handle(worker, &.{}, null, constants.tick_ns);
    try testing.expect(worker.session.settled());
    try testing.expect(!worker.session.entries[index].attached);
}

test "a socket Rotor has closed keeps its entry until its connection has ended" {
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    // What a read of the endpoint's events that stopped at its bound leaves: the socket's last
    // event arrived, and its connection's `ended` has not been read.
    handle(worker, &.{event_of(index, .close, 0)}, null, constants.tick_ns);
    try testing.expect(worker.sockets[index].live);
    try testing.expect(worker.session.entries[index].attached);
    // The endpoint reports the end, and the entry is free for the next socket.
    worker.session.peer_closed(index, constants.tick_ns);
    handle(worker, &.{}, null, constants.tick_ns);
    try testing.expect(!worker.sockets[index].live);
    try testing.expectEqual(index, accept(worker, constants.tick_ns));
}

test "design §8 step 13f: the --routes mode answers through the worker's router" {
    server_mode.routes_mode = true;
    defer server_mode.routes_mode = false;
    const worker = try fresh_worker();
    const index = accept(worker, 0);
    deliver(worker, index, "GET /users/colibri/repos HTTP/1.1\r\nHost: a\r\n\r\n", constants.tick_ns);
    try testing.expect(std.mem.endsWith(u8, staged(worker, index), "\r\n\r\nok\n"));
}

test "design §8 step 13f: an accepted socket sends at once, with Nagle's algorithm off" {
    const descriptor = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
    try testing.expect(descriptor >= 0);
    defer _ = std.c.close(descriptor);
    // The worker's accept takes the socket, as it takes each socket its listener accepts.
    const worker = try fresh_worker();
    handle(worker, &.{rotor.Event.success(server_worker.accept_user_data, @intCast(descriptor))}, null, constants.tick_ns);
    var enabled: c_int = 0;
    var enabled_len: std.c.socklen_t = @sizeOf(c_int);
    try testing.expectEqual(0, std.c.getsockopt(descriptor, std.c.IPPROTO.TCP, std.c.TCP.NODELAY, &enabled, &enabled_len));
    try testing.expect(enabled != 0);
}
