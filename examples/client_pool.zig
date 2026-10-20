//! Example: a client sends exchanges to one origin through a pool of several TCP connections over
//! h11, and gives the pool a later DNS answer while exchanges run.
//!
//! A pool holds up to `tcp_connections` TCP connections, which `client.Options` counts, in memory
//! the program supplies: `memory_bytes(options)` gives its size (decision 125). h11 carries one
//! exchange at a time on a connection, so the pool opens another connection when an exchange
//! waits and no open one has room for it. This pool speaks h11 alone, in cleartext, and holds no
//! QUIC state (decision 124).
//!
//! Each connection the pool opens is a socket of its own. Each `open` names the connection, by its
//! slot and its generation, and each later event about it names it too: `send`, when it owes
//! octets, and `close`, when it is over. The program keeps one socket for each slot.
//!
//! The run goes in this order:
//! 1. The program requests two GETs. The pool says `open` twice, to the address of the first DNS
//!    answer, and each connection takes one exchange.
//! 2. Both exchanges end. The two connections stay open for the next exchanges.
//! 3. A later DNS answer names another address, and the program calls `set_values`.
//! 4. The program requests four more GETs. The two open connections take two of them, and the
//!    pool opens two more connections, to the new address.
//! 5. Every exchange ends, and the program calls `shutdown`. The pool says `close` of each
//!    connection, and then `closed`.
//!
//! The server is in `client_pool_peer.zig`: one endpoint with four TCP slots. The link of
//! `link_streams.zig` stands where a program's sockets would be, one stream for each socket, and
//! `tls_program.zig` holds what any program that links `tls` defines once.
//!
//! The program checks each greeting octet for octet, two opens to each address, four closes and
//! the `closed` event. Anything else exits with an error, which is how `zig build examples` and CI
//! know the example still works.
//!
//! Run it with `zig build example-client_pool`, or every example with `zig build examples`.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const program = @import("tls_program.zig");
const peer = @import("client_pool_peer.zig");
const link_module = @import("link_streams.zig");

const StreamsLink = link_module.StreamsLink;
const greeting = peer.greeting;

/// Turns of the client and the server before the example gives up.
const turns_max = 64;

/// The longest either side sleeps when nothing waits, in nanoseconds: 100 ms.
const wait_ns_max: u64 = 100_000_000;

/// Calls of `send_stream` for one `send`, at most: one request fits in one output.
const sends_per_debt_max = 4;

/// The origin, which the requests name, and its port: 80 for "http" (RFC 9110 §4.2.1).
const origin = "localhost";
const server_port = 80;

/// The address of the first DNS answer, and the address of a later one. The link stands where
/// the sockets would be, so no socket connects to either, and the program records where each
/// `open` goes.
const first_host = [_]u8{ 192, 0, 2, 1 };
const second_host = [_]u8{ 192, 0, 2, 2 };
const first_addresses = [_]client.Address{.of(&first_host, 0)};
const second_addresses = [_]client.Address{.of(&second_host, 0)};

/// Exchanges of the first round, and of the second.
const first_round = 2;
const second_round = 4;
const exchanges_count = first_round + second_round;

pub const Error = error{
    /// The pool was not closed within `turns_max` turns.
    ExchangeUnfinished,
    /// What arrived is not what was sent.
    ExchangeWrong,
};

// The pool speaks h11 over TCP alone, so it holds no QUIC state (decision 124). Its options count
// four TCP connections, and `memory_bytes` sizes the memory it holds them in (decision 125).
const Pool = client.PoolOf(.{ .quic = false });
const options: client.Options = .{ .tcp_connections = link_module.streams_max };
var pool: Pool align(@alignOf(Pool)) = undefined;
var pool_memory: [Pool.memory_bytes(options)]u8 align(Pool.memory_alignment) = undefined;
var client_config: client.Config align(@alignOf(client.Config)) = .{
    .authority = origin,
    .versions = .{ .h2 = false, .h3 = false },
};

// The link holds every queue, so it lives outside the stack.
var link: StreamsLink align(@alignOf(StreamsLink)) = undefined;
/// What `send_stream` writes, which the link then sends.
var output: [client.constants.stream_output_len_min]u8 = undefined;

/// Calls of `receive` for one read of a socket, at most. Each call takes one octet or more of the
/// link's queue, or reports an event and takes no octet, or ends the loop.
const receive_calls_max = (link_module.queue_len_max + 1) * (Pool.receive_events_without_input_max(options) + 1);

/// The connection of each slot's socket, or null when the slot holds none. A slot's socket is
/// the link's stream of the same index.
var sockets: [link_module.streams_max]?client.ConnectionHandle align(@alignOf(client.ConnectionHandle)) = @splat(null);

const get: client.Request = .{ .method = "GET", .path = "/greeting" };
var bodies: [exchanges_count][greeting.len]u8 = undefined;
var responses: [exchanges_count]client.Response align(@alignOf(client.Response)) = undefined;
var requested: u32 = 0;

/// What the client saw: exchanges that ended, opens to each address, closes, and whether the
/// shut-down pool is over.
var finished: u32 = 0;
var opens_first: u32 = 0;
var opens_second: u32 = 0;
var closes: u32 = 0;
var pool_closed: bool = false;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    try peer.init(&link);
    // The pool takes what the first DNS answer knows: the server's address and its port.
    const known: client.Values = .{ .addresses = &first_addresses, .port = server_port };
    try pool.init(&pool_memory, &client_config, known, options, null);
    try request(first_round);
    for (0..turns_max) |_| {
        try client_turn();
        try peer.turn();
        if (pool_closed and peer.over(opens_first + opens_second)) return check();
        // No octet waits for either side. A program sleeps here until a socket has octets or a
        // deadline passes, whichever comes first.
        if (!link.pending()) try link.wait(.client, sleep_ns());
    }
    return error.ExchangeUnfinished;
}

/// Hands the pool `count` more GETs, each with its own response.
fn request(count: u32) !void {
    for (0..count) |_| {
        responses[requested] = .{ .body = &bodies[requested] };
        _ = try pool.request(&get, &responses[requested]);
        requested += 1;
    }
}

/// One turn of the client: pass the pool what each socket read, and then what it owes with no
/// octets.
fn client_turn() !void {
    try link.receive(.client);
    const now_ns = link.now_ns(.client);
    for (0..link_module.streams_max) |slot| try drain(@intCast(slot), now_ns);
}

/// Passes the pool the octets the socket of `slot` read, until it consumes nothing and reports
/// nothing. With no socket in the slot it passes `.none`, which reports what the pool owes.
fn drain(slot: u32, now_ns: u64) !void {
    const socket = sockets[slot];
    const input = link.queue(slot, .client);
    var consumed: usize = 0;
    for (0..receive_calls_max) |_| {
        const held = input[consumed..];
        // An event may close this socket, or open another in its slot: its octets then go to no
        // connection.
        const current = socket != null and std.meta.eql(sockets[slot], socket);
        const read: client.Input = if (current and held.len > 0) .{ .stream = .{ .connection = socket.?, .octets = held } } else .none;
        const received = pool.receive(read, now_ns);
        consumed += received.consumed;
        const event = received.event orelse {
            if (received.consumed == 0) break;
            continue;
        };
        try report(event, now_ns);
    }
    // A socket closed during the read dropped its octets with it.
    if (socket != null and std.meta.eql(sockets[slot], socket)) link.consume(slot, .client, consumed);
}

/// Acts on one event of the pool. Each exchange ends in one `finished` event.
fn report(event: client.Event, now_ns: u64) !void {
    switch (event) {
        .open => |open| try open_socket(open),
        // The connection owes octets, which the program writes into its socket.
        .send => |connection| try send_owed(connection, now_ns),
        // The connection is over: the program closes its socket.
        .close => |connection| close_socket(connection),
        .connected => |connected| if (connected.protocol != .h11) return error.ExchangeWrong,
        .finished => |ended| try on_finished(ended),
        // A pool in cleartext gets no ticket.
        .ticket => return error.ExchangeWrong,
        // The shut-down pool is over: every exchange ended and every connection closed.
        .closed => pool_closed = true,
    }
}

/// Connects a socket for the connection an `open` event named, to `open.to`, in the slot the
/// connection's handle names, and starts the connection on it.
fn open_socket(open: client.Open) !void {
    const slot = open.connection.slot;
    if (sockets[slot] != null) return error.ExchangeWrong;
    const host = open.to.octets[0..open.to.len];
    if (std.mem.eql(u8, host, &first_host)) opens_first += 1;
    if (std.mem.eql(u8, host, &second_host)) opens_second += 1;
    std.debug.print("client: open slot {d} to {any}\n", .{ slot, host });
    sockets[slot] = open.connection;
    // The link stands where the socket would be: the server's listener accepts the socket the
    // program connects.
    try peer.accept(slot);
    pool.start_tcp(open.connection, program.random(), 0, null) catch return error.ExchangeWrong;
}

/// Writes what `connection` owes into its socket, until a call leaves room in `output`: that
/// call wrote all the connection owed (decision 125).
fn send_owed(connection: client.ConnectionHandle, now_ns: u64) !void {
    if (!std.meta.eql(sockets[connection.slot], connection)) return error.ExchangeWrong;
    for (0..sends_per_debt_max) |_| {
        const written = pool.send_stream(connection, &output, now_ns);
        try link.send(connection.slot, .client, output[0..written]);
        if (written < output.len) return;
    }
    return error.ExchangeWrong;
}

/// Closes the socket of `connection`. The octets it held are dropped with it, and the server
/// hears the close.
fn close_socket(connection: client.ConnectionHandle) void {
    const slot = connection.slot;
    assert(std.meta.eql(sockets[slot], connection));
    link.close(slot);
    peer.closed(slot);
    sockets[slot] = null;
    closes += 1;
}

/// Counts one ended exchange. The first round's end brings a later DNS answer and the second
/// round, and the second round's end the shutdown.
fn on_finished(ended: client.Finished) !void {
    if (ended.response.outcome != .response or ended.response.status != 200) return error.ExchangeWrong;
    if (!std.mem.eql(u8, ended.response.content_received(), greeting)) return error.ExchangeWrong;
    finished += 1;
    if (finished == first_round) {
        // A later DNS answer names another address. Each connection that opens from now on goes
        // to it, and each open connection keeps its exchanges.
        pool.set_values(.{ .addresses = &second_addresses, .port = server_port });
        try request(second_round);
    }
    if (finished == exchanges_count) pool.shutdown();
}

/// How long both sides may sleep: until the server's next deadline, and never longer than
/// `wait_ns_max`. A pool with TCP alone has no deadline of its own.
fn sleep_ns() u64 {
    var wait_ns: u64 = wait_ns_max;
    if (peer.deadline_ns()) |deadline_ns| wait_ns = @min(wait_ns, deadline_ns -| link.now_ns(.server));
    // A wait of 0 would poll, so the shortest sleep is one nanosecond.
    return @max(wait_ns, 1);
}

/// The client saw every greeting, two opens to each address and a close of each connection, and
/// the server saw what it expects.
fn check() Error!void {
    const opened = opens_first == first_round and opens_second == second_round - first_round;
    const opens = opens_first + opens_second;
    if (finished == exchanges_count and opened and closes == opens and peer.check(exchanges_count, opens)) {
        std.debug.print("client_pool: every octet arrived as sent\n", .{});
        return;
    }
    std.debug.print("client_pool: finished {d}, opens {d} and {d}, closes {d}\n", .{
        finished, opens_first, opens_second, closes,
    });
    return error.ExchangeWrong;
}
