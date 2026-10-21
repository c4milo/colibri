//! What a pool holds of its own (decision 125): its table of exchanges, a link for each
//! connection slot, the counts set at run time, and where the memory `init` takes holds each of
//! them. Split out of `pool.zig` for length; the module's root exports `Options` alone.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const quic = @import("quic");

const RequestId = event.RequestId;
const Request = event.Request;
const Response = event.Response;
const Address = quic.PeerAddress;

/// Where an exchange is, at the pool.
pub const Stage = enum {
    free,
    /// The pool holds it until a connection with room takes it.
    waiting,
    /// A connection holds it, by `carried_id`.
    carried,
    /// It ended at the pool, refused, and its `finished` event is owed.
    ended,
};

pub const Entry = struct {
    stage: Stage = .free,
    id: RequestId = 0,
    /// The request the program placed, and its response (decision 124).
    request: *const Request = undefined,
    response: *Response = undefined,
    /// The slot of the connection that carries it (decision 125).
    carrier: u32 = 0,
    carried_id: RequestId = 0,
    /// Times it moved to another connection.
    moves: u8 = 0,
    /// The pool sent it again after a connection closed before any of its response arrived
    /// (decision 124), so a server may have processed it.
    resent: bool = false,
    /// It waits to go out again because its connection failed, and not because the server closed
    /// that connection in its last complete response, so h11 writes it alone (RFC 9112 §9.3.2).
    after_failure: bool = false,
};

/// One slot's connection, as the pool tracks it.
pub const Link = struct {
    state: State = .none,
    /// Connections this slot opened.
    opens: u64 = 0,
    /// The generation of the slot's current connection, which its handle carries, and the
    /// generation of the connection whose `close` is owed (decision 125).
    generation: u32 = 0,
    close_generation: u32 = 0,
    /// The slot opened in this attempt, as spec/tla/client_exchanges's `tried` names it. An
    /// attempt ends when an exchange leaves the wait, or when the pool gives up on every waiting
    /// one.
    tried: bool = false,
    /// A `send` event went out for the connection, and no `send_stream` ended its debt yet.
    send_outstanding: bool = false,
    /// A `send_stream` wrote nothing: what the connection holds waits for the peer or for room,
    /// so no `send` goes out until the connection reads octets or the program makes a call.
    send_blocked: bool = false,
    /// Where the current connection goes.
    to: Address = .{},
    /// The `open` event of the current connection is owed.
    open_owed: bool = false,
    /// The `close` event is owed: of the current connection once it is over, or of the one before
    /// it when the pass that closed that one opened this one. It goes out before the `open`.
    close_owed: bool = false,
    /// The connection reported `connected` and took exchanges when it did.
    won: bool = false,
    /// The client abandoned the connection before it was started.
    abandoned: bool = false,
    /// The connection reported `closed`.
    reported_closed: bool = false,
    /// The caller's transport closed on its own, so no `close` event is owed.
    gone: bool = false,

    pub const State = enum {
        none,
        /// The `open` event went out or is owed, and the connection is not started.
        opening,
        /// The connection's memory holds it.
        running,
        closed,
    };
};

/// What a pool holds, set at run time (decision 125, decision 35 as amended). `memory_bytes`
/// gives the octets the counts need, and `init` takes them from the caller.
pub const Options = struct {
    /// TCP connections the pool holds at most: from 1 to `constants.pool_tcp_connections_max`.
    tcp_connections: u16 = 1,
    /// Requests the pool holds at once, each until its `finished` event: from 1 to `constants.pool_requests_max`.
    requests: u16 = constants.requests_max,

    /// Whether each count is inside its limits. A count outside them is a programmer error.
    pub fn valid(options: Options) bool {
        if (options.tcp_connections == 0 or options.tcp_connections > constants.pool_tcp_connections_max) return false;
        return options.requests > 0 and options.requests <= constants.pool_requests_max;
    }
};

/// The alignment of the memory a pool's `init` takes: that of a TCP connection, of a link and of
/// an entry. Each pool type names it `memory_alignment`.
pub const memory_alignment: usize = @max(@alignOf(connection_module.Connection), @max(@alignOf(Link), @alignOf(Entry)));

/// Where a pool places what it counts in the memory `init` takes: its TCP connections first, then
/// a link for each, then its table of exchanges.
pub const Layout = struct {
    tcp_len: usize,
    links_offset: usize,
    entries_offset: usize,
    len: usize,

    pub fn of(options: Options) Layout {
        // Each part's size keeps the part after it aligned.
        comptime assert(@sizeOf(connection_module.Connection) % @alignOf(Link) == 0);
        comptime assert(@sizeOf(Link) % @alignOf(Entry) == 0);
        assert(options.valid());
        const tcp_count: usize = options.tcp_connections;
        const tcp_len = tcp_count * @sizeOf(connection_module.Connection);
        const entries_offset = tcp_len + tcp_count * @sizeOf(Link);
        const len = entries_offset + @as(usize, options.requests) * @sizeOf(Entry);
        assert(len > entries_offset and entries_offset > tcp_len);
        return .{ .tcp_len = tcp_len, .links_offset = tcp_len, .entries_offset = entries_offset, .len = len };
    }
};

/// The most `receive` calls in a row that report an event and take no octet, for a pool of
/// `options` that holds QUIC or not: one `finished` for each exchange, one `closed`, and
/// `constants.transport_events_max` for each transport.
pub fn events_without_input_max(options: Options, holds_quic: bool) usize {
    assert(options.valid());
    const transports = @as(usize, options.tcp_connections) + @intFromBool(holds_quic);
    return @as(usize, options.requests) + transports * constants.transport_events_max + 1;
}
