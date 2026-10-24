//! The client's pool to one origin (decision 100, design §8 step 17d): it carries the caller's
//! exchanges over the QUIC and TCP connections it chooses between, and tells the caller which
//! transport to open, to which address and port. spec/tla/client_exchanges models the choice
//! (decision 105).
//!
//! The caller passes what DNS knows as values and never a name to resolve: the server's addresses,
//! and an HTTPS record's `alpn` and `port` (RFC 9460 §7.1, §7.2). QUIC goes first when h3 is known,
//! or when the configuration says to try it (RFC 9114 §3.1), and TCP opens when QUIC fails or the
//! fallback delay passes. The first connection whose handshake completes takes the exchanges, and
//! the other closes. A TCP response's Alt-Svc teaches the pool h3 for its next connection (RFC
//! 7838 §3). An exchange that a connection taking no new exchange refused unprocessed moves to
//! another connection once (RFC 9113 §8.7, RFC 9114 §4.1.1). An idempotent request whose
//! connection closed before any of its response arrived moves too (RFC 9110 §9.2.2, decision 124),
//! and both moves count against one budget, `moves_max`.
//!
//! The caller opens a transport when an `open` event says to, starts its connection with
//! `start_quic` or `start_tcp`, and closes it when a `close` event says to, dropping the octets it
//! still holds of what the socket read. It passes what each transport reads to `receive`, and
//! writes what `send_datagram` and `send_stream` return. It loops over `receive` as it does for one
//! connection: until nothing is consumed and no event comes.
//! After each send, each event and each `on_instant` it reads again, with the TCP octets it still
//! holds, or with `.none` when it holds none: an h11 connection reads a held octet only once the
//! response before it ends. colibri makes no system call and reads no clock: time is a value the
//! caller passes (non-negotiable 3).
//!
//! The caller gives one configuration with one TLS value, and `init` builds from it the TLS
//! configuration of each transport the pool offers, with the ALPN list `versions` gives
//! (decision 120). A caller that offers h3 also places the receive pool each QUIC connection holds
//! the server's octets in, one at a time (decision 61), and sizes it to the longest response it
//! expects: `ReceivePool(capacity)`. The pool stays in place after `init`: the TLS
//! configurations it built point into it.
//!
//! A pool's functions are the calls a program makes, and `phase`, which the simulator's trace
//! reads. Their bodies are in `pool_calls.zig`, and the steps the pool takes on its own are
//! in `pool_events.zig`. The module's root exports neither file (design §8 step 17f).
const std = @import("std");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const choice = @import("pool_choice.zig");
const pool_config = @import("pool_config.zig");
const pool_calls = @import("pool_calls.zig");
const pool_state = @import("pool_state.zig");
const assert = std.debug.assert;

pub const Transport = choice.Transport;
pub const Phase = choice.Phase;
pub const RequestId = event.RequestId;
pub const Request = event.Request;
pub const Response = event.Response;
pub const Protocol = event.Protocol;
pub const Finished = event.Finished;
/// What `ConnectionPool.request` returns: what `check_request` refuses, and `Full`.
pub const RequestError = connection_module.CheckError || error{
    /// Every entry of the pool holds an exchange, until one's `finished` event is reported or
    /// the caller cancels one.
    Full,
};
pub const Config = pool_config.Config;
pub const StartError = pool_config.StartError;
pub const ReceiveStorage = quic_connection.ReceiveStorage;
pub const Address = quic.PeerAddress;
pub const Sent = quic_connection.Sent;

/// What DNS knows of the origin, which the caller looked up itself (decision 100).
pub const Destination = struct {
    /// The server's addresses, each with port 0, in the order the caller wants them tried.
    addresses: []const Address,
    /// The origin's port: 443 for "https" unless the URI names another (RFC 9110 §4.2.2).
    port: u16,
    /// An HTTPS record's values (RFC 9460 §9), or null when DNS had none.
    https_record: ?HttpsRecord = null,
    /// An h3 alternative an earlier pool learned from Alt-Svc, which the caller kept, or null.
    alternative: ?Alternative = null,
};

/// What an HTTPS record says of the endpoint (RFC 9460 §7.1, §7.2).
pub const HttpsRecord = struct {
    /// Whether the record's ALPN set holds "h3" (RFC 9460 §7.1.2).
    h3: bool,
    /// The record's "port", or null when it names none and the origin's applies (RFC 9460 §7.2).
    port: ?u16 = null,
};

/// An h3 endpoint on the origin's host that Alt-Svc named (RFC 7838 §3), and the instant on the
/// caller's clock until which it is fresh (§3.1).
pub const Alternative = struct {
    port: u16,
    fresh_until_ns: u64,
};

/// A connection of a pool, by its slot and the generation of the slot (decision 125), as
/// `server.ConnectionHandle` names one of an endpoint (decision 119). The TCP slots come first,
/// and the QUIC connection has the slot after them. A slot holds a new connection after the
/// `close` of the one before, with the next generation, so a handle names nothing once its
/// connection's `close` went out, and a call with it changes nothing.
pub const ConnectionHandle = packed struct(u64) {
    slot: u32,
    generation: u32,
};

/// A transport the caller opens: a UDP flow for QUIC, a TCP connection for TCP.
pub const Open = struct {
    /// The connection the transport carries, which each later call and event about it names.
    connection: ConnectionHandle,
    transport: Transport,
    /// One of `Destination.addresses`, with only its port set to the port the pool chose for the
    /// transport.
    to: Address,
};

/// The connection that takes the exchanges, and the version it speaks.
pub const Connected = struct {
    connection: ConnectionHandle,
    protocol: Protocol,
};

pub const Event = union(enum) {
    /// Open this transport, then start its connection with `start_quic` or `start_tcp`.
    open: Open,
    /// The TCP connection owes octets: the program calls `send_stream` for it (decision 125), as a
    /// server's program does for its endpoint (decision 119). The event comes once for each debt.
    /// A call of `send_stream` that leaves room in its output ends the debt, and the next debt
    /// gives the next event.
    send: ConnectionHandle,
    /// Close the transport of this connection: the connection is over, and the pool reads and
    /// writes nothing more on it. The program drops the octets it read from the socket and still
    /// holds: they are that connection's, and the next connection must not get them.
    close: ConnectionHandle,
    /// The connection that takes the exchanges, and its version. The event comes only for a
    /// connection that takes the exchanges. A connection that failed, or that takes no new
    /// exchange, in the call that completed its handshake carries nothing, and no event names it.
    connected: Connected,
    /// The connection's server issued a resumption ticket, which `take_ticket` hands over.
    ticket: ConnectionHandle,
    /// An exchange ended, and the caller may reuse the memory of its request and its response.
    finished: Finished,
    /// The pool was shut down, every exchange has finished, and every transport closed.
    closed,
};

/// A datagram the UDP flow read, with its ECN codepoint and the address it came from.
pub const Datagram = struct {
    bytes: []u8,
    ecn: quic.connection_receive.Datagram.Ecn = .not_ect,
    from: Address = .{},
};

/// Bytes the TCP socket of a connection read.
pub const StreamBytes = struct {
    connection: ConnectionHandle,
    bytes: []u8,
};

/// What the caller read, from the transport that read it.
pub const Input = union(enum) {
    none,
    datagram: Datagram,
    stream: StreamBytes,
};

/// What one `receive` call took and reported.
pub const ReceiveResult = struct {
    consumed: usize,
    event: ?Event,
};

pub const Stage = pool_state.Stage;
pub const Entry = pool_state.Entry;
pub const Link = pool_state.Link;

/// What a pool holds, fixed at build time (decision 124): whether it holds a QUIC connection. A
/// pool with no QUIC holds no QUIC connection and no QUIC TLS configuration, and speaks h11 and
/// h2 over TCP alone.
pub const Capacity = struct {
    quic: bool = true,
};

pub const Counts = pool_state.Counts;
pub const Layout = pool_state.Layout;
/// The alignment of the memory a pool's `init` takes. Each pool type names it `memory_alignment`.
pub const pool_memory_alignment = pool_state.memory_alignment;

/// A pool of the default capacity, which tries QUIC first and TCP after (decision 120).
pub const ConnectionPool = ConnectionPoolOf(.{});

/// A pool that holds the connections `capacity` names (decision 124). A pool with no QUIC
/// holds no QUIC state, and its code holds no step on a QUIC connection. Its `init` refuses
/// `versions` that allow h3, so it never asks for QUIC, and a call of its `start_quic` does not
/// compile. The body of each call is in `pool_calls.zig`.
pub fn ConnectionPoolOf(comptime capacity: Capacity) type {
    return struct {
        const Self = @This();
        /// The capacity, which `pool_calls.zig` and `pool_events.zig` read at build time.
        comptime capacity: Capacity = capacity,
        config: *const Config,
        values: Destination,
        /// The transports the configuration offers (decision 120): TCP while `versions` allows
        /// h11 or h2, and QUIC for h3 over TLS with a receive pool given.
        offered: pool_config.Offered,
        /// What `init` built from `config`, each written only when its transport is offered: the
        /// TLS configuration of TCP's connections, when the pool runs over TLS, and of QUIC's,
        /// and the configuration each connection borrows. QUIC's holds the address the current
        /// one sends to.
        tcp_tls: tls.record.ClientConfig,
        quic_tls: QuicField(capacity, tls.quic.ClientConfig),
        tcp_config: connection_module.Config,
        quic_config: QuicField(capacity, quic_connection.Config),
        quic: QuicField(capacity, quic_connection.QuicConnection),
        /// The counts of the configuration `init` took, and the parts of the caller's memory that
        /// hold the TCP connections, the link of each TCP slot and the table of exchanges (decision
        /// 125).
        counts: Counts,
        tcp: []connection_module.Connection,
        tcp_links: []Link,
        entries: []Entry,
        /// The QUIC slot's link, which a pool with no QUIC never opens.
        quic_link: Link,
        /// The index in `Destination.addresses` the next connection of each transport goes to. The
        /// TCP slots share theirs, so a new slot starts where the others are.
        quic_address_index: usize,
        tcp_address_index: usize,
        /// The id the next exchange gets.
        next_id: RequestId,
        /// Whether the fallback delay passed during QUIC's handshake, as
        /// spec/tla/client_exchanges names it. Each link says whether this attempt opened it.
        fallback: bool,
        /// The instant the fallback delay passes, once QUIC's connection started.
        fallback_at_ns: ?u64,
        /// The caller shut the pool down, and the `closed` event went out.
        shut: bool,
        closed_reported: bool,
        /// The receive pool of each QUIC connection, which the caller placed, or null when it
        /// gave none.
        receive_pool: QuicField(capacity, ?ReceiveStorage),

        /// The alignment of the memory `init` takes (decision 35 as amended).
        pub const memory_alignment = pool_memory_alignment;

        /// The bytes of memory `init` takes for the counts of a `Config` (decisions 125 and 126):
        /// `memory_bytes(.{ .tcp_connections = 4, .requests = 16 })`, with `Config`'s defaults for
        /// a count left out. The function is pure, so a program calls it at comptime to size a
        /// static array, or at run time.
        pub fn memory_bytes(counts: Counts) usize {
            return Layout.of(counts).len;
        }

        /// The most `receive` calls in a row that report an event and take no byte, for a pool
        /// of `counts` (decision 124 as amended by decision 125). The next call with the same
        /// input reports no event. The bound holds while the program does only this between the
        /// calls:
        /// - it starts the transport an `open` names, or calls `transport_closed` in place of the
        ///   start when it cannot open the transport;
        /// - it closes the socket a `close` names, and takes the ticket a `ticket` names;
        /// - it calls `shutdown`.
        /// A call that takes octets, a `transport_closed` after the start, and any other call of
        /// the program, start a new count.
        pub fn receive_events_without_input_max(counts: Counts) usize {
            return pool_state.events_without_input_max(counts, capacity.quic);
        }

        /// Prepares a pool with nothing opened, and builds the TLS configurations of the
        /// transports it offers, so the pool stays in place from here on. `memory` holds exactly
        /// `memory_bytes` of `config`'s counts, and the pool keeps its TCP connections and its table
        /// of exchanges there until the program stops using the pool (decision 35 as amended).
        /// `receive_pool` is the receive pool its QUIC connections use in turn, or null for a
        /// pool that opens no QUIC. A pool with no QUIC takes null. `error.NoVersion` says the
        /// configuration offers neither transport, `error.VersionUnavailable` that it allows h3
        /// on a pool with no QUIC, and the other errors that the TLS value names more than a TLS
        /// configuration holds. A program may call `init` again on a pool with no open transport
        /// and no exchange, for example with new addresses. The ids then count from 1 again, and
        /// the handles count again too, so the program keeps no id and no handle from before.
        pub fn init(pool: *Self, memory: []align(memory_alignment) u8, config: *const Config, destination: Destination, receive_pool: ?ReceiveStorage) StartError!void {
            return pool_calls.init(pool, memory, config, destination, receive_pool);
        }

        /// Gives the pool new values, for example the addresses of a later DNS answer, while
        /// exchanges run (decision 125). Each connection that opens after the call goes to
        /// `values.addresses`, from the first, and each open connection keeps its exchanges. The
        /// port stays the origin's. The pool keeps the h3 alternative it knows unless
        /// `values.alternative` names one. The pool reads `values.addresses` until the next
        /// `set_destination` or `init`.
        pub fn set_destination(pool: *Self, values: Destination) void {
            pool_calls.set_destination(pool, values);
        }

        /// Takes the request `message`, which goes out on the first connection open to take it,
        /// and the `response` it gets, and returns the exchange's id. The caller keeps both in
        /// place, and each slice they name, until the exchange's `finished` event or until
        /// `cancel` returns (decision 124). The caller makes no request after `shutdown`.
        pub fn request(pool: *Self, message: *const Request, response: *Response) RequestError!RequestId {
            return pool_calls.request(pool, message, response);
        }

        /// Ends exchange `id`, and reports nothing for it. The memory of its request and its
        /// response is the caller's again.
        pub fn cancel(pool: *Self, id: RequestId) void {
            pool_calls.cancel(pool, id);
        }

        /// Takes no new exchange, and ends every connection once the exchanges it holds have
        /// finished.
        pub fn shutdown(pool: *Self) void {
            pool.shut = true;
        }

        /// Reports what the pool owes, then passes `input` to the connection of the transport
        /// that read it, and reports what that changed.
        pub fn receive(pool: *Self, input: Input, now_ns: u64) ReceiveResult {
            return pool_calls.receive(pool, input, now_ns);
        }

        /// The next datagram the QUIC connection owes, written into `output`, or null for none.
        pub fn send_datagram(pool: *Self, output: []u8, now_ns: u64) ?Sent {
            return pool_calls.send_datagram(pool, output, now_ns);
        }

        /// The octets the TCP connection `connection` names owes, written into `output`: 0 for a
        /// handle that names no running connection.
        pub fn send_stream(pool: *Self, connection: ConnectionHandle, output: []u8, now_ns: u64) usize {
            return pool_calls.send_stream(pool, connection, output, now_ns);
        }

        /// The instant the pool next wants `on_instant` at: QUIC's next deadline, or the end of
        /// the fallback delay while the pool offers TCP. Null for none.
        pub fn deadline_ns(pool: *Self) ?u64 {
            return pool_calls.deadline_ns(pool);
        }

        /// Fires whichever deadlines `now_ns` has reached. The end of the fallback delay counts at
        /// the next `receive`.
        pub fn on_instant(pool: *Self, now_ns: u64) void {
            pool_calls.on_instant(pool, now_ns);
        }

        /// Starts the QUIC connection the `open` event asked for. The pool draws the
        /// connection's grease value and its two IDs from `random` (decision 120), then every draw
        /// its handshake makes comes from `random` too. `resumption` offers a ticket an earlier
        /// QUIC connection took. A call on a pool with no QUIC does not compile (decision 124).
        pub fn start_quic(pool: *Self, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) StartError!void {
            return pool_calls.start_quic(pool, random, now_seconds, now_ns, resumption);
        }

        /// Starts the TCP connection `connection`, which an `open` event asked for, as
        /// `start_quic` does QUIC's.
        pub fn start_tcp(pool: *Self, connection: ConnectionHandle, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
            return pool_calls.start_tcp(pool, connection, random, now_seconds, resumption);
        }

        /// The transport of `connection` closed on its own: the peer closed it, or it failed.
        /// Every exchange the connection held ends, as the connection's own `transport_closed`
        /// rules. A program may also close a transport itself at any time, and then calls this. A
        /// handle whose `close` went out names nothing, and the call changes nothing.
        pub fn transport_closed(pool: *Self, connection: ConnectionHandle) void {
            pool_calls.transport_closed(pool, connection);
        }

        /// The resumption ticket the `ticket` event announced for `connection`, which the call
        /// hands over and clears.
        pub fn take_ticket(pool: *Self, connection: ConnectionHandle) ?tls.Ticket {
            return pool_calls.take_ticket(pool, connection);
        }

        /// The h3 alternative the pool knows of, from the values or a TCP response's Alt-Svc,
        /// which a caller keeps for a later pool (RFC 7838 §2.2).
        pub fn alternative(pool: *const Self) ?Alternative {
            return pool.values.alternative;
        }

        /// Where the connection of `slot` stands, as spec/tla/client_exchanges's `phase` names it:
        /// the TCP slots count from 0, and the QUIC slot is the one after them (decision 125). A
        /// program reads the events and never this. The simulator's client trace run reads it
        /// (decision 105), and its TCP trace run decides by it whether its one connection takes a
        /// request.
        pub fn phase(pool: *const Self, slot: u32) Phase {
            return pool_calls.phase(pool, slot);
        }
    };
}

/// The type of a field that holds QUIC's state: `Type` in a pool that holds QUIC, and void in
/// one with no QUIC (decision 124).
fn QuicField(comptime capacity: Capacity, comptime Type: type) type {
    return if (capacity.quic) Type else void;
}

test "design §8 step 17f: the pool's public names are the calls a program makes, and phase" {
    // Decision 125: step 22.3 adds `memory_alignment`, `memory_bytes` and
    // `receive_events_without_input_max`, which size a pool and bound a program's loop, and step
    // 22.7 adds `set_destination`, which a program calls after a later DNS answer.
    const public_names = @import("core").public_names;
    // Decision 124: a pool with no QUIC names the same calls, and its `start_quic` does not
    // compile.
    inline for (.{ ConnectionPool, ConnectionPoolOf(.{ .quic = false }) }) |Type| {
        try public_names.expect(Type, &.{
            "memory_alignment", "memory_bytes",    "receive_events_without_input_max",
            "init",             "set_destination", "request",
            "cancel",           "shutdown",        "receive",
            "send_datagram",    "send_stream",     "deadline_ns",
            "on_instant",       "start_quic",      "start_tcp",
            "transport_closed", "take_ticket",     "alternative",
            "phase",
        });
    }
}
