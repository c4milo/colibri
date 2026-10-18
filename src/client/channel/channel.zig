//! The client's channel to one origin (decision 100, design §8 step 17d): it carries the caller's
//! exchanges over the QUIC and TCP connections it chooses between, and tells the caller which
//! transport to open, to which address and port. spec/tla/client_exchanges models the choice
//! (decision 105).
//!
//! The caller passes what DNS knows as values and never a name to resolve: the server's addresses,
//! and an HTTPS record's `alpn` and `port` (RFC 9460 §7.1, §7.2). QUIC goes first when h3 is known,
//! or when the configuration says to try it (RFC 9114 §3.1), and TCP opens when QUIC fails or the
//! fallback delay passes. The first connection whose handshake completes takes the exchanges, and
//! the other closes. A TCP response's Alt-Svc teaches the channel h3 for its next connection (RFC
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
//! configuration of each transport the channel offers, with the ALPN list `versions` gives
//! (decision 120). A caller that offers h3 also places the receive pool each QUIC connection holds
//! the server's octets in, one at a time (decision 61), and sizes it to the longest response it
//! expects: `ReceivePool(capacity)`. The channel stays in place after `init`: the TLS
//! configurations it built point into it.
//!
//! A channel's functions are the calls a program makes, and `phase`, which the simulator's trace
//! reads. Their bodies are in `channel_calls.zig`, and the steps the channel takes on its own are
//! in `channel_events.zig`. The module's root exports neither file (design §8 step 17f).
const std = @import("std");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const choice = @import("channel_choice.zig");
const channel_config = @import("channel_config.zig");
const channel_calls = @import("channel_calls.zig");

pub const Transport = choice.Transport;
pub const Phase = choice.Phase;
pub const Id = event.Id;
pub const Request = event.Request;
pub const Response = event.Response;
pub const Protocol = event.Protocol;
pub const Finished = event.Finished;
/// What `Channel.request` returns: what `check_request` refuses, and `Full`.
pub const RequestError = connection_module.CheckError || error{
    /// Every entry of the channel holds an exchange, until one's `finished` event is reported or
    /// the caller cancels one.
    Full,
};
pub const Config = channel_config.Config;
pub const StartError = channel_config.StartError;
pub const ReceiveStorage = quic_connection.ReceiveStorage;
pub const Address = quic.PeerAddress;
pub const Sent = quic_connection.Sent;

/// What DNS knows of the origin, which the caller looked up itself (decision 100).
pub const Values = struct {
    /// The server's addresses, each with port 0, in the order the caller wants them tried.
    addresses: []const Address,
    /// The origin's port: 443 for "https" unless the URI names another (RFC 9110 §4.2.2).
    port: u16,
    /// An HTTPS record's values (RFC 9460 §9), or null when DNS had none.
    https: ?Https = null,
    /// An h3 alternative an earlier channel learned from Alt-Svc, which the caller kept, or null.
    alternative: ?Alternative = null,
};

/// What an HTTPS record says of the endpoint (RFC 9460 §7.1, §7.2).
pub const Https = struct {
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

/// A transport the caller opens: a UDP flow for QUIC, a TCP connection for TCP.
pub const Open = struct {
    transport: Transport,
    /// One of `Values.addresses`, with only its port set to the port the channel chose for the
    /// transport.
    to: Address,
};

pub const Event = union(enum) {
    /// Open this transport, then start its connection with `start_quic` or `start_tcp`.
    open: Open,
    /// Close this transport: its connection is over, and the channel reads and writes nothing more
    /// on it. The program drops the octets it read from the socket and still holds: they are that
    /// connection's, and the next connection on the transport must not get them.
    close: Transport,
    /// The connection carrying the exchanges speaks `Protocol`. The event comes only for a
    /// connection that takes the exchanges. A connection that failed, or that takes no new
    /// exchange, in the call that completed its handshake carries nothing, and no event names it.
    connected: Protocol,
    /// A transport's server issued a resumption ticket, which `take_ticket` hands over.
    ticket: Transport,
    /// An exchange ended, and the caller may reuse the memory of its request and its response.
    finished: Finished,
    /// The channel was shut down, every exchange has finished, and every transport closed.
    closed,
};

/// A datagram the UDP flow read, with its ECN codepoint and the address it came from.
pub const Datagram = struct {
    octets: []u8,
    ecn: quic.connection_receive.Datagram.Ecn = .not_ect,
    from: Address = .{},
};

/// What the caller read, from the transport that read it.
pub const Input = union(enum) {
    none,
    datagram: Datagram,
    stream: []u8,
};

/// What one `receive` call took and reported.
pub const Received = struct {
    consumed: usize,
    event: ?Event,
};

/// Where an exchange is, at the channel.
pub const Stage = enum {
    free,
    /// The channel holds it until a connection is open to take it.
    waiting,
    /// A connection holds it, by `carried_id`.
    carried,
    /// It ended at the channel, refused, and its `finished` event is owed.
    ended,
};

pub const Entry = struct {
    stage: Stage = .free,
    id: Id = 0,
    /// The request the program placed, and its response (decision 124).
    request: *const Request = undefined,
    response: *Response = undefined,
    carrier: Transport = .quic,
    carried_id: Id = 0,
    /// Times it moved to another connection.
    moves: u8 = 0,
    /// The channel sent it again after a connection closed before any of its response arrived
    /// (decision 124), so a server may have processed it.
    resent: bool = false,
};

/// One transport's connection, as the channel tracks it.
pub const Link = struct {
    state: State = .none,
    /// Connections this transport opened.
    opens: u64 = 0,
    /// The index in `Values.addresses` the next connection goes to.
    address_index: usize = 0,
    /// Where the current connection goes.
    to: Address = .{},
    /// The `open` event of the current connection is owed.
    open_owed: bool = false,
    /// The `close` event is owed: of the current connection once it is over, or of the one before
    /// it when the pass that closed that one opened this one. It goes out before the `open`.
    close_owed: bool = false,
    /// The connection reported `connected` and took the exchanges when it did.
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

/// What a channel holds, fixed at build time (decision 124): whether it holds a QUIC connection. A
/// channel with no QUIC holds no QUIC connection and no QUIC TLS configuration, and speaks h11 and
/// h2 over TCP alone.
pub const Capacity = struct {
    quic: bool = true,
};

/// A channel of the default capacity, which tries QUIC first and TCP after (decision 120).
pub const Channel = ChannelOf(.{});

/// A channel that holds the connections `capacity` names (decision 124). A channel with no QUIC
/// holds no QUIC state, and its code holds no step on a QUIC connection. Its `init` refuses
/// `versions` that allow h3, so it never asks for QUIC, and a call of its `start_quic` does not
/// compile. The body of each call is in `channel_calls.zig`.
pub fn ChannelOf(comptime capacity: Capacity) type {
    return struct {
        const Self = @This();
        /// The capacity, which `channel_calls.zig` and `channel_events.zig` read at build time.
        comptime capacity: Capacity = capacity,
        config: *const Config,
        values: Values,
        /// The transports the configuration offers (decision 120): TCP while `versions` allows
        /// h11 or h2, and QUIC for h3 over TLS with a receive pool given.
        offered: channel_config.Offered,
        /// What `init` built from `config`, each written only when its transport is offered: the
        /// TLS configuration of TCP's connections, when the channel runs over TLS, and of QUIC's,
        /// and the configuration each connection borrows. QUIC's holds the address the current
        /// one sends to.
        tcp_tls: tls.record.ClientConfig,
        quic_tls: QuicField(capacity, tls.quic.ClientConfig),
        tcp_config: connection_module.Config,
        quic_config: QuicField(capacity, quic_connection.Config),
        quic: QuicField(capacity, quic_connection.QuicConnection),
        tcp: connection_module.Connection,
        links: std.EnumArray(Transport, Link),
        entries: [constants.exchanges_max]Entry,
        /// The id the next exchange gets.
        next_id: Id,
        /// The transports this attempt opened, and whether the fallback delay passed during
        /// QUIC's handshake, as spec/tla/client_exchanges names them.
        tried: std.EnumArray(Transport, bool),
        fallback: bool,
        /// The instant the fallback delay passes, once QUIC's connection started.
        fallback_at_ns: ?u64,
        /// The caller shut the channel down, and the `closed` event went out.
        shut: bool,
        closed_reported: bool,
        /// The receive pool of each QUIC connection, which the caller placed, or null when it
        /// gave none.
        receive_pool: QuicField(capacity, ?ReceiveStorage),

        /// Prepares a channel with nothing opened, and builds the TLS configurations of the
        /// transports it offers, so the channel stays in place from here on. `receive_pool` is
        /// the pool its QUIC connections use in turn, or null for a channel that opens no QUIC. A
        /// channel with no QUIC takes null. `error.NoVersion` says the configuration offers
        /// neither transport, `error.VersionUnavailable` that it allows h3 on a channel with no
        /// QUIC, and the other errors that the TLS value names more than a TLS configuration holds.
        /// A program may call `init` again on a channel with no open transport and no exchange,
        /// for example with new addresses. The ids then count from 1 again.
        pub fn init(channel: *Self, config: *const Config, values: Values, receive_pool: ?ReceiveStorage) StartError!void {
            return channel_calls.init(channel, config, values, receive_pool);
        }

        /// Takes the request `message`, which goes out on the first connection open to take it,
        /// and the `response` it gets, and returns the exchange's id. The caller keeps both in
        /// place, and each slice they name, until the exchange's `finished` event or until
        /// `cancel` returns (decision 124). The caller makes no request after `shutdown`.
        pub fn request(channel: *Self, message: *const Request, response: *Response) RequestError!Id {
            return channel_calls.request(channel, message, response);
        }

        /// Ends exchange `id`, and reports nothing for it. The memory of its request and its
        /// response is the caller's again.
        pub fn cancel(channel: *Self, id: Id) void {
            channel_calls.cancel(channel, id);
        }

        /// Takes no new exchange, and ends every connection once the exchanges it holds have
        /// finished.
        pub fn shutdown(channel: *Self) void {
            channel.shut = true;
        }

        /// Reports what the channel owes, then passes `input` to the connection of the transport
        /// that read it, and reports what that changed.
        pub fn receive(channel: *Self, input: Input, now_ns: u64) Received {
            return channel_calls.receive(channel, input, now_ns);
        }

        /// The next datagram the QUIC connection owes, written into `output`, or null for none.
        pub fn send_datagram(channel: *Self, output: []u8, now_ns: u64) ?Sent {
            return channel_calls.send_datagram(channel, output, now_ns);
        }

        /// The octets the TCP connection owes, written into `output`.
        pub fn send_stream(channel: *Self, output: []u8, now_ns: u64) usize {
            return channel_calls.send_stream(channel, output, now_ns);
        }

        /// The instant the channel next wants `on_instant` at: QUIC's next deadline, or the end of
        /// the fallback delay while the channel offers TCP. Null for none.
        pub fn deadline_ns(channel: *Self) ?u64 {
            return channel_calls.deadline_ns(channel);
        }

        /// Fires whichever deadlines `now_ns` has reached. The end of the fallback delay counts at
        /// the next `receive`.
        pub fn on_instant(channel: *Self, now_ns: u64) void {
            channel_calls.on_instant(channel, now_ns);
        }

        /// Starts the QUIC connection the `open` event asked for. The channel draws the
        /// connection's grease value and its two IDs from `random` (decision 120), then every draw
        /// its handshake makes comes from `random` too. `resumption` offers a ticket an earlier
        /// QUIC connection took. A call on a channel with no QUIC does not compile (decision 124).
        pub fn start_quic(channel: *Self, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) StartError!void {
            return channel_calls.start_quic(channel, random, now_seconds, now_ns, resumption);
        }

        /// Starts the TCP connection the `open` event asked for, as `start_quic` does QUIC's.
        pub fn start_tcp(channel: *Self, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
            return channel_calls.start_tcp(channel, random, now_seconds, resumption);
        }

        /// The caller's transport closed on its own: the peer closed it, or it failed. Every
        /// exchange its connection held ends, as the connection's own `transport_closed` rules. A
        /// program may also close a transport itself at any time, and then calls this.
        pub fn transport_closed(channel: *Self, transport: Transport) void {
            channel_calls.transport_closed(channel, transport);
        }

        /// The resumption ticket the `ticket` event announced for `transport`, which the call
        /// hands over and clears.
        pub fn take_ticket(channel: *Self, transport: Transport) ?tls.Ticket {
            return channel_calls.take_ticket(channel, transport);
        }

        /// The h3 alternative the channel knows of, from the values or a TCP response's Alt-Svc,
        /// which a caller keeps for a later channel (RFC 7838 §2.2).
        pub fn alternative(channel: *const Self) ?Alternative {
            return channel.values.alternative;
        }

        /// Where `transport`'s connection stands, as spec/tla/client_exchanges's `phase` names it.
        /// A program reads the events and never this. The simulator's client trace run reads it
        /// (decision 105), and its TCP trace run decides by it whether its one connection takes a
        /// request.
        pub fn phase(channel: *const Self, transport: Transport) Phase {
            return channel_calls.phase(channel, transport);
        }
    };
}

/// The type of a field that holds QUIC's state: `Type` in a channel that holds QUIC, and void in
/// one with no QUIC (decision 124).
fn QuicField(comptime capacity: Capacity, comptime Type: type) type {
    return if (capacity.quic) Type else void;
}

test "design §8 step 17f: the channel's public functions are the calls a program makes, and phase" {
    const public_names = @import("core").public_names;
    // Decision 124: a channel with no QUIC names the same calls, and its `start_quic` does not
    // compile.
    inline for (.{ Channel, ChannelOf(.{ .quic = false }) }) |Type| {
        try public_names.expect(Type, &.{
            "init",          "request",          "cancel",      "shutdown",    "receive",
            "send_datagram", "send_stream",      "deadline_ns", "on_instant",  "start_quic",
            "start_tcp",     "transport_closed", "take_ticket", "alternative", "phase",
        });
    }
}
