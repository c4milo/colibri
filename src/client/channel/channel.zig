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
//! another connection once (RFC 9113 §8.7, RFC 9114 §4.1.1).
//!
//! The caller opens a transport when an `open` event says to, starts its connection with
//! `start_quic` or `start_tcp`, and closes it when a `close` event says to. It passes what each
//! transport reads to `receive`, and writes what `send_datagram` and `send_stream` return. It loops
//! over `receive` as it does for one connection: until nothing is consumed and no event comes, and
//! again with `.none` after each send and `on_instant`. colibri makes no system call and reads no
//! clock: time is a value the caller passes (non-negotiable 3). A caller that offers h3 also places
//! the receive pool each QUIC connection holds the server's octets in, one at a time (decision 61),
//! and sizes it to the longest response it expects: `ReceivePool(capacity)`.
//!
//! `Channel`'s functions are the calls a program makes, and `phase`, which the simulator's trace
//! reads. The steps the channel takes on its own are in `channel_events.zig`, which the module's
//! root does not export (design §8 step 17f).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("../connection/connection.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const choice = @import("channel_choice.zig");
const channel_events = @import("channel_events.zig");

pub const Transport = choice.Transport;
pub const Phase = choice.Phase;
pub const Id = event.Id;
pub const HttpExchange = event.HttpExchange;
pub const Protocol = event.Protocol;
pub const Finished = event.Finished;
pub const RequestError = connection_module.RequestError;
pub const StartError = connection_module.StartError;
pub const Address = quic.peer_address.PeerAddress;
pub const Sent = quic_connection.Sent;
pub const QuicStart = quic_connection.Start;

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

pub const Config = struct {
    /// The TCP connections' configuration. It is over TLS whenever `quic` is set: h3 serves only
    /// "https" origins (RFC 9114 §3.1.2).
    tcp: *const connection_module.Config,
    /// The QUIC connections' configuration, or null when the caller offers no h3. The channel names
    /// each connection's `server_address` itself.
    quic: ?*const quic_connection.Config = null,
    /// Whether QUIC goes first when neither an HTTPS record nor Alt-Svc says whether the origin
    /// speaks h3 (RFC 9114 §3.1). When false, QUIC waits for a TCP response's Alt-Svc.
    quic_first: bool = true,
    /// How long QUIC's handshake runs before TCP opens beside it, in nanoseconds.
    fallback_delay_ns: u64,
};

/// A transport the caller opens: a UDP flow for QUIC, a TCP connection for TCP.
pub const Open = struct {
    transport: Transport,
    to: Address,
};

pub const Event = union(enum) {
    /// Open this transport, then start its connection with `start_quic` or `start_tcp`.
    open: Open,
    /// Close this transport: its connection is over, and the channel reads and writes nothing more
    /// on it.
    close: Transport,
    /// The connection carrying the exchanges speaks `Protocol`.
    connected: Protocol,
    /// A transport's server issued a resumption ticket, which `take_ticket` hands over.
    ticket: Transport,
    /// An exchange ended, and the caller may reuse its memory.
    finished: Finished,
    /// The channel was shut down, every exchange has finished, and every transport closed.
    closed,
};

/// A datagram the UDP flow read, as `QuicConnection.receive` takes it.
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
    exchange: *HttpExchange = undefined,
    carrier: Transport = .quic,
    carried_id: Id = 0,
    /// Times it moved to another connection.
    moves: u8 = 0,
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
    /// The `open` event is owed, and then the `close` event.
    open_owed: bool = false,
    close_owed: bool = false,
    /// The connection reported `connected`, and took the exchanges when it did.
    connected: bool = false,
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

pub const Channel = struct {
    config: *const Config,
    values: Values,
    /// The QUIC connections' configuration, with the address the current one sends to.
    quic_config: quic_connection.Config,
    quic: quic_connection.QuicConnection,
    tcp: connection_module.Connection,
    links: std.EnumArray(Transport, Link),
    entries: [constants.exchanges_max]Entry,
    /// The id the next exchange gets.
    next_id: Id,
    /// The transports this attempt opened, and whether the fallback delay passed during QUIC's
    /// handshake, as spec/tla/client_exchanges names them.
    tried: std.EnumArray(Transport, bool),
    fallback: bool,
    /// The instant the fallback delay passes, once QUIC's connection started.
    fallback_at_ns: ?u64,
    /// The caller shut the channel down, and the `closed` event went out.
    shut: bool,
    closed_reported: bool,
    /// The receive pool of each QUIC connection, which the caller placed, or null when it offers
    /// no h3.
    receive_pool: ?quic_connection.ReceiveStorage,

    /// Prepares a channel with nothing opened. `receive_pool` is the pool its QUIC connections use
    /// in turn when `config.quic` offers h3, and null when it does not.
    pub fn init(channel: *Channel, config: *const Config, values: Values, receive_pool: ?quic_connection.ReceiveStorage) void {
        assert(values.addresses.len > 0);
        // The pool is for QUIC's connections alone, and they need one.
        assert((config.quic == null) == (receive_pool == null));
        if (config.quic) |quic_config| {
            // RFC 9114 §3.1.2: h3 cannot reach an "http" origin, so TCP runs over TLS here.
            assert(config.tcp.tls != null);
            assert(std.mem.eql(u8, quic_config.authority, config.tcp.authority));
        }
        channel.receive_pool = receive_pool;
        channel.config = config;
        channel.values = values;
        channel.links = .initFill(.{});
        channel.entries = @splat(.{});
        channel.next_id = 1;
        channel.tried = .initFill(false);
        channel.fallback = false;
        channel.fallback_at_ns = null;
        channel.shut = false;
        channel.closed_reported = false;
    }

    /// Takes `exchange`, which goes out on the first connection open to take it, and returns its
    /// id. The caller makes no request after `shutdown`.
    pub fn request(channel: *Channel, exchange: *HttpExchange) RequestError!Id {
        assert(!channel.shut);
        try connection_module.check_request(exchange);
        const entry = channel.free_entry() orelse return error.Full;
        exchange.clear();
        entry.* = .{ .stage = .waiting, .id = channel.next_id, .exchange = exchange };
        channel.next_id += 1;
        channel_events.assign_waiting(channel);
        return entry.id;
    }

    /// Ends exchange `id`, and reports nothing for it. Its memory is the caller's again.
    pub fn cancel(channel: *Channel, id: Id) void {
        const entry = channel.entry_of(id) orelse return;
        if (entry.stage == .carried) switch (entry.carrier) {
            .quic => channel.quic.cancel(entry.carried_id),
            .tcp => channel.tcp.cancel(entry.carried_id),
        };
        entry.* = .{};
    }

    /// Takes no new exchange, and ends every connection once the exchanges it holds have finished.
    pub fn shutdown(channel: *Channel) void {
        channel.shut = true;
    }

    /// Reports what the channel owes, then passes `input` to the connection of the transport that
    /// read it, and reports what that changed.
    pub fn receive(channel: *Channel, input: Input, now_ns: u64) Received {
        if (channel.report(now_ns)) |owed| return .{ .consumed = 0, .event = owed };
        const fed = channel_events.feed(channel, input, now_ns);
        return .{ .consumed = fed.len, .event = fed.event };
    }

    /// The next datagram the QUIC connection owes, written into `output`, or null for none.
    pub fn send_datagram(channel: *Channel, output: []u8, now_ns: u64) ?Sent {
        if (channel.links.get(.quic).state != .running) return null;
        return channel.quic.send(output, now_ns);
    }

    /// The octets the TCP connection owes, written into `output`.
    pub fn send_stream(channel: *Channel, output: []u8, now_ns: u64) usize {
        if (channel.links.get(.tcp).state != .running) return 0;
        return channel.tcp.send(output, now_ns);
    }

    /// The instant the channel next wants `on_instant` at: QUIC's next deadline, or the end of the
    /// fallback delay. Null for none.
    pub fn deadline_ns(channel: *Channel) ?u64 {
        var deadline: ?u64 = null;
        if (channel.links.get(.quic).state == .running) deadline = channel.quic.deadline_ns();
        if (!channel.fallback and channel.phase(.quic) == .handshake) {
            const fallback_at = channel.fallback_at_ns orelse return deadline;
            deadline = @min(deadline orelse fallback_at, fallback_at);
        }
        return deadline;
    }

    /// Fires whichever deadlines `now_ns` has reached. The end of the fallback delay counts at the
    /// next `receive`.
    pub fn on_instant(channel: *Channel, now_ns: u64) void {
        if (channel.links.get(.quic).state == .running) channel.quic.on_instant(now_ns);
    }

    /// Starts the QUIC connection the `open` event asked for. Every draw its handshake makes comes
    /// from `random`, and `resumption` offers a ticket an earlier QUIC connection took.
    pub fn start_quic(channel: *Channel, start: QuicStart, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) quic_connection.StartError!void {
        const link = channel.links.getPtr(.quic);
        if (link.state != .opening) return;
        assert(!link.open_owed);
        channel.quic_config = channel.config.quic.?.*;
        channel.quic_config.server_address = link.to;
        channel.quic.init(&channel.quic_config, channel.receive_pool.?, start, random, now_seconds, now_ns, resumption) catch |failure| {
            // The attempt ended before it began: the model's FailHandshake, then Close.
            channel_events.close_unstarted(channel, .quic);
            return failure;
        };
        link.state = .running;
        channel.fallback_at_ns = now_ns + channel.config.fallback_delay_ns;
    }

    /// Starts the TCP connection the `open` event asked for, as `start_quic` does QUIC's.
    pub fn start_tcp(channel: *Channel, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
        const link = channel.links.getPtr(.tcp);
        if (link.state != .opening) return;
        assert(!link.open_owed);
        channel.tcp.init(channel.config.tcp, random, now_seconds, resumption) catch |failure| {
            channel_events.close_unstarted(channel, .tcp);
            return failure;
        };
        link.state = .running;
    }

    /// The caller's transport closed on its own: the peer closed it, or it failed. Every exchange
    /// its connection held ends, as the connection's own `transport_closed` rules.
    pub fn transport_closed(channel: *Channel, transport: Transport) void {
        const link = channel.links.getPtr(transport);
        switch (link.state) {
            .none, .closed => {},
            .opening => channel_events.close_unstarted(channel, transport),
            .running => {
                link.gone = true;
                switch (transport) {
                    .quic => channel.quic.transport_closed(),
                    .tcp => channel.tcp.transport_closed(),
                }
            },
        }
    }

    /// The resumption ticket the `ticket` event announced for `transport`, which the call hands
    /// over and clears.
    pub fn take_ticket(channel: *Channel, transport: Transport) ?tls.Ticket {
        if (channel.links.get(transport).state != .running) return null;
        return switch (transport) {
            .quic => channel.quic.take_ticket(),
            .tcp => channel.tcp.take_ticket(),
        };
    }

    /// The h3 alternative the channel knows of, from the values or a TCP response's Alt-Svc, which
    /// a caller keeps for a later channel (RFC 7838 §2.2).
    pub fn alternative(channel: *const Channel) ?Alternative {
        return channel.values.alternative;
    }

    /// Where `transport`'s connection stands, as spec/tla/client_exchanges's `phase` names it. A
    /// program reads the events and never this: the simulator's trace does (decision 105).
    pub fn phase(channel: *const Channel, transport: Transport) Phase {
        const link = channel.links.get(transport);
        return switch (link.state) {
            .none => .none,
            .closed => .closed,
            .opening => if (link.abandoned) .failed else .handshake,
            .running => channel.running_phase(transport, link),
        };
    }

    fn running_phase(channel: *const Channel, transport: Transport, link: Link) Phase {
        const failed = switch (transport) {
            .quic => channel.quic.failed,
            .tcp => channel.tcp.failed,
        };
        const draining = switch (transport) {
            .quic => channel.quic.draining,
            .tcp => channel.tcp.draining,
        };
        if (failed) return .failed;
        if (draining) return .draining;
        return if (link.won) .open else .handshake;
    }

    /// The first event the channel owes, after it has read what its connections owe and chosen what
    /// to open, or null.
    fn report(channel: *Channel, now_ns: u64) ?Event {
        channel.check_fallback(now_ns);
        // Bounded: each pass reads a connection's event, or plans and stops.
        for (0..constants.channel_events_per_poll_max + 1) |_| {
            channel_events.plan(channel, now_ns);
            if (channel_events.owed(channel)) |owed| return owed;
            const read = channel_events.poll(channel, now_ns) orelse return null;
            if (read.event) |reported| return reported;
        }
        unreachable;
    }

    /// The fallback delay passed while QUIC's handshake runs, and TCP may open beside it.
    fn check_fallback(channel: *Channel, now_ns: u64) void {
        const fallback_at = channel.fallback_at_ns orelse return;
        if (channel.fallback or channel.phase(.quic) != .handshake) return;
        if (now_ns >= fallback_at) channel.fallback = true;
    }

    fn free_entry(channel: *Channel) ?*Entry {
        for (&channel.entries) |*entry| {
            if (entry.stage == .free) return entry;
        }
        return null;
    }

    fn entry_of(channel: *Channel, id: Id) ?*Entry {
        for (&channel.entries) |*entry| {
            if (entry.stage != .free and entry.id == id) return entry;
        }
        return null;
    }
};

test "design §8 step 17f: the channel's public functions are the calls a program makes, and phase" {
    const public_names = @import("core").public_names;
    try public_names.expect(Channel, &.{
        "init",          "request",          "cancel",      "shutdown",    "receive",
        "send_datagram", "send_stream",      "deadline_ns", "on_instant",  "start_quic",
        "start_tcp",     "transport_closed", "take_ticket", "alternative", "phase",
    });
}
