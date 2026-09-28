//! The client for one origin (decision 100, design §8 step 17d): it carries the caller's exchanges
//! over the QUIC and TCP connections it chooses between, and tells the caller which transport to
//! open, to which address and port. spec/tla/client_exchanges models the choice (decision 105).
//!
//! The caller passes what DNS knows as values and never a name to resolve: the server's addresses,
//! and an HTTPS record's `alpn` and `port` (RFC 9460 §7.1, §7.2). QUIC goes first when h3 is known,
//! or when the configuration says to try it (RFC 9114 §3.1), and TCP opens when QUIC fails or the
//! fallback delay passes. The first connection whose handshake completes takes the exchanges, and
//! the other closes. A TCP response's Alt-Svc teaches the origin h3 for its next connection (RFC
//! 7838 §3). An exchange that a connection taking no new exchange refused unprocessed moves to
//! another connection once (RFC 9113 §8.7, RFC 9114 §4.1.1).
//!
//! The caller opens a transport when an `open` event says to, starts its connection with
//! `start_quic` or `start_tcp`, and closes it when a `close` event says to. It passes what each
//! transport reads to `receive`, and writes what `send_datagram` and `send_stream` return. It loops
//! over `receive` as it does for one connection: until nothing is consumed and no event comes, and
//! again with `.none` after each send and `on_instant`. colibri makes no system call and reads no
//! clock: time is a value the caller passes (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("constants.zig");
const event = @import("event.zig");
const connection_module = @import("connection.zig");
const quic_connection = @import("quic_connection.zig");
const alt_svc = @import("alt_svc.zig");
const choice = @import("origin_choice.zig");
const origin_events = @import("origin_events.zig");

pub const Transport = choice.Transport;
pub const Phase = choice.Phase;
pub const Id = event.Id;
pub const Exchange = event.Exchange;
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
    /// An h3 alternative an earlier origin learned from Alt-Svc, which the caller kept, or null.
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
    /// The QUIC connections' configuration, or null when the caller offers no h3. The origin names
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
    /// Close this transport: its connection is over, and the origin reads and writes nothing more
    /// on it.
    close: Transport,
    /// The connection carrying the exchanges speaks `Protocol`.
    connected: Protocol,
    /// A transport's server issued a resumption ticket, which `take_ticket` hands over.
    ticket: Transport,
    /// An exchange ended, and the caller may reuse its memory.
    finished: Finished,
    /// The origin was shut down, every exchange has finished, and every transport closed.
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

/// Where an exchange is, at the origin.
pub const Stage = enum {
    free,
    /// The origin holds it until a connection is open to take it.
    waiting,
    /// A connection holds it, by `carried_id`.
    carried,
    /// It ended at the origin, refused, and its `finished` event is owed.
    ended,
};

pub const Entry = struct {
    stage: Stage = .free,
    id: Id = 0,
    exchange: *Exchange = undefined,
    carrier: Transport = .quic,
    carried_id: Id = 0,
    /// Times it moved to another connection.
    moves: u8 = 0,
};

/// One transport's connection, as the origin tracks it.
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

pub const Origin = struct {
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
    /// The caller shut the origin down, and the `closed` event went out.
    shut: bool,
    closed_reported: bool,

    /// Prepares an origin with nothing opened.
    pub fn init(origin: *Origin, config: *const Config, values: Values) void {
        assert(values.addresses.len > 0);
        if (config.quic) |quic_config| {
            // RFC 9114 §3.1.2: h3 cannot reach an "http" origin, so TCP runs over TLS here.
            assert(config.tcp.tls != null);
            assert(std.mem.eql(u8, quic_config.authority, config.tcp.authority));
        }
        origin.config = config;
        origin.values = values;
        origin.links = .initFill(.{});
        origin.entries = @splat(.{});
        origin.next_id = 1;
        origin.tried = .initFill(false);
        origin.fallback = false;
        origin.fallback_at_ns = null;
        origin.shut = false;
        origin.closed_reported = false;
    }

    /// Takes `exchange`, which goes out on the first connection open to take it, and returns its
    /// id. The caller makes no request after `shutdown`.
    pub fn request(origin: *Origin, exchange: *Exchange) RequestError!Id {
        assert(!origin.shut);
        try connection_module.check_request(exchange);
        const entry = origin.free_entry() orelse return error.Full;
        exchange.clear();
        entry.* = .{ .stage = .waiting, .id = origin.next_id, .exchange = exchange };
        origin.next_id += 1;
        origin_events.assign_waiting(origin);
        return entry.id;
    }

    /// Ends exchange `id`, and reports nothing for it. Its memory is the caller's again.
    pub fn cancel(origin: *Origin, id: Id) void {
        const entry = origin.entry_of(id) orelse return;
        if (entry.stage == .carried) switch (entry.carrier) {
            .quic => origin.quic.cancel(entry.carried_id),
            .tcp => origin.tcp.cancel(entry.carried_id),
        };
        entry.* = .{};
    }

    /// Takes no new exchange, and ends every connection once the exchanges it holds have finished.
    pub fn shutdown(origin: *Origin) void {
        origin.shut = true;
    }

    /// Reports what the origin owes, then passes `input` to the connection of the transport that
    /// read it, and reports what that changed.
    pub fn receive(origin: *Origin, input: Input, now_ns: u64) Received {
        if (origin.report(now_ns)) |owed| return .{ .consumed = 0, .event = owed };
        const fed = origin_events.feed(origin, input, now_ns);
        return .{ .consumed = fed.len, .event = fed.event };
    }

    /// The next datagram the QUIC connection owes, written into `output`, or null for none.
    pub fn send_datagram(origin: *Origin, output: []u8, now_ns: u64) ?Sent {
        if (origin.links.get(.quic).state != .running) return null;
        return origin.quic.send(output, now_ns);
    }

    /// The octets the TCP connection owes, written into `output`.
    pub fn send_stream(origin: *Origin, output: []u8, now_ns: u64) usize {
        if (origin.links.get(.tcp).state != .running) return 0;
        return origin.tcp.send(output, now_ns);
    }

    /// The instant the origin next wants `on_instant` at: QUIC's next deadline, or the end of the
    /// fallback delay. Null for none.
    pub fn deadline_ns(origin: *Origin) ?u64 {
        var deadline: ?u64 = null;
        if (origin.links.get(.quic).state == .running) deadline = origin.quic.deadline_ns();
        if (!origin.fallback and origin.phase(.quic) == .handshake) {
            const fallback_at = origin.fallback_at_ns orelse return deadline;
            deadline = @min(deadline orelse fallback_at, fallback_at);
        }
        return deadline;
    }

    /// Fires whichever deadlines `now_ns` has reached. The end of the fallback delay counts at the
    /// next `receive`.
    pub fn on_instant(origin: *Origin, now_ns: u64) void {
        if (origin.links.get(.quic).state == .running) origin.quic.on_instant(now_ns);
    }

    /// Starts the QUIC connection the `open` event asked for. Every draw its handshake makes comes
    /// from `random`, and `resumption` offers a ticket an earlier QUIC connection took.
    pub fn start_quic(origin: *Origin, start: QuicStart, random: tls.Random, now_seconds: u64, now_ns: u64, resumption: ?tls.Resumption) quic_connection.StartError!void {
        const link = origin.links.getPtr(.quic);
        if (link.state != .opening) return;
        assert(!link.open_owed);
        origin.quic_config = origin.config.quic.?.*;
        origin.quic_config.server_address = link.to;
        origin.quic.init(&origin.quic_config, start, random, now_seconds, now_ns, resumption) catch |failure| {
            // The attempt ended before it began: the model's FailHandshake, then Close.
            origin_events.close_unstarted(origin, .quic);
            return failure;
        };
        link.state = .running;
        origin.fallback_at_ns = now_ns + origin.config.fallback_delay_ns;
    }

    /// Starts the TCP connection the `open` event asked for, as `start_quic` does QUIC's.
    pub fn start_tcp(origin: *Origin, random: tls.Random, now_seconds: u64, resumption: ?tls.Resumption) StartError!void {
        const link = origin.links.getPtr(.tcp);
        if (link.state != .opening) return;
        assert(!link.open_owed);
        origin.tcp.init(origin.config.tcp, random, now_seconds, resumption) catch |failure| {
            origin_events.close_unstarted(origin, .tcp);
            return failure;
        };
        link.state = .running;
    }

    /// The caller's transport closed on its own: the peer closed it, or it failed. Every exchange
    /// its connection held ends, as the connection's own `transport_closed` rules.
    pub fn transport_closed(origin: *Origin, transport: Transport) void {
        const link = origin.links.getPtr(transport);
        switch (link.state) {
            .none, .closed => {},
            .opening => origin_events.close_unstarted(origin, transport),
            .running => {
                link.gone = true;
                switch (transport) {
                    .quic => origin.quic.transport_closed(),
                    .tcp => origin.tcp.transport_closed(),
                }
            },
        }
    }

    /// The resumption ticket the `ticket` event announced for `transport`, which the call hands
    /// over and clears.
    pub fn take_ticket(origin: *Origin, transport: Transport) ?tls.Ticket {
        if (origin.links.get(transport).state != .running) return null;
        return switch (transport) {
            .quic => origin.quic.take_ticket(),
            .tcp => origin.tcp.take_ticket(),
        };
    }

    /// The h3 alternative the origin knows of, from the values or a TCP response's Alt-Svc, which
    /// a caller keeps for a later origin (RFC 7838 §2.2).
    pub fn alternative(origin: *const Origin) ?Alternative {
        return origin.values.alternative;
    }

    /// Where `transport`'s connection stands, as spec/tla/client_exchanges's `phase` names it.
    pub fn phase(origin: *const Origin, transport: Transport) Phase {
        const link = origin.links.get(transport);
        return switch (link.state) {
            .none => .none,
            .closed => .closed,
            .opening => if (link.abandoned) .failed else .handshake,
            .running => origin.running_phase(transport, link),
        };
    }

    fn running_phase(origin: *const Origin, transport: Transport, link: Link) Phase {
        const failed = switch (transport) {
            .quic => origin.quic.failed,
            .tcp => origin.tcp.failed,
        };
        const draining = switch (transport) {
            .quic => origin.quic.draining,
            .tcp => origin.tcp.draining,
        };
        if (failed) return .failed;
        if (draining) return .draining;
        return if (link.won) .open else .handshake;
    }

    /// Whether QUIC may carry the exchanges at `now_ns`: h3 is offered, and a fresh Alt-Svc
    /// alternative, an HTTPS record or the configuration says to try it.
    pub fn quic_allowed(origin: *const Origin, now_ns: u64) bool {
        if (origin.config.quic == null) return false;
        if (origin.fresh_alternative(now_ns)) |_| return true;
        // RFC 9460 §7.1.2: a client uses the transports of the protocols the record names.
        if (origin.values.https) |https| return https.h3;
        return origin.config.quic_first;
    }

    /// The Alt-Svc alternative, while it is fresh (RFC 7838 §2.2).
    pub fn fresh_alternative(origin: *const Origin, now_ns: u64) ?Alternative {
        const held = origin.values.alternative orelse return null;
        return if (now_ns < held.fresh_until_ns) held else null;
    }

    /// Keeps what a TCP response's Alt-Svc said at `now_ns`, which replaces what the origin knew
    /// (RFC 7838 §3.1).
    pub fn learn(origin: *Origin, advert: alt_svc.Advert, now_ns: u64) void {
        origin.values.alternative = switch (advert) {
            .clear, .none => null,
            .h3 => |h3| .{ .port = h3.port, .fresh_until_ns = now_ns +| h3.max_age_s *| constants.nanoseconds_per_second },
        };
    }

    /// The first event the origin owes, after it has read what its connections owe and chosen what
    /// to open, or null.
    fn report(origin: *Origin, now_ns: u64) ?Event {
        origin.check_fallback(now_ns);
        // Bounded: each pass reads a connection's event, or plans and stops.
        for (0..constants.origin_events_per_poll_max + 1) |_| {
            origin_events.plan(origin, now_ns);
            if (origin_events.owed(origin)) |owed| return owed;
            const read = origin_events.poll(origin, now_ns) orelse return null;
            if (read.event) |reported| return reported;
        }
        unreachable;
    }

    /// The fallback delay passed while QUIC's handshake runs, and TCP may open beside it.
    fn check_fallback(origin: *Origin, now_ns: u64) void {
        const fallback_at = origin.fallback_at_ns orelse return;
        if (origin.fallback or origin.phase(.quic) != .handshake) return;
        if (now_ns >= fallback_at) origin.fallback = true;
    }

    fn free_entry(origin: *Origin) ?*Entry {
        for (&origin.entries) |*entry| {
            if (entry.stage == .free) return entry;
        }
        return null;
    }

    fn entry_of(origin: *Origin, id: Id) ?*Entry {
        for (&origin.entries) |*entry| {
            if (entry.stage != .free and entry.id == id) return entry;
        }
        return null;
    }
};
