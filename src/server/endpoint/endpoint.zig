//! The server's QUIC endpoint (decision 103, design §8 step 17b): up to a build-time number of
//! QUIC connections behind one UDP socket the caller owns. The caller passes each datagram with
//! the address it came from; the endpoint hands it to the connection its first packet's
//! Destination Connection ID names (RFC 9000 §5.2), starts a connection from a client's first
//! Initial (§7.2), and answers Version Negotiation (§6.1) and Retry (§8.1.2) itself. It returns
//! the connection that took the datagram, which the caller then drives with the TCP connection's
//! calls, in the shape the owner chose on 2026-09-28.
//!
//! `send` writes the next datagram any connection owes, with the address it goes to, and `ended`
//! hands back each connection that is over, whose slot a later client takes. Every connection ID
//! the endpoint issues and every value a handshake draws come from the caller's source (invariant
//! 5). colibri makes no system call and reads no clock (non-negotiable 3). The endpoint keeps
//! pointers into itself, so it stays where `init` found it.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const endpoint_connections = @import("endpoint_connections.zig");

const QuicConnection = quic_connection.QuicConnection;
const PeerAddress = quic_connection.PeerAddress;
const ReceiveStorage = quic_connection.ReceiveStorage;
const Sent = quic_connection.Sent;
const Ecn = quic.connection_receive.Datagram.Ecn;

pub const Config = endpoint_connections.Config;
pub const LogProvider = endpoint_connections.LogProvider;

/// An endpoint of the default size: `quic_connections_default` connections, each with a receive
/// pool of `receive_pool_len_default` octets.
pub const Endpoint = EndpointOf(constants.quic_connections_default, quic.constants.receive_pool_len_default);

/// An endpoint that holds up to `connections_max` connections, each holding up to
/// `receive_capacity` octets it has not read (decision 61).
pub fn EndpointOf(comptime connections_max: usize, comptime receive_capacity: usize) type {
    comptime assert(connections_max > 0);
    return struct {
        const Self = @This();
        const Pool = quic.stream.stream_incoming.Pool(receive_capacity);

        held: endpoint_connections.Connections,
        connections: [connections_max]QuicConnection,
        live: [connections_max]bool,
        pools: [connections_max]Pool,
        storages: [connections_max]ReceiveStorage,

        /// Prepares an endpoint that holds no connection. Every value it draws comes from
        /// `random`. `now_seconds` is the Unix time at `now_ns`, which the server's tickets are
        /// issued at, or 0 for none. `error.DeadlineInvalid` says `config.quic.deadlines` holds a
        /// limit `Deadlines.validate` or `validate_units` refuses (decision 110 as amended).
        pub fn init(endpoint: *Self, config: *const Config, random: tls.Random, now_seconds: u64, now_ns: u64) error{DeadlineInvalid}!void {
            for (&endpoint.pools, &endpoint.storages) |*pool, *storage| storage.* = pool.storage();
            try endpoint.held.init(config, &endpoint.connections, &endpoint.live, &endpoint.storages, random, now_seconds, now_ns);
        }

        /// Takes one datagram the socket read from `from`, which the suite opens in place, and
        /// returns the connection that took it, or null when none did.
        pub fn receive(endpoint: *Self, datagram: []u8, ecn: Ecn, from: PeerAddress, now_ns: u64) ?*QuicConnection {
            return endpoint.held.receive(datagram, ecn, from, now_ns);
        }

        /// Writes into `output` the next datagram the endpoint owes: a Version Negotiation or
        /// Retry packet first, then each connection's in turn. Null when it owes none.
        pub fn send(endpoint: *Self, output: []u8, now_ns: u64) ?Sent {
            return endpoint.held.send(output, now_ns);
        }

        /// The instant a connection next wants `on_instant` at (design §4.2), or null for none.
        pub fn deadline_ns(endpoint: *Self) ?u64 {
            return endpoint.held.deadline_ns();
        }

        /// Fires whichever deadlines `now_ns` has reached.
        pub fn on_instant(endpoint: *Self, now_ns: u64) void {
            endpoint.held.on_instant(now_ns);
        }

        /// The next connection that is over, which the call frees, or null. The connection's
        /// memory stays as it is until a later `receive` starts another in its slot.
        pub fn ended(endpoint: *Self) ?*QuicConnection {
            return endpoint.held.ended();
        }
    };
}

test "design §8 step 17f: the endpoint's public functions are the calls a program makes" {
    const public_names = @import("core").public_names;
    try public_names.expect(Endpoint, &.{
        "init",  "receive", "send", "deadline_ns", "on_instant",
        "ended",
    });
}
