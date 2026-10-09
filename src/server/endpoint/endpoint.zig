//! The server's endpoint (decision 103, decision 119): up to a build-time number of QUIC
//! connections behind one UDP socket the caller owns, each in a slot of its own. The caller passes
//! each datagram, with the address it came from, to `receive`; the endpoint hands it to the
//! connection its first packet's Destination Connection ID names (RFC 9000 §5.2), starts a
//! connection from a client's first Initial (§7.2), and answers Version Negotiation (§6.1) and
//! Retry (§8.1.2) itself. `receive` then reports the next event any connection owes, its id naming
//! the connection, and the caller answers a request by its id with `respond`, `write_body` and
//! `write_trailers`.
//!
//! Every request ends with one `done` or `cancelled`, and a connection's `ended` comes after its
//! requests' (INV-30); its slot then takes a later client, and the slot's generation makes every
//! id of the ended connection name nothing. `send_datagram` writes the next datagram any
//! connection owes, with the address it goes to, and `deadline_ns` is the soonest deadline of any
//! connection, kept without reading every connection on each call (INV-31). Every connection ID the
//! endpoint issues and every value a handshake draws come from the caller's source (invariant 5).
//! colibri makes no system call and reads no clock (non-negotiable 3). The endpoint keeps pointers
//! into itself, so it stays where `init` found it.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const deadline = @import("../deadline.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const endpoint_connections = @import("endpoint_connections.zig");
const endpoint_config = @import("endpoint_config.zig");
const endpoint_held = @import("endpoint_held.zig");

const QuicConnection = quic_connection.QuicConnection;
const Connection = @import("../connection/connection.zig").Connection;
const ReceiveStorage = quic_connection.ReceiveStorage;
const Sent = quic_connection.Sent;
const Id = event.Id;
const ConnectionHandle = event.ConnectionHandle;
const SendError = connection_errors.SendError;
const StartError = connection_errors.StartError;

pub const Config = endpoint_config.Config;
pub const LogProvider = endpoint_connections.LogProvider;
pub const Input = endpoint_held.Input;
pub const Datagram = endpoint_held.Datagram;
pub const Security = endpoint_held.Security;
pub const StreamOctets = endpoint_held.StreamOctets;

/// How many connections an endpoint holds, fixed at build time (decision 35): its TCP and its
/// QUIC connections, either of which may be 0, and the octets each QUIC connection holds that it
/// has not read (decision 61).
pub const Capacity = struct {
    tcp_connections: usize = constants.tcp_connections_default,
    quic_connections: usize = constants.quic_connections_default,
    receive_pool_len: usize = quic.constants.receive_pool_len_default,
};

/// An endpoint of the default size.
pub const Endpoint = EndpointOf(.{});

/// An endpoint that holds the connections `capacity` names.
pub fn EndpointOf(comptime capacity: Capacity) type {
    comptime assert(capacity.tcp_connections + capacity.quic_connections > 0);
    const slots_max = capacity.tcp_connections + capacity.quic_connections;
    return struct {
        const Self = @This();
        const Pool = quic.stream.stream_incoming.Pool(capacity.receive_pool_len);

        held: endpoint_held.Held,
        /// The TLS configuration of each transport, and what each connection borrows, which
        /// `init` builds from `Config`.
        quic_tls: tls.quic.ServerConfig,
        quic_config: quic_connection.Config,
        tcp_tls: tls.record.ServerConfig,
        tcp_configs: endpoint_config.TcpConfigs,
        tcp: [capacity.tcp_connections]Connection,
        tcp_tables: [capacity.tcp_connections]endpoint_held.TcpTable,
        transports: [capacity.tcp_connections]endpoint_held.Transport,
        send_outstanding: [capacity.tcp_connections]bool,
        quic: [capacity.quic_connections]QuicConnection,
        pools: [capacity.quic_connections]Pool,
        storages: [capacity.quic_connections]ReceiveStorage,
        quic_tables: [capacity.quic_connections]endpoint_held.QuicTable,
        generations: [slots_max]u32,
        live: [slots_max]bool,
        free: [slots_max]u32,
        failed: [slots_max]bool,
        room: [slots_max]u32,
        ready_numbers: [slots_max]u32,
        ready_queued: [slots_max]bool,
        send_numbers: [slots_max]u32,
        send_queued: [slots_max]bool,
        cached: [slots_max]u64,
        position: [slots_max]u32,
        order: [slots_max]u32,
        stale_numbers: [slots_max]u32,
        stale_queued: [slots_max]bool,

        /// Prepares an endpoint that holds no connection. Every value it draws comes from
        /// `random`. `now_seconds` is the Unix time at `now_ns`, which the server's tickets are
        /// issued at, or 0 for none. It builds the TLS configuration of each transport it serves
        /// from `config.tls` and checks that its key signs. `error.NoVersion` says no slot it
        /// holds serves a version `versions` allows: its TCP slots no h11 or h2, and its QUIC
        /// slots no h3 or no identity. `error.DeadlineInvalid` says that
        /// `config.deadlines` holds a limit `Deadlines.validate` or `validate_units` refuses
        /// (decision 110 as amended). `error.IdentityRefused`, `TooManyCertificates`,
        /// `TooManySuites` and `SuitesUnavailable` say the TLS configuration refused the
        /// identity. The endpoint reads `config` while it runs.
        pub fn init(endpoint: *Self, config: *const Config, random: tls.Random, now_seconds: u64, now_ns: u64) StartError!void {
            const counts: endpoint_config.Counts = .{ .tcp = capacity.tcp_connections, .quic = capacity.quic_connections };
            const served = try endpoint_config.build(config, counts, .{
                .quic_tls = &endpoint.quic_tls,
                .quic = &endpoint.quic_config,
                .tcp_tls = &endpoint.tcp_tls,
                .tcp = &endpoint.tcp_configs,
            }, random);
            for (&endpoint.pools, &endpoint.storages) |*pool, *storage| storage.* = pool.storage();
            for (&endpoint.quic_tables) |*table| table.init();
            const built: endpoint_held.Built = .{ .quic = &endpoint.quic_config, .tcp = &endpoint.tcp_configs, .served = served };
            endpoint.held.init(config, built, .{
                .tcp = &endpoint.tcp,
                .tcp_tables = &endpoint.tcp_tables,
                .transports = &endpoint.transports,
                .send_outstanding = &endpoint.send_outstanding,
                .quic = &endpoint.quic,
                .pools = &endpoint.storages,
                .quic_tables = &endpoint.quic_tables,
                .generations = &endpoint.generations,
                .live = &endpoint.live,
                .free = &endpoint.free,
                .failed = &endpoint.failed,
                .room = &endpoint.room,
                .ready_numbers = &endpoint.ready_numbers,
                .ready_queued = &endpoint.ready_queued,
                .send_numbers = &endpoint.send_numbers,
                .send_queued = &endpoint.send_queued,
                .cached = &endpoint.cached,
                .position = &endpoint.position,
                .order = &endpoint.order,
                .stale_numbers = &endpoint.stale_numbers,
                .stale_queued = &endpoint.stale_queued,
            }, random, now_seconds, now_ns);
        }

        /// Starts a connection on a TCP socket the program accepted, in cleartext or over TLS,
        /// and returns the handle that names it. Null when no TCP slot is free, after `shutdown`,
        /// when `versions` allows no TCP version, or when chapulin refuses to start its session:
        /// the program closes the socket then.
        pub fn accept(endpoint: *Self, security: Security, now_ns: u64) ?ConnectionHandle {
            return endpoint.held.accept(security, now_ns);
        }

        /// Takes what `input` brings, then reports the next event any connection owes. The
        /// caller passes the octets each TCP socket read and each datagram the UDP socket read,
        /// and calls with `.none` after it answers, after `send_stream` and after `on_instant`,
        /// until a call reports nothing. A TCP connection may consume less than it was given: the
        /// caller holds the rest and passes it again, with what the socket reads next, and after
        /// each event that names the connection, which may say it reads again, such as the `done`
        /// of an h11 response a pipelined request waited for. An event's slices stay
        /// valid until the next `receive`, `on_instant`, `send_stream`, `send_datagram`, `accept`,
        /// `transport_closed` or `shutdown`.
        pub fn receive(endpoint: *Self, input: Input, now_ns: u64) event.Received {
            return endpoint.held.receive(input, now_ns);
        }

        /// Sets the word each later event of request `id` carries: its `body`, `trailers`,
        /// `writable` and its one `done` or `cancelled` (decision 119).
        pub fn set_user_data(endpoint: *Self, id: Id, user_data: usize) error{RequestUnknown}!void {
            return endpoint.held.set_user_data(id, user_data);
        }

        /// Writes the head of the response to request `id`: an interim one (1xx) or the final
        /// one. With `end`, the final response carries no content. `error.NoSpaceLeft` says the
        /// response has no room for it: its `writable` comes once it has.
        pub fn respond(endpoint: *Self, id: Id, response: event.Response) SendError!void {
            return endpoint.held.respond(id, response);
        }

        /// Takes content of the response to request `id`, and returns the octets taken. Nothing is
        /// copied over QUIC: the octets stay the caller's until the request is `done` or
        /// `cancelled` (decision 103). A take of less than `content`, or `error.Blocked`, says the
        /// response has no room for more: its `writable` comes once it has.
        pub fn write_body(endpoint: *Self, id: Id, content: event.Content) SendError!usize {
            return endpoint.held.write_body(id, content);
        }

        /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5).
        /// `error.NoSpaceLeft`, or `error.Blocked` while a coded response's last octets wait, says
        /// the response has no room for it: its `writable` comes once it has.
        pub fn write_trailers(endpoint: *Self, id: Id, fields: []const http.Field) SendError!void {
            return endpoint.held.write_trailers(id, fields);
        }

        /// Ends request `id` before its response is whole: its `cancelled` follows, with the
        /// reason `program`, and nothing more of it.
        pub fn cancel(endpoint: *Self, id: Id) void {
            endpoint.held.cancel(id);
        }

        /// Ends every connection once the requests it holds are answered, and starts no new one.
        /// `closed` follows once every connection has ended.
        pub fn shutdown(endpoint: *Self, now_ns: u64) void {
            endpoint.held.shutdown(now_ns);
        }

        /// Writes into `output` what the TCP connection `connection` owes its socket, after the
        /// endpoint reported a `send` for it, and returns the octets written: 0 for a handle that
        /// names no connection. A call that fills `output` leaves more owed, and the caller calls
        /// again. One that leaves room ends the `send`: the endpoint reports another once the
        /// connection owes more, at once when a record's overhead did not fit the room left.
        pub fn send_stream(endpoint: *Self, connection: ConnectionHandle, output: []u8, now_ns: u64) usize {
            return endpoint.held.send_stream(connection, output, now_ns);
        }

        /// The socket of the TCP connection `connection` closed: the peer closed it, the caller
        /// closed it after a `close`, or it failed. The `done` of each response written whole,
        /// the `cancelled` of each other request, and the connection's `ended` follow.
        pub fn transport_closed(endpoint: *Self, connection: ConnectionHandle) void {
            endpoint.held.transport_closed(connection);
        }

        /// Writes into `output` the next datagram the endpoint owes, and names where it goes. Null
        /// when it owes none.
        pub fn send_datagram(endpoint: *Self, output: []u8, now_ns: u64) ?Sent {
            return endpoint.held.send_datagram(output, now_ns);
        }

        /// The soonest instant any connection wants `on_instant` at (design §4.2), or null.
        pub fn deadline_ns(endpoint: *Self) ?u64 {
            return endpoint.held.deadline_ns();
        }

        /// Fires whichever deadlines `now_ns` has reached.
        pub fn on_instant(endpoint: *Self, now_ns: u64) void {
            endpoint.held.on_instant(now_ns);
        }

        /// Replaces one connection's limits (decision 110), for a caller short of connections that
        /// shortens its deadlines.
        pub fn set_deadlines(endpoint: *Self, connection: ConnectionHandle, deadlines: deadline.Deadlines) error{ DeadlineInvalid, ConnectionUnknown }!void {
            return endpoint.held.set_deadlines(connection, deadlines);
        }

        /// The server_name the connection's client sent (RFC 9846 §9.2), or null.
        pub fn server_name(endpoint: *Self, connection: ConnectionHandle) ?[]const u8 {
            return endpoint.held.server_name(connection);
        }
    };
}

test "design §8 step 17f: the endpoint's public functions are the calls a program makes" {
    const public_names = @import("core").public_names;
    // Design §8 step 21b.3 (decision 119): the endpoint answers requests by id.
    // Design §8 step 21b.4 adds `accept`, `send_stream` and `transport_closed` (decision 119).
    try public_names.expect(Endpoint, &.{
        "init",             "accept",         "receive",     "set_user_data", "respond",
        "write_body",       "write_trailers", "cancel",      "shutdown",      "send_stream",
        "transport_closed", "send_datagram",  "deadline_ns", "on_instant",    "set_deadlines",
        "server_name",
    });
}
