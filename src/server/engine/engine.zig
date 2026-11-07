//! The server's engine (decision 103, decision 119): the server side of every connection one
//! thread serves. It holds up to a build-time number of TCP connections, which the caller accepts
//! and which serve h11 or h2, and of QUIC connections behind one UDP socket the caller owns, which
//! serve h3, each in a slot of its own.
//!
//! The caller calls `accept` for each TCP socket, and passes what a socket read to `receive` with
//! the handle `accept` returned. It passes each datagram, with the address it came from, to
//! `receive` too: the engine hands it to the connection its first packet's Destination
//! Connection ID names (RFC 9000 §5.2), starts a connection from a client's first Initial (§7.2),
//! and answers Version Negotiation (§6.1) and Retry (§8.1.2) itself. `receive` then reports the
//! next event any connection owes, its id naming the connection, and the caller answers a request
//! by its id with `respond`, `write_body` and `write_trailers`.
//!
//! Every request ends with one `done` or `cancelled`, and a connection's `ended` comes after its
//! requests' (INV-30); its slot then takes a later connection, and the slot's generation makes
//! every id of the ended connection name nothing. `send_stream` writes what a TCP connection owes
//! its socket, `send_datagram` writes the next datagram any QUIC connection owes, with the address
//! it goes to, and `deadline_ns` is the soonest deadline of any connection, kept without reading
//! every connection on each call (INV-31). Every connection ID the engine issues and every value
//! a handshake draws come from the caller's source (invariant 5). colibri makes no system call and
//! reads no clock (non-negotiable 3). The engine keeps pointers into itself, so it stays where
//! `init` found it.
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
const engine_connections = @import("engine_connections.zig");
const engine_routes = @import("engine_routes.zig");
const engine_config = @import("engine_config.zig");
const engine_state = @import("engine_state.zig");

const QuicConnection = quic_connection.QuicConnection;
const Connection = @import("../connection/connection.zig").Connection;
const ReceiveStorage = quic_connection.ReceiveStorage;
const Sent = quic_connection.Sent;
const RequestId = event.RequestId;
const ConnectionHandle = event.ConnectionHandle;
const SendError = connection_errors.SendError;
const StartError = connection_errors.StartError;

pub const Config = engine_config.Config;
pub const LogProvider = engine_connections.LogProvider;
pub const Input = engine_state.Input;
pub const Datagram = engine_state.Datagram;
pub const StreamBytes = engine_state.StreamBytes;

/// How many connections an engine holds, fixed at build time (decision 35): its TCP and its
/// QUIC connections, either of which may be 0, and the octets each QUIC connection holds that it
/// has not read (decision 61).
pub const Capacity = struct {
    tcp_connections: usize = constants.limits.tcp_connections_default,
    quic_connections: usize = constants.limits.quic_connections_default,
    receive_pool_len: usize = quic.constants.limits.receive_pool_len_default,
};

/// An instant as the program reads its clocks: the nanoseconds of its monotonic clock, and the Unix
/// time in seconds at that instant, or 0 for none (decision 158 ruling 2). One value holds both, so
/// the compiler refuses the two in the wrong order.
pub const Instant = struct {
    ns: u64,
    unix_seconds: u64,
};

/// An engine that holds the connections `capacity` names: the server side of every connection one
/// thread serves, over TCP and over QUIC. A program with several threads places one for each, and
/// `Engine(.{})` holds the default capacity.
pub fn Engine(comptime capacity: Capacity) type {
    comptime assert(capacity.tcp_connections + capacity.quic_connections > 0);
    const slots_max = capacity.tcp_connections + capacity.quic_connections;
    return struct {
        const Self = @This();
        const Pool = quic.ReceivePool(.{ .capacity = capacity.receive_pool_len });

        state: engine_state.State,
        /// The copy of the program's `Config` that `init` took. The engine reads this copy while it
        /// runs, and never the program's `Config` (decision 158 ruling 2).
        config: Config,
        /// The TLS configuration of each transport, and what each connection borrows, which
        /// `init` builds from `Config`.
        quic_tls: tls.quic.ServerConfig,
        quic_config: quic_connection.Config,
        tcp_tls: tls.record.ServerConfig,
        tcp_configs: engine_config.TcpConfigs,
        tcp: [capacity.tcp_connections]Connection,
        tcp_tables: [capacity.tcp_connections]engine_state.TcpTable,
        transports: [capacity.tcp_connections]engine_state.Transport,
        send_outstanding: [capacity.tcp_connections]bool,
        empty_read_ns: [capacity.tcp_connections]?u64,
        quic: [capacity.quic_connections]QuicConnection,
        pools: [capacity.quic_connections]Pool,
        storages: [capacity.quic_connections]ReceiveStorage,
        quic_tables: [capacity.quic_connections]engine_state.QuicTable,
        route_entries: [engine_routes.entries_for(capacity.quic_connections)]engine_routes.Entry,
        route_held: [capacity.quic_connections]engine_routes.Held,
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

        /// What `accept` takes of a TCP socket the program accepted.
        pub const Accepted = engine_state.Accepted;

        /// Prepares an engine that holds no connection. Every value it draws comes from
        /// `random`. `now.unix_seconds` is the Unix time at `now.ns`, which the server's tickets
        /// are issued at, or 0 for none. It builds the TLS configuration of each transport it serves
        /// from `config.tls` and checks that its key signs. `error.NoVersion` says no slot it
        /// holds serves a version `versions` allows: its TCP slots no h11 or h2, and its QUIC
        /// slots no h3 or no identity. `error.TimeoutInvalid` says that
        /// `config.deadlines` holds a limit `Timeouts.validate` or `validate_units` refuses
        /// (decision 110 as amended). `error.IdentityRefused`, `TooManyCertificates`,
        /// `TooManySuites` and `SuitesUnavailable` say the TLS configuration refused the
        /// identity. The engine copies `config`, so the program may change or free its own
        /// `Config` once `init` returns. The pools, the identity and the providers `config`
        /// names stay the program's, and live as long as the engine.
        pub fn init(engine: *Self, config: *const Config, random: tls.Random, now: Instant) StartError!void {
            engine.config = config.*;
            const counts: engine_config.Counts = .{ .tcp = capacity.tcp_connections, .quic = capacity.quic_connections };
            const served = try engine_config.build(&engine.config, counts, .{
                .quic_tls = &engine.quic_tls,
                .quic = &engine.quic_config,
                .tcp_tls = &engine.tcp_tls,
                .tcp = &engine.tcp_configs,
            }, random);
            for (&engine.pools, &engine.storages) |*pool, *storage| storage.* = pool.storage();
            for (&engine.quic_tables) |*table| table.init();
            const built: engine_state.Built = .{ .quic = &engine.quic_config, .tcp = &engine.tcp_configs, .served = served };
            engine.state.init(&engine.config, built, .{
                .tcp = &engine.tcp,
                .tcp_tables = &engine.tcp_tables,
                .transports = &engine.transports,
                .send_outstanding = &engine.send_outstanding,
                .empty_read_ns = &engine.empty_read_ns,
                .quic = &engine.quic,
                .pools = &engine.storages,
                .quic_tables = &engine.quic_tables,
                .route_entries = &engine.route_entries,
                .route_held = &engine.route_held,
                .generations = &engine.generations,
                .live = &engine.live,
                .free = &engine.free,
                .failed = &engine.failed,
                .room = &engine.room,
                .ready_numbers = &engine.ready_numbers,
                .ready_queued = &engine.ready_queued,
                .send_numbers = &engine.send_numbers,
                .send_queued = &engine.send_queued,
                .cached = &engine.cached,
                .position = &engine.position,
                .order = &engine.order,
                .stale_numbers = &engine.stale_numbers,
                .stale_queued = &engine.stale_queued,
            }, random, now.unix_seconds, now.ns);
        }

        /// Starts a connection on a TCP socket the program accepted, over TLS by default, `.{}`,
        /// or in cleartext, `.{ .tls = false }`, and returns the handle that names it. Null when no TCP slot is
        /// free, after `shutdown`, when `protocols` allows no TCP protocol, or when chapulin
        /// refuses to start its session: the program closes the socket then.
        pub fn accept(engine: *Self, socket: Accepted, now_ns: u64) ?ConnectionHandle {
            return engine.state.accept(socket, now_ns);
        }

        /// Takes what `input` brings, then reports the next event any connection owes. The
        /// caller passes the octets each TCP socket read and each datagram the UDP socket read,
        /// and calls with `.none` after every call that changes a connection, until a call reports
        /// nothing: an answer, `cancel`, `send_stream`, `transport_closed`, `shutdown` and
        /// `on_instant`. Each leaves what follows it, a slot's release included, to the next
        /// `receive`. A TCP connection may consume less than it was given: the
        /// caller holds the rest and passes it again, with what the socket reads next, and after
        /// each event that names the connection, which may say it reads again, such as the `done`
        /// of an h11 response a pipelined request waited for. An event's slices stay
        /// valid until the next `receive`, `on_instant`, `send_stream`, `send_datagram`, `accept`,
        /// `transport_closed` or `shutdown`.
        pub fn receive(engine: *Self, input: Input, now_ns: u64) event.ReceiveResult {
            return engine.state.receive(input, now_ns);
        }

        /// Sets the word each later event of request `id` carries: its `body`, `trailers`,
        /// `writable` and its one `done` or `cancelled` (decision 119).
        pub fn set_user_data(engine: *Self, id: RequestId, user_data: usize) error{RequestUnknown}!void {
            return engine.state.set_user_data(id, user_data);
        }

        /// Writes the head of the response to request `id`: an interim one (1xx) or the final
        /// one. With `end`, the final response carries no content. `error.NoSpaceLeft` says the
        /// response has no room for it: its `writable` comes once it has.
        pub fn respond(engine: *Self, id: RequestId, response: event.Response) SendError!void {
            return engine.state.respond(id, response);
        }

        /// Takes content of the response to request `id`, and returns the octets taken. Nothing is
        /// copied over QUIC: the octets stay the caller's until the request is `done` or
        /// `cancelled` (decision 103). A take of less than `content`, or `error.Blocked`, says the
        /// response has no room for more: its `writable` comes once it has.
        pub fn write_body(engine: *Self, id: RequestId, content: event.ResponseBody) SendError!usize {
            return engine.state.write_body(id, content);
        }

        /// Ends the response to request `id` with a trailer section (RFC 9110 §6.5).
        /// `error.NoSpaceLeft`, or `error.Blocked` while a coded response's last octets wait, says
        /// the response has no room for it: its `writable` comes once it has.
        pub fn write_trailers(engine: *Self, id: RequestId, fields: []const http.Field) SendError!void {
            return engine.state.write_trailers(id, fields);
        }

        /// Ends request `id` before its response is whole: its `cancelled` follows, with the
        /// reason `program`, and nothing more of it.
        pub fn cancel(engine: *Self, id: RequestId) void {
            engine.state.cancel(id);
        }

        /// Ends every connection once the requests it holds are answered, and starts no new one.
        /// `closed` follows once every connection has ended.
        pub fn shutdown(engine: *Self, now_ns: u64) void {
            engine.state.shutdown(now_ns);
        }

        /// Writes into `output` what the TCP connection `connection` owes its socket, and returns
        /// the octets written: 0 for a handle that names no connection. The engine reports a
        /// `send` when a connection owes octets no call has taken. A program may also call this
        /// for an open connection at any time, such as straight after it writes a response, which
        /// sends before the connection is read again. A call that fills `output` leaves more
        /// owed, and the caller calls again. One that leaves room ends the `send`: the engine
        /// reports another once the connection owes more, at once when a record's overhead did
        /// not fit the room left.
        pub fn send_stream(engine: *Self, connection: ConnectionHandle, output: []u8, now_ns: u64) usize {
            return engine.state.send_stream(connection, output, now_ns);
        }

        /// The socket of the TCP connection `connection` closed before the engine reported its
        /// `close`: the peer closed it, or it failed. The `done` of each response written whole,
        /// the `cancelled` of each other request, and the connection's `ended` follow. After a
        /// `close` the program closes the socket and owes no call: `ended` follows by itself, and
        /// this call changes nothing.
        pub fn transport_closed(engine: *Self, connection: ConnectionHandle) void {
            engine.state.transport_closed(connection);
        }

        /// Writes into `output` the next datagram the engine owes, and names where it goes. Null
        /// when it owes none.
        pub fn send_datagram(engine: *Self, output: []u8, now_ns: u64) ?Sent {
            return engine.state.send_datagram(output, now_ns);
        }

        /// The soonest instant any connection wants `on_instant` at (design §4.2), or null.
        pub fn deadline_ns(engine: *Self) ?u64 {
            return engine.state.deadline_ns();
        }

        /// Fires whichever deadlines `now_ns` has reached.
        pub fn on_instant(engine: *Self, now_ns: u64) void {
            engine.state.on_instant(now_ns);
        }

        /// Replaces one connection's limits (decision 110), for a caller short of connections that
        /// shortens its deadlines.
        pub fn set_timeouts(engine: *Self, connection: ConnectionHandle, deadlines: deadline.Timeouts) error{ TimeoutInvalid, ConnectionUnknown }!void {
            return engine.state.set_timeouts(connection, deadlines);
        }

        /// The server_name the connection's client sent (RFC 9846 §9.2), or null.
        pub fn server_name(engine: *Self, connection: ConnectionHandle) ?[]const u8 {
            return engine.state.server_name(connection);
        }
    };
}

test "design §8 step 17f: the engine's public functions are the calls a program makes" {
    const public_names = @import("core").public_names;
    // Design §8 step 21b.3 (decision 119): the engine answers requests by id.
    // Design §8 step 21b.4 adds `accept`, `send_stream` and `transport_closed` (decision 119).
    // Decision 158 ruling 6 adds `Accepted`, the type `accept` takes.
    try public_names.expect(Engine(.{}), &.{
        "Accepted",      "init",           "accept",     "receive",      "set_user_data", "respond",
        "write_body",    "write_trailers", "cancel",     "shutdown",     "send_stream",   "transport_closed",
        "send_datagram", "deadline_ns",    "on_instant", "set_timeouts", "server_name",
    });
}
