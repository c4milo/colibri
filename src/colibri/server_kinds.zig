//! What each kind of `colibri.Server` does at `init` and at `deinit` (decision 159). `private`
//! binds through colibri's own Rotor host. `hosted` takes the sockets that the program's host
//! opened, and starts the engine. `server.zig` picks one by the kind's name, so the type function
//! holds no branch for the kind.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const tls = @import("tls");
const identity_module = @import("identity.zig");
const server_module = @import("server.zig");
const server_loop = @import("server_loop.zig");
const server_udp = @import("server_udp.zig");
const server_bind = @import("server_bind.zig");
const host = @import("host.zig");
const rotor_host = @import("rotor_host.zig");
const entropy = @import("rotor_host_entropy.zig");

const Identity = identity_module.Identity;

/// A server on colibri's own Rotor loop.
pub const private = struct {
    pub const Config = server_module.ServerConfig;
    pub const InitError = server_module.InitError;
    pub const Host = rotor_host.Host;

    /// Reads the identity, binds the listener, and opens the UDP socket on the listener's port
    /// when the server serves h3.
    pub fn init(state: anytype, config: *const Config, quic_slots: bool) InitError!void {
        const listener = @TypeOf(state.*).listener;
        state.host.prepare();
        state.random = config.random orelse entropy.random();
        // Decision 68: the server's own host reads each datagram's codepoint and sets the one the
        // engine names, so the engine reads ECN whatever the program set.
        state.engine_config.ecn = true;
        state.listening = true;
        state.datagram_segments = true;
        // Decision 161: `run` starts the engine at these Unix seconds, which its tickets carry.
        state.unix_seconds = config.unix_seconds;
        // A server that `init` does not return keeps no private key, cookie key or ticket key.
        errdefer server_module.wipe_keys(state);
        try load(state, config.identity, config.cpu, .{ .current = config.ticket_key, .previous = config.ticket_key_previous });
        const h3 = server_udp.served(quic_slots, config.identity != null);
        try server_bind.bind(&state.host, listener, @TypeOf(state.*).datagram, config.host, config.port, h3);
        errdefer state.host.close_open();
        if (h3) server_udp.opened(state, state.host.bound_port);
    }

    /// Closes the listener and the UDP socket when `run` did not close them.
    pub fn deinit(state: anytype) void {
        state.host.close_open();
    }
};

/// A server on the program's loop.
pub const hosted = struct {
    /// What a `.hosted` server serves (decision 159). It is `ServerConfig` with the fields of the
    /// bind removed, plus the sockets that the host opened before `init`. A program writes it as
    /// a literal, so it has no public name (decision 156 ruling 2).
    pub const Config = struct {
        identity: ?Identity = null,
        cpu: tls.Cpu,
        /// The program's source. A hosted server has no default (decision 150 ruling 9 as
        /// amended).
        random: tls.Random,
        /// Two readings of the instant of `init`, which the program reads from its clocks. The
        /// engine starts at it: its deadlines count on the host's monotonic clock, which every
        /// later call passes, and with a ticket key its tickets carry the Unix seconds (decision
        /// 159 as amended on 2026-11-10). It has no default, because no instant is right to
        /// assume.
        now: server.Timestamp,
        /// The key the server seals its session tickets under, which it copies, or null to draw
        /// one from `random` (decision 161). The server wipes its copy at `deinit`.
        ticket_key: ?[tls.constants.protocol.server_key_len]u8 = null,
        /// The key the server sealed its tickets under before `ticket_key`, as
        /// `ServerConfig.ticket_key_previous` is (decision 161 as amended).
        ticket_key_previous: ?[tls.constants.protocol.server_key_len]u8 = null,
        /// What the engine starts from. `colibri` fills its `tls` from `identity`, and sets its
        /// `ecn` from the UDP socket's `Features`. The host knows its port, so the program names
        /// the h3 alternative in `h3_alternative` itself (RFC 7838 §3).
        engine: server.Config = .{},
        sockets: struct {
            /// The host opened the TCP listener `listener`.
            listener: bool = true,
            /// The host opened the UDP socket `datagram`, and what it does on it.
            datagram: ?host.Features = null,
        } = .{},
    };

    /// The identity's PEM text refused, or the engine's start refused.
    pub const InitError = identity_module.LoadError || server.StartError;

    /// A hosted server has no host of colibri's.
    pub fn Host(comptime _: u16, comptime _: u32, comptime _: bool) type {
        return void;
    }

    /// Reads the identity and starts the engine at `config.now` (non-negotiable 3).
    pub fn init(state: anytype, config: *const Config, quic_slots: bool) InitError!void {
        state.random = config.random;
        state.listening = config.sockets.listener;
        const features = config.sockets.datagram;
        // Decision 159: a host that cannot read the codepoint leaves the engine's ECN off, so it
        // never halts on ECT(0) (decision 68 as amended).
        state.engine_config.ecn = if (features) |held| held.ecn else false;
        state.datagram_segments = if (features) |held| held.segments else false;
        errdefer server_module.wipe_keys(state);
        state.unix_seconds = config.now.unix_seconds;
        try load(state, config.identity, config.cpu, .{ .current = config.ticket_key, .previous = config.ticket_key_previous });
        if (server_udp.served(quic_slots and features != null, config.identity != null)) state.udp.open(0, @TypeOf(state.*).datagram);
        try server_loop.start(state, config.now);
    }

    /// A host calls `deinit` once `stopped()` holds (decision 159, rule 2). Before it, an
    /// operation may still name the server's memory, so the server halts.
    pub fn deinit(state: anytype) void {
        if (!server_loop.finished(state)) std.debug.panic("colibri: deinit of a .hosted object before stopped() (decision 159, rule 2)", .{});
    }
};

/// Reads `identity`, when the program gave one, into the engine's TLS values, with the ticket keys.
fn load(state: anytype, identity: ?Identity, cpu: tls.Cpu, keys: identity_module.TicketKeys) identity_module.LoadError!void {
    assert(state.engine_config.tls == null);
    const held = identity orelse return;
    state.engine_config.tls = try identity_module.load(held, &state.identity, cpu, state.random, keys);
}
