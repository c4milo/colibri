//! What each kind of `colibri.Client` does at `init` and at `deinit` (decision 159). `private`
//! opens its UDP socket through colibri's own Rotor host. `hosted` takes the UDP socket that the
//! program's host opened for the destination's family. `client.zig` picks one by the kind's name,
//! so the type function holds no branch for the kind.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const tls = @import("tls");
const client_module = @import("client.zig");
const client_loop = @import("client_loop.zig");
const errors = @import("errors.zig");
const host = @import("host.zig");
const rotor_host = @import("rotor_host.zig");
const entropy = @import("rotor_host_entropy.zig");

const Family = client_loop.Family;

/// A client on colibri's own Rotor loop.
pub const private = struct {
    pub const Config = client_module.ClientConfig;
    pub const InitError = errors.ClientInitError;
    pub const RunError = errors.LoopError;
    pub const Host = rotor_host.Host;

    /// Starts the pool, and opens a UDP socket of each family when the pool offers QUIC
    /// (decision 156 ruling 13). The bind of the destination's family must succeed. A family that
    /// the system refuses for another one stays closed.
    pub fn init(state: anytype, config: *const Config, family: Family) InitError!void {
        state.host.prepare();
        state.random = config.random orelse entropy.random();
        // Decision 68: the client's host reads each datagram's codepoint and sets the one the
        // pool names, so the pool reads ECN whatever the program set. A pool that does not read
        // it halts on a datagram marked ECT(0), as a `colibri.Server` marks them.
        state.pool_config.ecn = true;
        state.datagram_segments = true;
        try start_pool(state, config.port);
        if (!state.pool.offered.quic) return;
        try bind(state, family);
        const other: Family = if (family == .ipv4) .ipv6 else .ipv4;
        bind(state, other) catch {};
    }

    /// Opens the UDP socket of `family` on every interface, on a port the system chooses.
    fn bind(state: anytype, family: Family) errors.BindError!void {
        const id = client_loop.datagram_id(state.sockets.len, family);
        try state.host.bind_datagram_any(id, family);
        state.udp.open(@intFromEnum(family), id);
    }

    /// Closes the UDP socket when `run` did not close it.
    pub fn deinit(state: anytype) void {
        state.host.close_open();
    }
};

/// A client on the program's loop.
pub const hosted = struct {
    /// What a `.hosted` client connects to (decision 159). It is `ClientConfig` plus the UDP
    /// sockets that the host opened before `init`. A program writes it as a literal, so it has no
    /// public name (decision 156 ruling 2).
    pub const Config = struct {
        host: []const u8,
        port: u16 = 443,
        /// The pool's configuration. `init` sets its `ecn` from the UDP socket's `Features`.
        pool: client.Config,
        /// The program's source. A hosted client has no default (decision 150 ruling 9 as
        /// amended).
        random: tls.Random,
        /// The seconds since 1970 at the instant of the first `turn`.
        unix_seconds: u64,
        /// One UDP socket for each family. A family that the host could not open stays null, and
        /// the pool falls back to TCP for it (decision 156 ruling 13).
        datagram: struct { ipv4: ?host.Features = null, ipv6: ?host.Features = null } = .{},
    };

    /// The pool's refusals, and a `host` that is no IP literal. A hosted client binds nothing.
    pub const InitError = client.StartError || error{HostInvalid};
    /// A hosted client has no run, so the set is empty.
    pub const RunError = error{};

    /// A hosted client has no host of colibri's.
    pub fn Host(comptime _: u16, comptime _: u32, comptime _: bool) type {
        return void;
    }

    /// Takes the UDP socket of each family that the host opened. With no socket of the
    /// destination's family the pool offers no QUIC, and opens TCP (decision 156 ruling 13). The
    /// pool's ECN and the segments follow the `Features` of the destination's family.
    pub fn init(state: anytype, config: *const Config, family: Family) InitError!void {
        state.random = config.random;
        const features = switch (family) {
            .ipv4 => config.datagram.ipv4,
            .ipv6 => config.datagram.ipv6,
        };
        if (features == null) state.pool_config.protocols.h3 = false;
        // Decision 159: a host that cannot read the codepoint leaves the pool's ECN off, so it
        // never halts on ECT(0) (decision 68 as amended).
        state.pool_config.ecn = if (features) |held| held.ecn else false;
        state.datagram_segments = if (features) |held| held.segments else false;
        try start_pool(state, config.port);
        if (!state.pool.offered.quic) return;
        assert(features != null);
        if (config.datagram.ipv4 != null) state.udp.open(@intFromEnum(Family.ipv4), client_loop.datagram_id(state.sockets.len, .ipv4));
        if (config.datagram.ipv6 != null) state.udp.open(@intFromEnum(Family.ipv6), client_loop.datagram_id(state.sockets.len, .ipv6));
    }

    /// A host calls `deinit` once `stopped()` holds (decision 159, rule 2). Before it, an
    /// operation may still name the client's memory, so the client halts.
    pub fn deinit(state: anytype) void {
        if (!client_loop.finished(state)) std.debug.panic("colibri: deinit of a .hosted object before stopped() (decision 159, rule 2)", .{});
    }
};

/// Starts the pool on the destination's address and `port`, with the receive pool its QUIC
/// connections use, or none for a client with no QUIC.
fn start_pool(state: anytype, port: u16) client.StartError!void {
    const destination: client.Destination = .{ .addresses = &state.addresses, .port = port };
    const storage: ?client.ReceiveStorage = if (@TypeOf(state.receive_pool) == void) null else state.receive_pool.storage();
    try state.pool.init(&state.pool_memory, &state.pool_config, destination, storage);
}
