//! colibri's networked server and client (decisions 150, 153 and 159), over the sans-I/O modules
//! underneath it. A program writes `colibri.Server(capacity, kind)`, gives it an identity and a
//! router, and serves. It writes `colibri.Client(capacity, kind)`, gives it a destination, a
//! pool's configuration and a handler, and hands it requests. Each object is a driver, which does
//! no I/O, and a host, which does each operation the driver writes:
//! - `.private` runs on colibri's own Rotor host (`rotor_host.zig`), which binds and runs one loop
//!   on the thread that calls `run` (decision 150 ruling 7). Rotor is a lazy package: a dependent's
//!   build passes `.rotor = true` to get it, and `.private` does not compile without it;
//! - `.hosted` runs on the program's loop, which calls `turn` and `complete` with the seven types
//!   from `SocketId` to `Turn`.
//!
//! `colibri` is the one module that the package exports (decision 170). The root names each of
//! the sixteen other library modules, so a program imports `colibri` alone and writes
//! `colibri.server.Router`, `colibri.tls.Client` or `colibri.h2.Connection`. It names nothing of
//! stdx: a program depends on stdx itself for `platform` and for the `crypto.Context` its TLS
//! values hold (decisions 97 as amended and 175).
pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const tls_provider = @import("tls_provider");
pub const tls = @import("tls");
pub const dnssec = @import("dnssec");
pub const crypto = @import("crypto");
pub const qlog = @import("qlog");
pub const hpack = @import("hpack");
pub const qpack = @import("qpack");
pub const quic = @import("quic");
pub const h2 = @import("h2");
pub const h3 = @import("h3");
pub const h11 = @import("h11");
pub const server = @import("server");
pub const client = @import("client");
pub const constants = @import("constants.zig");

const files = struct {
    const rotor_present = @import("host.zig").rotor_present;

    pub const client = @import("client.zig");
    pub const client_fetch = @import("client_fetch.zig");
    pub const client_kinds = @import("client_kinds.zig");
    pub const client_loop = @import("client_loop.zig");
    pub const client_tcp = @import("client_tcp.zig");
    pub const client_udp = @import("client_udp.zig");
    pub const erased = @import("erased.zig");
    pub const errors = @import("errors.zig");
    pub const host = @import("host.zig");
    pub const identity = @import("identity.zig");
    pub const operation_table = @import("operation_table.zig");
    // colibri's own Rotor host, which only a build with Rotor compiles (decision 159). Zig does
    // not analyse the branch that it does not take.
    pub const rotor_host = if (rotor_present) @import("rotor_host.zig") else void;
    pub const rotor_host_end = if (rotor_present) @import("rotor_host_end.zig") else void;
    pub const rotor_host_entropy = if (rotor_present) @import("rotor_host_entropy.zig") else void;
    pub const rotor_host_submit = if (rotor_present) @import("rotor_host_submit.zig") else void;
    pub const rotor_host_udp = if (rotor_present) @import("rotor_host_udp.zig") else void;
    pub const server = @import("server.zig");
    pub const server_bind = @import("server_bind.zig");
    pub const server_kinds = @import("server_kinds.zig");
    pub const server_loop = @import("server_loop.zig");
    pub const server_pump = @import("server_pump.zig");
    pub const server_udp = @import("server_udp.zig");
    pub const datagram_batch = @import("datagram_batch.zig");
    pub const datagram_socket = @import("datagram_socket.zig");
    pub const socket = @import("socket.zig");
    pub const socket_output = @import("socket_output.zig");
};

pub const Server = files.server.Server;
pub const ServerConfig = files.server.ServerConfig;
pub const Identity = files.identity.Identity;
pub const InitError = files.server.InitError;
pub const RunError = files.server.RunError;
pub const Client = files.client.Client;
pub const ClientCapacity = files.client.ClientCapacity;
pub const ClientConfig = files.client.ClientConfig;
pub const SocketId = files.host.SocketId;
pub const OperationId = files.host.OperationId;
pub const Operation = files.host.Operation;
pub const Completion = files.host.Completion;
pub const Failure = files.host.Failure;
pub const Wait = files.host.Wait;
pub const Turn = files.host.Turn;

comptime {
    // A program that imports `colibri` links chapulin's objects through `tls` and `dnssec`, though
    // it may name neither. Zig analyses a file only when something references it, so these
    // references run each root's comptime block, which keeps chapulin's `ch_assert_fail`
    // (decision 172).
    _ = tls;
    _ = dnssec;
}

test "decision 115: the root exports the names design §8 steps 37, 42, 44 and 73 list" {
    // Step 37a adds `Server`, `ServerConfig`, `Identity` and `InitError`, and 37b `RunError`.
    // Step 42c adds `Client` and `ClientConfig`, and the owner's rulings of 2026-11-06 add
    // `ClientCapacity` (decision 153 ruling 9). Step 44d makes `Server` and `Client` type
    // functions of a capacity and a kind, removes `ServerOf` and `ClientOf` (decision 156 ruling
    // 1), and adds the seven types of the host's contract (decision 159). Step 44i re-exports
    // the modules `client` and `server` (decision 156 ruling 14). Step 73 re-exports the
    // fourteen other library modules, since the package exports `colibri` alone (decision 170).
    const public_names = core.public_names;
    try public_names.expect(@This(), &.{
        "core",         "wire",     "http",        "tls_provider", "tls",        "dnssec",
        "crypto",       "qlog",     "hpack",       "qpack",        "quic",       "h2",
        "h3",           "h11",      "server",      "client",       "constants",  "Server",
        "ServerConfig", "Identity", "InitError",   "RunError",     "Client",     "ClientCapacity",
        "ClientConfig", "SocketId", "OperationId", "Operation",    "Completion", "Failure",
        "Wait",         "Turn",
    });
    // Each re-export is the module itself, so a type has one identity by either path.
    const testing = @import("std").testing;
    const modules = .{
        .{ core, @import("core") },                 .{ wire, @import("wire") }, .{ http, @import("http") },
        .{ tls_provider, @import("tls_provider") }, .{ tls, @import("tls") },   .{ dnssec, @import("dnssec") },
        .{ crypto, @import("crypto") },             .{ qlog, @import("qlog") }, .{ hpack, @import("hpack") },
        .{ qpack, @import("qpack") },               .{ quic, @import("quic") }, .{ h2, @import("h2") },
        .{ h3, @import("h3") },                     .{ h11, @import("h11") },   .{ server, @import("server") },
        .{ client, @import("client") },
    };
    inline for (modules) |pair| try testing.expect(pair[0] == pair[1]);
    // The owner's ruling 7 of 2026-11-10 adds `InitError` (decision 159 as amended).
    const server_names = &.{ "InitError", "operations_max", "sockets_max", "listener", "datagram", "init", "deinit", "port", "run", "turn", "complete", "set_ticket_key", "shutdown", "stopped" };
    try public_names.expect(Server(.{}, .private), server_names);
    try public_names.expect(Server(.{}, .hosted), server_names);
    // Step 44f adds the second UDP socket, 44g `set_destination`, and 44h `fetch`, `cancel` and
    // their types.
    const client_names = &.{ "InitError", "RunError", "FetchOptions", "FetchResult", "FetchError", "operations_max", "sockets_max", "datagram_ipv4", "datagram_ipv6", "init", "deinit", "request", "fetch", "cancel", "set_destination", "run", "turn", "complete", "shutdown", "stopped" };
    try public_names.expect(Client(.{}, .private), client_names);
    try public_names.expect(Client(.{}, .hosted), client_names);
}

test {
    @import("std").testing.refAllDecls(files);
    _ = constants;
}
