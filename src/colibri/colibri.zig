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
//! The root re-exports the modules `client` and `server` (decision 156 ruling 14). So a program
//! that imports `colibri` writes `colibri.client.Request` and `colibri.server.Router`, and needs
//! no import of its own for either module.
pub const client = @import("client");
pub const server = @import("server");
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

test "decision 115: the root exports the names design §8 steps 37, 42 and 44 list" {
    // Step 37a adds `Server`, `ServerConfig`, `Identity` and `InitError`, and 37b `RunError`.
    // Step 42c adds `Client` and `ClientConfig`, and the owner's rulings of 2026-11-06 add
    // `ClientCapacity` (decision 153 ruling 9). Step 44d makes `Server` and `Client` type
    // functions of a capacity and a kind, removes `ServerOf` and `ClientOf` (decision 156 ruling
    // 1), and adds the seven types of the host's contract (decision 159). Step 44i re-exports
    // the modules `client` and `server` (decision 156 ruling 14).
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "client",      "server",    "constants",  "Server",         "ServerConfig", "Identity",
        "InitError",   "RunError",  "Client",     "ClientCapacity", "ClientConfig", "SocketId",
        "OperationId", "Operation", "Completion", "Failure",        "Wait",         "Turn",
    });
    // Each re-export is the module itself, so a type has one identity by either path.
    const testing = @import("std").testing;
    try testing.expect(client.Request == @import("client").Request);
    try testing.expect(server.Request == @import("server").Request);
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
    _ = @import("test_hooks.zig");
}
