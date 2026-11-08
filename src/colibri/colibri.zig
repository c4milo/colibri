//! colibri's networked server and client (decisions 150, 153 and 159), over the sans-I/O modules
//! underneath it. A program writes `colibri.Server(capacity, kind)`, gives it an identity and a
//! router, and serves. It writes `colibri.Client(capacity, kind)`, gives it a host, a port, a
//! pool's configuration and a handler, and hands it requests. Each object is a driver, which does
//! no I/O, and a host, which does each operation the driver writes:
//! - `.private` runs on colibri's own Rotor host (`rotor_host.zig`), which binds and runs one loop
//!   on the thread that calls `run` (decision 150 ruling 7);
//! - `.hosted` runs on the program's loop, which calls `turn` and `complete` with the seven types
//!   from `SocketId` to `Turn`.
pub const constants = @import("constants.zig");

const files = struct {
    pub const client = @import("client.zig");
    pub const client_kinds = @import("client_kinds.zig");
    pub const client_loop = @import("client_loop.zig");
    pub const client_tcp = @import("client_tcp.zig");
    pub const client_udp = @import("client_udp.zig");
    pub const erased = @import("erased.zig");
    pub const errors = @import("errors.zig");
    pub const host = @import("host.zig");
    pub const identity = @import("identity.zig");
    pub const operation_table = @import("operation_table.zig");
    pub const rotor_host = @import("rotor_host.zig");
    pub const rotor_host_end = @import("rotor_host_end.zig");
    pub const rotor_host_entropy = @import("rotor_host_entropy.zig");
    pub const rotor_host_submit = @import("rotor_host_submit.zig");
    pub const rotor_host_udp = @import("rotor_host_udp.zig");
    pub const server = @import("server.zig");
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
    // 1), and adds the seven types of the host's contract (decision 159).
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants",   "Server",    "ServerConfig",   "Identity",     "InitError",
        "RunError",    "Client",    "ClientCapacity", "ClientConfig", "SocketId",
        "OperationId", "Operation", "Completion",     "Failure",      "Wait",
        "Turn",
    });
    const server_names = &.{ "operations_max", "sockets_max", "listener", "datagram", "init", "deinit", "port", "run", "turn", "complete", "shutdown", "stopped" };
    try public_names.expect(Server(.{}, .private), server_names);
    try public_names.expect(Server(.{}, .hosted), server_names);
    // Step 44f adds the second UDP socket, and 44g, 44h and 44i the rest of decision 159's list.
    const client_names = &.{ "InitError", "RunError", "operations_max", "sockets_max", "datagram_ipv4", "datagram_ipv6", "init", "deinit", "request", "run", "turn", "complete", "shutdown", "stopped" };
    try public_names.expect(Client(.{}, .private), client_names);
    try public_names.expect(Client(.{}, .hosted), client_names);
}

test {
    @import("std").testing.refAllDecls(files);
    _ = constants;
    _ = @import("test_hooks.zig");
}
