//! colibri's networked server and client (decisions 150, 153 and 159): the one module that binds
//! sockets and runs a loop, over the sans-I/O modules underneath it. A program writes
//! `colibri.Server`, gives it a host, a port, an identity and a router, and calls `run`. It writes
//! `colibri.Client`, gives it a host, a port and a pool's configuration, and hands it requests.
//! Each object is a driver, which does no I/O, and a host, which does each operation the driver
//! writes. Each runs on colibri's own Rotor host (`rotor_host.zig`), one loop on the thread that
//! calls `run` (decision 150 ruling 7).
pub const constants = @import("constants.zig");

const files = struct {
    pub const client = @import("client.zig");
    pub const client_loop = @import("client_loop.zig");
    pub const client_tcp = @import("client_tcp.zig");
    pub const client_udp = @import("client_udp.zig");
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
    pub const server_loop = @import("server_loop.zig");
    pub const server_pump = @import("server_pump.zig");
    pub const server_udp = @import("server_udp.zig");
    pub const datagram_batch = @import("datagram_batch.zig");
    pub const datagram_socket = @import("datagram_socket.zig");
    pub const socket = @import("socket.zig");
};

pub const Server = files.server.Server;
pub const ServerOf = files.server.ServerOf;
pub const ServerConfig = files.server.ServerConfig;
pub const Identity = files.identity.Identity;
pub const InitError = files.server.InitError;
pub const RunError = files.server.RunError;
pub const Client = files.client.Client;
pub const ClientOf = files.client.ClientOf;
pub const ClientCapacity = files.client.ClientCapacity;
pub const ClientConfig = files.client.ClientConfig;

test "decision 115: the root exports the names design §8 steps 37 and 42 list" {
    // Step 37a adds `Server`, `ServerOf`, `ServerConfig`, `Identity` and `InitError`, 37b
    // `RunError` and `run`, `port` and `shutdown`, and the owner's ruling of 2026-11-05 `deinit`.
    // Step 42c adds `Client` and `ClientConfig`, with `init`, `deinit`, `request` and `shutdown`,
    // and 42d adds `run`. The owner's rulings of 2026-11-06 add `ClientOf` and `ClientCapacity`,
    // so a program sizes its client as it sizes its server (decision 153 ruling 9).
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{ "constants", "Server", "ServerOf", "ServerConfig", "Identity", "InitError", "RunError", "Client", "ClientOf", "ClientCapacity", "ClientConfig" });
    try public_names.expect(Server, &.{ "init", "deinit", "port", "shutdown", "run" });
    try public_names.expect(Client, &.{ "init", "deinit", "request", "shutdown", "run" });
}

test {
    @import("std").testing.refAllDecls(files);
    _ = constants;
    _ = @import("test_hooks.zig");
}
