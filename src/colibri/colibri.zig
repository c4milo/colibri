//! colibri's networked server (decision 150): the one module that binds sockets and runs a loop,
//! over the sans-I/O modules underneath it. A program writes `colibri.Server`, gives it a host, a
//! port, an identity and a router, and calls `run`. It runs on Rotor's own loop (rulings 6 and
//! 10), one loop on the thread that calls `run` (ruling 7).
pub const constants = @import("constants.zig");

const files = struct {
    pub const entropy = @import("entropy.zig");
    pub const identity = @import("identity.zig");
    pub const identity_files = @import("identity_files.zig");
    pub const server = @import("server.zig");
    pub const server_loop = @import("server_loop.zig");
    pub const server_pump = @import("server_pump.zig");
    pub const server_udp = @import("server_udp.zig");
    pub const datagram_batch = @import("datagram_batch.zig");
    pub const socket = @import("socket.zig");
};

pub const Server = files.server.Server;
pub const ServerOf = files.server.ServerOf;
pub const ServerConfig = files.server.ServerConfig;
pub const Identity = files.identity.Identity;
pub const InitError = files.server.InitError;
pub const RunError = files.server.RunError;

test "decision 115: the root exports the names design §8 step 37 lists" {
    // Step 37a adds `Server`, `ServerOf`, `ServerConfig`, `Identity` and `InitError`, and 37b
    // `RunError` and `run`, `port` and `shutdown`.
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{ "constants", "Server", "ServerOf", "ServerConfig", "Identity", "InitError", "RunError" });
    try public_names.expect(Server, &.{ "init", "port", "shutdown", "run" });
}

test {
    @import("std").testing.refAllDecls(files);
    _ = constants;
    _ = @import("test_hooks.zig");
}
