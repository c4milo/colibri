//! colibri's networked server (decision 150): the one module that binds sockets and runs a loop,
//! over the sans-I/O modules underneath it. A program writes `colibri.Server`, gives it a host, a
//! port, an identity and a router, and calls `run`. It runs on Rotor's own loop until a program
//! can pass a `std.Io` (ruling 6), one loop on the thread that calls `run` (ruling 7).
pub const constants = @import("constants.zig");

const files = struct {
    pub const entropy = @import("entropy.zig");
    pub const identity = @import("identity.zig");
    pub const server = @import("server.zig");
};

pub const Server = files.server.Server;
pub const ServerOf = files.server.ServerOf;
pub const ServerConfig = files.server.ServerConfig;
pub const Identity = files.identity.Identity;
pub const InitError = files.server.InitError;

test "decision 115: the root exports the names design §8 step 37 lists" {
    // Step 37a adds `Server`, `ServerOf`, `ServerConfig`, `Identity` and `InitError`.
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{ "constants", "Server", "ServerOf", "ServerConfig", "Identity", "InitError" });
    try public_names.expect(Server, &.{"init"});
}

test {
    @import("std").testing.refAllDecls(files);
    _ = constants;
    _ = @import("test_hooks.zig");
}
