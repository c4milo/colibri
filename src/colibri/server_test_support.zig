//! The server that `server.zig`'s tests place, outside any stack frame. Test-only.
//!
//! The server is not `threadlocal`. glibc places the static TLS of each new thread on that
//! thread's stack, and `pthread_create` returns EINVAL when the stack cannot hold it. The default
//! server is about 52 MB, and `std.Thread.spawn` asks for a stack of 16 MiB. So a `threadlocal`
//! server stops each test of this module that spawns a thread, on Linux only.
const server_module = @import("server.zig");

const Server = server_module.Server;

pub var test_server: Server align(@alignOf(Server)) = undefined;
