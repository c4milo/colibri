//! http.zig, one of the h11 servers colibri's is measured against (design §8 step 13g), as
//! `bench/run.sh --competitors` starts it: one worker and one handler thread, on the core run.sh
//! pins the process to, answering every request with the answer of colibri's test-only server.
//! http.zig has no TLS, so it serves the cleartext h11 inputs alone.
//!
//!   colibri-bench-httpz --port <port>
const std = @import("std");
const httpz = @import("httpz");

/// One thread that reads connections and one that answers, as nginx and h2o run one worker each.
const workers: u16 = 1;
const handler_threads: u16 = 1;
/// The program's name, `--port` and the port, and where each stands.
const arguments_len: usize = 3;
const flag_index: usize = 1;
const port_index: usize = 2;
const usage_status: u8 = 2;
const decimal: u8 = 10;
const ok: u16 = 200;

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len != arguments_len or !std.mem.eql(u8, arguments[flag_index], "--port")) {
        std.debug.print("usage: colibri-bench-httpz --port <port>\n", .{});
        std.process.exit(usage_status);
    }
    const port = try std.fmt.parseInt(u16, arguments[port_index], decimal);
    var server = try httpz.Server(void).init(init.io, init.gpa, .{
        .address = .localhost(port),
        .workers = .{ .count = workers },
        .thread_pool = .{ .count = handler_threads },
    }, {});
    defer server.deinit();
    var router = try server.router(.{});
    router.get("/", answer, .{});
    try server.listen();
}

/// The answer to every request: what colibri's test-only server sends.
fn answer(_: *httpz.Request, response: *httpz.Response) !void {
    response.status = ok;
    response.header("content-type", "text/plain; charset=utf-8");
    response.body = "colibri\n";
}
