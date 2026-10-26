//! http.zig, one of the h11 servers colibri's is measured against (design §8 step 13g), as
//! `bench/run.sh --competitors` starts it: one worker and one handler thread, on the core run.sh
//! pins the process to, answering every request with the answer of colibri's test-only server.
//! http.zig has no TLS, so it serves the cleartext h11 inputs alone. With `--routes`, it registers
//! the routes of the file with its router instead, and answers each with 200 and "ok\n", for the
//! request benchmark of design §8 step 13f.
//!
//!   colibri-bench-httpz --port <port> [--routes <routes file>]
const std = @import("std");
const httpz = @import("httpz");

/// One thread that reads connections and one that answers, as nginx and h2o run one worker each.
const workers: u16 = 1;
const handler_threads: u16 = 1;
/// The program's name, `--port` and the port, then `--routes` and its file, and where each stands.
const arguments_len: usize = 3;
const routed_arguments_len: usize = 5;
const flag_index: usize = 1;
const port_index: usize = 2;
const routes_flag_index: usize = 3;
const routes_index: usize = 4;
/// The largest routes file the server reads.
const routes_len_max: usize = 1 << 20;
const usage_status: u8 = 2;
const decimal: u8 = 10;
const ok: u16 = 200;

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    const routed = arguments.len == routed_arguments_len and std.mem.eql(u8, arguments[routes_flag_index], "--routes");
    if ((arguments.len != arguments_len and !routed) or !std.mem.eql(u8, arguments[flag_index], "--port")) {
        std.debug.print("usage: colibri-bench-httpz --port <port> [--routes <routes file>]\n", .{});
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
    if (routed) {
        const text = try std.Io.Dir.cwd().readFileAlloc(init.io, arguments[routes_index], init.arena.allocator(), .limited(routes_len_max));
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.RouteInvalid;
            const method = std.meta.stringToEnum(httpz.Method, line[0..space]) orelse return error.RouteInvalid;
            const path = line[space + 1 ..];
            switch (method) {
                .GET => router.get(path, answer_routed, .{}),
                .POST => router.post(path, answer_routed, .{}),
                .PUT => router.put(path, answer_routed, .{}),
                .DELETE => router.delete(path, answer_routed, .{}),
                else => return error.RouteInvalid,
            }
        }
    } else {
        router.get("/", answer, .{});
    }
    try server.listen();
}

/// The answer to every route of the request benchmark (design §8 step 13f).
fn answer_routed(_: *httpz.Request, response: *httpz.Response) !void {
    response.status = ok;
    response.header("content-type", "text/plain; charset=utf-8");
    response.body = "ok\n";
}

/// The answer to every request: what colibri's test-only server sends.
fn answer(_: *httpz.Request, response: *httpz.Response) !void {
    response.status = ok;
    response.header("content-type", "text/plain; charset=utf-8");
    response.body = "colibri\n";
}
