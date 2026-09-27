//! The program the consumer project builds: it reaches h11 and h2 through the modules colibri
//! exports, writes a request, and reads a response, which shows the modules link and run for a
//! project that depends on colibri.
const std = @import("std");
const h11 = @import("h11");
const h2 = @import("h2");

var client: h11.connection.Connection align(@alignOf(h11.connection.Connection)) = undefined;
var h2_client: h2.connection.Connection align(@alignOf(h2.connection.Connection)) = undefined;
var output: [4096]u8 = undefined;

pub fn main() !void {
    client.init(.client, .{});
    const head_len = try client.write_request(&output, "GET", "/", &.{
        .{ .name = "Host", .value = "example.test" },
    });
    if (!std.mem.startsWith(u8, output[0..head_len], "GET / HTTP/1.1\r\n")) return error.RequestWrong;
    const step = try client.receive("HTTP/1.1 204 No Content\r\n\r\n");
    const status = step.event.?.response.line.status.code;
    if (status != 204) return error.ResponseWrong;

    // h2's client preface starts with the 24 octets of RFC 9113 §3.4.
    h2_client.init(.client);
    const preface_len = h2_client.write_pending(&output, 0);
    if (!std.mem.startsWith(u8, output[0..preface_len], "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) return error.PrefaceWrong;
    std.debug.print("consumer: h11 and h2 link and run as a dependency\n", .{});
}
