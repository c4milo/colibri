//! Static memory per connection (design §8 step 13b, §11.2): the size of each struct a caller holds
//! for one connection, taken from the code being built and never estimated, as chapulin's
//! `bench/sram.sh` measures its rows. `zig build bench-memory` prints the table, and the test
//! requires `docs/performance.md` to hold the same table, so a struct that changes size changes
//! the document in the same commit.
const std = @import("std");
const server = @import("server");
const client = @import("client");
const h11 = @import("h11");
const h2 = @import("h2");
const h3 = @import("h3");
const quic = @import("quic");
const tls = @import("tls");
const options = @import("options");
const performance_md = @embedFile("performance_md");

/// The line the table follows in `docs/performance.md`, naming the objects its sizes come from by
/// chapulin's `AES` value. x86-64 and arm64 build `AES=runtime` (decision 97 as amended); a target
/// whose objects are built otherwise holds sessions of other sizes, and prints another heading
/// that the document holds no table under.
const heading = "With chapulin's objects built `AES=" ++ options.aes ++ "`:\n\n";

/// One row: a struct a caller holds per connection, and what it holds.
const Row = struct {
    name: []const u8,
    size: usize,
    holds: []const u8,
};

const rows = [_]Row{
    .{ .name = "server.Connection", .size = @sizeOf(server.Connection), .holds = "one TCP connection: h11 or h2, in cleartext or over TLS" },
    .{ .name = "server.QuicConnection", .size = @sizeOf(server.QuicConnection), .holds = "one h3 connection, without its receive pool" },
    .{ .name = "client.Connection", .size = @sizeOf(client.Connection), .holds = "one TCP connection: h11 or h2, in cleartext or over TLS" },
    .{ .name = "client.QuicConnection", .size = @sizeOf(client.QuicConnection), .holds = "one h3 connection, without its receive pool" },
    .{ .name = "client.Channel", .size = @sizeOf(client.Channel), .holds = "one server's connections, QUIC first and TCP after, without receive pools" },
    .{ .name = "client.DefaultReceivePool", .size = @sizeOf(client.DefaultReceivePool), .holds = "the receive pool a QUIC connection's caller passes, at its default capacity" },
    .{ .name = "h11.connection.Connection", .size = @sizeOf(h11.connection.Connection), .holds = "the h11 state inside a TCP connection" },
    .{ .name = "h2.Connection", .size = @sizeOf(h2.Connection), .holds = "the h2 state inside a TCP connection" },
    .{ .name = "h3.Connection", .size = @sizeOf(h3.Connection), .holds = "the h3 state inside a QUIC connection" },
    .{ .name = "quic.Connection", .size = @sizeOf(quic.Connection), .holds = "the QUIC state inside an h3 connection" },
    .{ .name = "tls.record.Client", .size = @sizeOf(tls.record.Client), .holds = "a TLS client session over TCP" },
    .{ .name = "tls.record.Server", .size = @sizeOf(tls.record.Server), .holds = "a TLS server session over TCP" },
    .{ .name = "tls.quic.Client", .size = @sizeOf(tls.quic.Client), .holds = "a TLS client session inside QUIC" },
    .{ .name = "tls.quic.Server", .size = @sizeOf(tls.quic.Server), .holds = "a TLS server session inside QUIC" },
};

/// The longest table `write_table` writes: every row's line, with room for its size's digits.
const table_len_max: usize = 4096;

/// Writes the table in the Markdown `docs/performance.md` holds.
fn write_table(output: []u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(output);
    try writer.writeAll(heading);
    try writer.writeAll("| Struct | Bytes | What it holds |\n| --- | ---: | --- |\n");
    for (rows) |row| try writer.print("| `{s}` | {d} | {s} |\n", .{ row.name, row.size, row.holds });
    return writer.buffered();
}

pub fn main() !void {
    var output: [table_len_max]u8 = undefined;
    std.debug.print("{s}", .{try write_table(&output)});
}

/// chapulin's one hook, which every program that links `tls` defines (decision 94): a failed
/// chapulin assertion ends the program. This one builds no session, so it never runs.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

test "docs/performance.md holds the table this build prints" {
    var output: [table_len_max]u8 = undefined;
    const table = try write_table(&output);
    std.testing.expect(std.mem.indexOf(u8, performance_md, table) != null) catch |failure| {
        std.debug.print("docs/performance.md's memory table differs from this build's:\n{s}", .{table});
        return failure;
    };
}
