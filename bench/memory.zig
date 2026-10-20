//! Static memory per connection (design §8 step 13b, §11.2). The table gives the size of each
//! struct a program places, and of the connection in each slot of an endpoint and in each transport
//! of a pool. An endpoint holds a server's connections (design §8 step 21b.6). Each size comes
//! from the code that the build compiles and is never estimated, as chapulin's `bench/sram.sh`
//! measures its rows. `zig build bench-memory` prints the table, and the test
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

/// The line the table follows in `docs/performance.md`, naming the objects its sizes come from:
/// chapulin's host objects, which x86-64 and arm64 build (decision 97 as amended), or its device
/// objects, which any other target builds. Those hold sessions of other sizes, and print another
/// heading that the document holds no table under.
const heading = "With chapulin's " ++ options.object ++ " objects:\n\n";

/// One row: a struct a program places, or the connection one of its fields holds, and what the
/// struct holds.
const Row = struct {
    name: []const u8,
    size: usize,
    holds: []const u8,
};

/// The endpoints of one TCP slot and of one QUIC slot. Each holds one connection and the
/// endpoint's fixed part: its TLS configurations and what its connections borrow.
const one_tcp: server.Capacity = .{ .tcp_connections = 1, .quic_connections = 0 };
const one_quic: server.Capacity = .{ .tcp_connections = 0, .quic_connections = 1 };

const rows = [_]Row{
    .{ .name = "server.Endpoint", .size = @sizeOf(server.Endpoint), .holds = "a server's connections at the default capacity: 16 over TCP, and 16 over QUIC with their receive pools" },
    .{ .name = "server.EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 })", .size = @sizeOf(server.EndpointOf(one_tcp)), .holds = "an endpoint that holds one TCP connection" },
    .{ .name = "server.EndpointOf(.{ .tcp_connections = 0, .quic_connections = 1 })", .size = @sizeOf(server.EndpointOf(one_quic)), .holds = "an endpoint that holds one QUIC connection, with its receive pool" },
    .{ .name = "std.meta.Elem(@FieldType(server.Endpoint, \"tcp\"))", .size = @sizeOf(std.meta.Elem(@FieldType(server.Endpoint, "tcp"))), .holds = "the connection each TCP slot of an endpoint holds: h11 or h2, in cleartext or over TLS" },
    .{ .name = "std.meta.Elem(@FieldType(server.Endpoint, \"quic\"))", .size = @sizeOf(std.meta.Elem(@FieldType(server.Endpoint, "quic"))), .holds = "the connection each QUIC slot of an endpoint holds, without its receive pool" },
    .{ .name = "std.meta.Elem(@FieldType(client.Pool, \"tcp\"))", .size = @sizeOf(std.meta.Elem(@FieldType(client.Pool, "tcp"))), .holds = "each TCP connection of a pool: h11 or h2, in cleartext or over TLS" },
    .{ .name = "std.meta.Elem(@FieldType(client.Pool, \"entries\"))", .size = @sizeOf(std.meta.Elem(@FieldType(client.Pool, "entries"))), .holds = "each exchange a pool holds at once" },
    .{ .name = "@FieldType(client.Pool, \"quic\")", .size = @sizeOf(@FieldType(client.Pool, "quic")), .holds = "a pool's QUIC connection, without its receive pool" },
    .{ .name = "client.Pool", .size = @sizeOf(client.Pool), .holds = "a pool's fixed part: its QUIC connection, its TLS configurations and its links" },
    .{ .name = "client.PoolOf(.{ .quic = false })", .size = @sizeOf(client.PoolOf(.{ .quic = false })), .holds = "the fixed part of a pool with no QUIC state" },
    .{ .name = "client.Pool.memory_bytes(.{})", .size = client.Pool.memory_bytes(.{}), .holds = "the memory a pool takes at the default counts: one TCP connection and 16 exchanges" },
    .{ .name = "client.DefaultReceivePool", .size = @sizeOf(client.DefaultReceivePool), .holds = "the receive pool a program passes to a pool, at its default capacity" },
    .{ .name = "h11.Connection", .size = @sizeOf(h11.Connection), .holds = "the h11 state inside a TCP connection" },
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
