//! What the servers of the client trace run did that spec/tla/client_exchanges's state names
//! (decision 105): which connection's server processed each exchange, and how many did. A server
//! processes a request when it passes it to its application, which is what RFC 9114 §4.1.1 calls
//! "processed": one it answers or resets after reading it, and not one it rejects.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const limits = sim.constants.client_trace;

pub const Transport = enum { quic, tcp };

/// One connection of the run: its transport, and which of that transport's connections it is,
/// counting from 1.
pub const Connection = struct {
    transport: Transport,
    generation: u64,
};

pub const Ledger = struct {
    /// Servers that processed each exchange, and the connection whose server did last.
    processed: [limits.exchanges_max]u8,
    processed_by: [limits.exchanges_max]?Connection,
    /// GOAWAY frames the servers sent.
    goaways: u32,

    pub fn init(ledger: *Ledger) void {
        ledger.processed = @splat(0);
        ledger.processed_by = @splat(null);
        ledger.goaways = 0;
    }

    /// A server passed exchange `index`'s request to its application.
    pub fn process(ledger: *Ledger, index: usize, connection: Connection) void {
        assert(index < limits.exchanges_max);
        ledger.processed[index] += 1;
        ledger.processed_by[index] = connection;
    }

    /// Whether the server of `connection` processed exchange `index`.
    pub fn processed_on(ledger: *const Ledger, index: usize, connection: Connection) bool {
        const by = ledger.processed_by[index] orelse return false;
        return std.meta.eql(by, connection);
    }
};

/// The exchange index a request's path names: the run makes exchange `i` with path `/e/<i>`.
pub fn exchange_of(path: []const u8) ?usize {
    const prefix = "/e/";
    if (!std.mem.startsWith(u8, path, prefix)) return null;
    const index = std.fmt.parseInt(usize, path[prefix.len..], decimal_base) catch return null;
    return if (index < limits.exchanges_max) index else null;
}

const decimal_base: u8 = 10;

/// The path exchange `index` goes out with.
pub fn path_of(index: usize, storage: []u8) []const u8 {
    return std.fmt.bufPrint(storage, "/e/{d}", .{index}) catch unreachable;
}

const testing = std.testing;

test "an exchange's path names its index, and a path that names none is no exchange" {
    var storage: [8]u8 = undefined;
    try testing.expectEqual(@as(?usize, 2), exchange_of(path_of(2, &storage)));
    try testing.expectEqual(@as(?usize, null), exchange_of("/other"));
    try testing.expectEqual(@as(?usize, null), exchange_of("/e/99"));
}
