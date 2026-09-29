//! The tuples a connection's qlog names (main schema §7.2, quic-events §4.7): which of the peer's
//! addresses each packet went to or came from, as the caller names them (decision 72). Split off
//! `connection_qlog.zig` for length.
//!
//! A tuple is a number. The first address the log meets is tuple 0, the default quic-events §4.7
//! gives an event that names none, so its events name no tuple. Each new address takes the next
//! number, and `quic:tuple_assigned` names the address for it. colibri knows the peer's half of a
//! tuple alone: its own address is the caller's, and the caller never names it.
const std = @import("std");
const assert = std.debug.assert;
const qlog = @import("qlog");
const constants = @import("../constants.zig");
const PeerAddress = @import("../peer_address.zig").PeerAddress;

const Log = qlog.Log;
const quic_event = qlog.quic_event;

/// The octets of an IPv4 address (RFC 791 §3.1) and of an IPv6 one (RFC 4291 §2).
const ipv4_len: usize = 4;
const ipv6_len: usize = 16;

pub const Tuples = struct {
    /// The addresses given a number last, oldest first.
    known: [constants.qlog_tuples_max]Known = undefined,
    len: u8 = 0,
    /// The number the next new address takes.
    next: u32 = 0,

    /// The tuple number of `address`, logging quic-events §4.7's `tuple_assigned` for an address
    /// the log has not numbered yet. An empty address, from a caller that names none, is tuple 0
    /// and logs nothing.
    pub fn of(tuples: *Tuples, log: *Log, address: *const PeerAddress, now_ns: u64) u32 {
        if (address.len == 0) return 0;
        // Bounded by `qlog_tuples_max`.
        for (tuples.known[0..tuples.len]) |*known| {
            if (known.address.eql(address)) return known.tuple;
        }
        const tuple = tuples.next;
        tuples.next +|= 1;
        tuples.remember(.{ .address = address.*, .tuple = tuple });
        log.event(quic_event.name.tuple_assigned, now_ns, quic_event.TupleAssigned{
            .tuple = tuple,
            .tuple_remote = remote_of(address),
        });
        return tuple;
    }

    /// Holds `known`, and lets the oldest go when every entry is taken.
    fn remember(tuples: *Tuples, known: Known) void {
        if (tuples.len == tuples.known.len) {
            std.mem.copyForwards(Known, tuples.known[0 .. tuples.known.len - 1], tuples.known[1..]);
            tuples.len -= 1;
        }
        tuples.known[tuples.len] = known;
        tuples.len += 1;
        assert(tuples.len <= tuples.known.len);
    }
};

const Known = struct {
    address: PeerAddress,
    tuple: u32,
};

/// Quic-events §8.5's half of a tuple for the peer's `address`: its octets and its port, under
/// IPv4 or IPv6 by the octets' length. An address of another length, which a caller may name for a
/// network of its own, gives none.
fn remote_of(address: *const PeerAddress) ?quic_event.TupleEndpointInfo {
    const octets: quic_event.Hex = .{ .octets = address.octets[0..address.len] };
    return switch (address.len) {
        ipv4_len => .{ .ip_v4 = octets, .port_v4 = address.port },
        ipv6_len => .{ .ip_v6 = octets, .port_v6 = address.port },
        else => null,
    };
}

const testing = std.testing;

/// Room for the records a test writes. Test-only.
const test_log_len: usize = 4096;
const test_port: u16 = 443;
const test_schemas = [_][]const u8{qlog.quic_event_schema};
const host_octet: u8 = 0x7f;
const host: [ipv4_len]u8 = .{ host_octet, 0, 0, 1 };

fn test_log(log: *Log, buffer: []u8) !void {
    log.* = Log.init(buffer, qlog.Features.none());
    try log.start(.{ .vantage_point = .server, .group_id = "odcid", .event_schemas = &test_schemas }, 0);
    log.clear();
}

test "quic-events §4.7: each new address takes the next number, and the first is the default" {
    var buffer: [test_log_len]u8 = undefined;
    var log: Log = undefined;
    try test_log(&log, &buffer);
    var tuples: Tuples = .{};
    const first = PeerAddress.of(&host, test_port);
    try testing.expectEqual(0, tuples.of(&log, &first, 0));
    try testing.expectEqualStrings("\x1e{\"time\":0.000,\"name\":\"quic:tuple_assigned\",\"data\":{\"tuple_id\":\"\"," ++
        "\"tuple_remote\":{\"ip_v4\":\"7f000001\",\"port_v4\":443}}}\n", log.bytes());
    // An address already numbered keeps its number and logs nothing more.
    log.clear();
    try testing.expectEqual(0, tuples.of(&log, &first, 0));
    try testing.expectEqual(0, log.bytes().len);
    // RFC 9000 §9.3's NAT rebinding: the same host on another port is another tuple.
    const rebound = PeerAddress.of(&host, test_port + 1);
    try testing.expectEqual(1, tuples.of(&log, &rebound, 0));
    try testing.expect(std.mem.indexOf(u8, log.bytes(), "{\"tuple_id\":\"1\",\"tuple_remote\":{\"ip_v4\":\"7f000001\",\"port_v4\":444}}") != null);
}

test "quic-events §4.7: an address the caller left empty is the default tuple, and logs nothing" {
    var buffer: [test_log_len]u8 = undefined;
    var log: Log = undefined;
    try test_log(&log, &buffer);
    var tuples: Tuples = .{};
    try testing.expectEqual(0, tuples.of(&log, &PeerAddress{}, 0));
    try testing.expectEqual(0, log.bytes().len);
}

test "an address of neither length names its tuple and no half of it" {
    var buffer: [test_log_len]u8 = undefined;
    var log: Log = undefined;
    try test_log(&log, &buffer);
    var tuples: Tuples = .{};
    _ = tuples.of(&log, &PeerAddress.of(&.{host_octet}, test_port), 0);
    try testing.expect(std.mem.endsWith(u8, log.bytes(), "{\"tuple_id\":\"\"}}\n"));
}

test "with every entry taken, the oldest address lets go of its number" {
    var buffer: [test_log_len]u8 = undefined;
    var log: Log = undefined;
    try test_log(&log, &buffer);
    var tuples: Tuples = .{};
    // Bounded by the table, and one more.
    for (0..constants.qlog_tuples_max + 1) |port_step| {
        const address = PeerAddress.of(&host, test_port + @as(u16, @intCast(port_step)));
        try testing.expectEqual(port_step, tuples.of(&log, &address, 0));
    }
    // The first address was let go, so it comes back as a new tuple; the last is still held.
    try testing.expectEqual(constants.qlog_tuples_max + 1, tuples.of(&log, &PeerAddress.of(&host, test_port), 0));
    const last_port = test_port + @as(u16, @intCast(constants.qlog_tuples_max));
    try testing.expectEqual(constants.qlog_tuples_max, tuples.of(&log, &PeerAddress.of(&host, last_port), 0));
}
