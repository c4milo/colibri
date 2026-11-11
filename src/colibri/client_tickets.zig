//! The session tickets a `colibri.Client` keeps (decision 161): the newest one a TCP connection
//! took, and the newest one a QUIC connection took, each with the instant it arrived. The next
//! connection of that transport offers its ticket once, and the client then drops it, because
//! RFC 9846 Appendix C.4 asks a client not to reuse a ticket for two connections. `client.zig`
//! holds one `Kept`, and the root does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const tls = @import("tls");

const nanoseconds_per_second = core.constants.nanoseconds_per_second;
const nanoseconds_per_millisecond = core.constants.nanoseconds_per_millisecond;

/// The transport a ticket resumes: chapulin keeps a ticket to the transport that issued it
/// (chapulin's decision 79).
pub const Transport = enum { tcp, quic };

/// A ticket and the instant it arrived, which its age counts from (RFC 9846 §4.3.11.1).
pub const Held = struct {
    ticket: tls.Ticket,
    at_ns: u64,

    /// The offer of this ticket at `now_ns`, which points into it, so the holder keeps it in place
    /// until the connection has started.
    pub fn resumption(held: *const Held, now_ns: u64) tls.Resumption {
        return .{ .ticket = &held.ticket, .age_ms = age_ms(held, now_ns) };
    }
};

pub const Kept = struct {
    tcp: ?Held = null,
    quic: ?Held = null,

    /// Keeps `ticket`, which arrived at `now_ns`, in place of the older ticket of its transport,
    /// and wipes both the older one and the caller's copy.
    pub fn keep(kept: *Kept, ticket: *tls.Ticket, now_ns: u64) void {
        const room = kept.slot(transport_of(ticket));
        if (room.*) |*older| older.ticket.wipe();
        room.* = .{ .ticket = ticket.*, .at_ns = now_ns };
        ticket.wipe();
    }

    /// Takes the ticket the next connection of `transport` offers at `now_ns`, or null. The
    /// client holds it no more, so no second connection offers it. A ticket past its lifetime is
    /// wiped, and none is offered, because the TLS stack refuses it and the connection would fail
    /// (RFC 9846 §4.7.1). The caller wipes the ticket once its connection has started.
    pub fn take(kept: *Kept, transport: Transport, now_ns: u64) ?Held {
        const room = kept.slot(transport);
        const held = room.* orelse return null;
        room.*.?.ticket.wipe();
        room.* = null;
        if (!usable(&held, now_ns)) {
            var stale = held;
            stale.ticket.wipe();
            return null;
        }
        return held;
    }

    /// Wipes each ticket kept.
    pub fn wipe(kept: *Kept) void {
        inline for (.{ &kept.tcp, &kept.quic }) |room| {
            if (room.*) |*held| held.ticket.wipe();
            room.* = null;
        }
    }

    fn slot(kept: *Kept, transport: Transport) *?Held {
        return switch (transport) {
            .tcp => &kept.tcp,
            .quic => &kept.quic,
        };
    }
};

/// A ticket a QUIC connection issued carries that connection's version, and one a TCP connection
/// issued carries 0 (RFC 9369 §5).
fn transport_of(ticket: *const tls.Ticket) Transport {
    return if (ticket.quic_version == 0) .tcp else .quic;
}

fn age_ms(held: *const Held, now_ns: u64) u64 {
    assert(now_ns >= held.at_ns);
    return (now_ns - held.at_ns) / nanoseconds_per_millisecond;
}

/// RFC 9846 §4.3.11.1: a client uses no ticket older than its ticket_lifetime, and §4.7.1: never
/// for longer than seven days after it was issued.
fn usable(held: *const Held, now_ns: u64) bool {
    const lifetime_s = @min(held.ticket.lifetime_s, tls.constants.protocol.ticket_lifetime_max_s);
    assert(now_ns >= held.at_ns);
    return now_ns - held.at_ns < @as(u64, lifetime_s) * nanoseconds_per_second;
}

const testing = std.testing;

/// A ticket of `transport` whose identity's first octet is `mark`, which lives `lifetime_s`.
/// Test-only.
fn test_ticket(transport: Transport, mark: u8, lifetime_s: u32) tls.Ticket {
    var ticket = std.mem.zeroes(tls.Ticket);
    ticket.identity[0] = mark;
    ticket.identity_len = 1;
    ticket.lifetime_s = lifetime_s;
    // RFC 9000 §15: QUIC version 1.
    ticket.quic_version = if (transport == .quic) 1 else 0;
    return ticket;
}

const lifetime_test_s: u32 = 3600;
const ns_per_s = nanoseconds_per_second;
const ms_per_s = nanoseconds_per_second / nanoseconds_per_millisecond;

test "RFC 9846 Appendix C.4: a kept ticket is offered once, and the newest replaces the older" {
    var kept: Kept = .{};
    var first = test_ticket(.tcp, 1, lifetime_test_s);
    kept.keep(&first, ns_per_s);
    // The caller's copy is wiped once the client keeps the ticket.
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&first), 0));
    var second = test_ticket(.tcp, 2, lifetime_test_s);
    kept.keep(&second, 2 * ns_per_s);
    const offered = kept.take(.tcp, 5 * ns_per_s).?;
    try testing.expectEqual(2, offered.ticket.identity[0]);
    try testing.expectEqual(3 * ms_per_s, offered.resumption(5 * ns_per_s).age_ms);
    // A second connection offers no ticket: the first one took it.
    try testing.expectEqual(null, kept.take(.tcp, 5 * ns_per_s));
}

test "chapulin's decision 79: a ticket resumes only the transport that issued it" {
    var kept: Kept = .{};
    var quic = test_ticket(.quic, 7, lifetime_test_s);
    kept.keep(&quic, 0);
    try testing.expectEqual(null, kept.take(.tcp, 0));
    try testing.expectEqual(7, kept.take(.quic, 0).?.ticket.identity[0]);
}

test "RFC 9846 §4.7.1: a ticket past its lifetime, or past seven days, is not offered" {
    var kept: Kept = .{};
    var short = test_ticket(.tcp, 1, 10);
    kept.keep(&short, 0);
    try testing.expectEqual(null, kept.take(.tcp, 10 * ns_per_s));
    var long = test_ticket(.tcp, 2, std.math.maxInt(u32));
    kept.keep(&long, 0);
    const seven_days_ns = @as(u64, tls.constants.protocol.ticket_lifetime_max_s) * ns_per_s;
    try testing.expectEqual(null, kept.take(.tcp, seven_days_ns));
    var fresh = test_ticket(.tcp, 3, 10);
    kept.keep(&fresh, 0);
    try testing.expect(kept.take(.tcp, 9 * ns_per_s) != null);
}

test "decision 161: wipe zeroes each kept ticket and drops it" {
    var kept: Kept = .{};
    var tcp = test_ticket(.tcp, 1, lifetime_test_s);
    var quic = test_ticket(.quic, 2, lifetime_test_s);
    kept.keep(&tcp, 0);
    kept.keep(&quic, 0);
    const tcp_room = &kept.tcp.?.ticket;
    kept.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(tcp_room), 0));
    try testing.expectEqual(null, kept.tcp);
    try testing.expectEqual(null, kept.quic);
}
