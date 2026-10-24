//! The life of each slot's link (decision 125): where its next connection goes, its `open`, the
//! end of a connection the client abandons or that is over, and its `close`, each named after the
//! step of spec/tla/client_exchanges it is (decision 105). Split out of `pool_events.zig` for
//! length; the module's root does not export this file.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../constants.zig");
const alt_svc = @import("../alt_svc.zig");
const quic_internal = @import("../quic/quic_connection_internal.zig");
const pool_module = @import("pool.zig");
const pool_handle = @import("pool_handle.zig");
const pool_connection = @import("pool_connection.zig");

const Link = pool_module.Link;
const Address = pool_module.Address;
const Alternative = pool_module.Alternative;
const Transport = pool_module.Transport;

/// Asks the caller to open `slot`'s next connection (the model's Open).
pub fn open_link(pool: anytype, slot: u32, now_ns: u64) void {
    const transport = pool_handle.transport_of(pool, slot);
    // Decision 124: a pool with no QUIC refused h3 at `init`, so it never offers QUIC.
    assert(transport == .tcp or pool.capacity.quic);
    const link = pool_handle.link(pool, slot);
    assert(link.state == .none or link.state == .closed);
    const addresses = pool.values.addresses;
    var to = addresses[address_index(pool, transport).* % addresses.len];
    to.port = port_of(pool, transport, now_ns);
    // Only a connection that is over owes its `close`.
    assert(!link.close_owed or link.state == .closed);
    // The connection this pass closed still owes its `close`, which goes out before the `open`.
    // Decision 125: the slot's next connection has the next generation, and the `close` still owed
    // names the one before it.
    link.* = .{
        .state = .opening,
        .opens = link.opens + 1,
        .generation = link.generation +% 1,
        .close_generation = link.close_generation,
        .tried = true,
        .to = to,
        .open_owed = true,
        .close_owed = link.close_owed,
    };
}

/// The index in `Values.addresses` the next connection of `transport` goes to. The TCP slots share
/// one, so a slot that opens beside the others starts where they are.
fn address_index(pool: anytype, transport: Transport) *usize {
    return switch (transport) {
        .quic => &pool.quic_address_index,
        .tcp => &pool.tcp_address_index,
    };
}

/// `slot`'s connection is over: its transport closes, and the `close` event is owed unless the
/// caller closed it. A connection that took no exchange, and that the client did not abandon, is
/// a failed attempt, and the next one tries the next address.
pub fn finish_link(pool: anytype, slot: u32) void {
    const link = pool_handle.link(pool, slot);
    const failed = !link.won and !link.abandoned;
    if (failed) move_past(pool, pool_handle.transport_of(pool, slot), &link.to);
    link.* = .{
        .state = .closed,
        .opens = link.opens,
        .generation = link.generation,
        // Decision 125: the `close` names the connection that is over.
        .close_generation = link.generation,
        .tried = link.tried,
        .close_owed = !link.gone,
    };
}

/// An attempt ended before it began: `start_quic` or `start_tcp` failed, or the caller's
/// transport closed first.
pub fn close_unstarted(pool: anytype, slot: u32) void {
    const link = pool_handle.link(pool, slot);
    assert(link.state == .opening);
    link.gone = true;
    finish_link(pool, slot);
}

/// Ends the handshake of a connection a connection of the other transport beat, or one a
/// shut-down pool has nothing for (the model's Abandon).
pub fn abandon(pool: anytype, slot: u32) void {
    const link = pool_handle.link(pool, slot);
    // An `open` still owed reached no caller, which opened no socket for it, so the link closes
    // with no `close` of its own. Only a shut-down pool's `plan` meets one: a pass that closed
    // the link's last connection and opened it again reported that connection's `close` first.
    if (link.open_owed) {
        assert(link.state == .opening and pool.shut);
        link.* = .{ .state = .closed, .opens = link.opens, .generation = link.generation, .close_generation = link.close_generation, .tried = link.tried, .close_owed = link.close_owed };
        return;
    }
    link.abandoned = true;
    switch (link.state) {
        .opening => {},
        .running => switch (pool_handle.transport_of(pool, slot)) {
            .quic => if (pool.capacity.quic) abandon_quic(pool) else unreachable,
            .tcp => pool.tcp[slot].transport_closed(),
        },
        .none, .closed => unreachable,
    }
}

/// Owes the close of an abandoned QUIC connection, and ends it.
fn abandon_quic(pool: anytype) void {
    // RFC 9000 §10.2: the close carries NO_ERROR, since no error ended the connection.
    quic.connection_close.owe(&pool.quic.transport, quic.connection_close.transport(quic.error_code.no_error, null));
    quic_internal.fail(&pool.quic);
}

/// Closes `slot`'s transport once its connection is over (the model's Close): an abandoned attempt
/// the caller opened, or a connection that reported `closed` and whose transport may close.
pub fn close_over(pool: anytype, slot: u32) void {
    const link = pool_handle.link(pool, slot);
    if (link.state == .opening and link.abandoned) return finish_link(pool, slot);
    if (link.state != .running or !link.reported_closed) return;
    // The TCP connection says when `send_stream` has written what it owes: the alert of a
    // handshake it refused (RFC 9846 §6.2), the last flight of a handshake whose session the
    // protocol then refused, and h2's GOAWAY (RFC 9113 §6.8). The transport closes after them. One
    // the caller closed, and an abandoned one, have had `transport_closed`, which leaves nothing
    // to write.
    if (!pool_connection.should_close(pool, slot)) return;
    // The connection's `transport_closed` wipes its secrets, and a second call changes nothing.
    pool_connection.transport_closed(pool, slot);
    finish_link(pool, slot);
}

/// The attempt ended: the next one tries QUIC first again (the model's `tried` and `fallback`
/// cleared).
pub fn end_attempt(pool: anytype) void {
    clear_tried(pool);
    pool.fallback = false;
    pool.fallback_at_ns = null;
}

/// An exchange left the wait, which ends the attempt's tries (the model's Assign).
pub fn clear_tried(pool: anytype) void {
    pool.quic_link.tried = false;
    for (pool.tcp_links) |*link| link.tried = false;
}

/// A connection of `transport` to `to` failed, so the next one tries the address after it. The
/// index moves only while it names `to`'s host: another connection to that address may have
/// failed first and moved it, or `set_destination` may have given new addresses since.
fn move_past(pool: anytype, transport: Transport, to: *const Address) void {
    const index = address_index(pool, transport);
    const addresses = pool.values.addresses;
    if (addresses[index.* % addresses.len].same_host(to)) index.* += 1;
}

/// Sends each `open` still owed to the first of the values `set_destination` gave, at the port it
/// chose: the program has not opened its transport yet.
pub fn retarget_owed(pool: anytype) void {
    for (pool.tcp_links) |*link| retarget(pool, link, .tcp);
    retarget(pool, &pool.quic_link, .quic);
}

fn retarget(pool: anytype, link: *Link, transport: Transport) void {
    if (!link.open_owed) return;
    const addresses = pool.values.addresses;
    var to = addresses[address_index(pool, transport).* % addresses.len];
    to.port = link.to.port;
    link.to = to;
}

/// The port `transport` connects to: a fresh Alt-Svc alternative's for QUIC (RFC 7838 §3), else
/// the HTTPS record's "port", else the origin's (RFC 9460 §7.2).
fn port_of(pool: anytype, transport: Transport, now_ns: u64) u16 {
    if (transport == .quic) {
        if (fresh_alternative(pool, now_ns)) |held| return held.port;
    }
    const https = pool.values.https_record orelse return pool.values.port;
    return https.port orelse pool.values.port;
}

/// Whether QUIC may carry the exchanges at `now_ns`: the pool offers it, and a fresh Alt-Svc
/// alternative, an HTTPS record or the configuration says to try it.
pub fn quic_allowed(pool: anytype, now_ns: u64) bool {
    if (!pool.offered.quic) return false;
    if (fresh_alternative(pool, now_ns)) |_| return true;
    // RFC 9460 §7.1.2: a client uses the transports of the protocols the record names.
    if (pool.values.https_record) |https| return https.h3;
    return pool.config.quic_first;
}

/// The Alt-Svc alternative, while it is fresh (RFC 7838 §2.2).
fn fresh_alternative(pool: anytype, now_ns: u64) ?Alternative {
    const held = pool.values.alternative orelse return null;
    return if (now_ns < held.fresh_until_ns) held else null;
}

/// Keeps what a TCP response's Alt-Svc said at `now_ns`, which replaces what the pool knew
/// (RFC 7838 §3.1).
pub fn learn(pool: anytype, advert: alt_svc.Advert, now_ns: u64) void {
    pool.values.alternative = switch (advert) {
        .clear, .none => null,
        .h3 => |h3| .{ .port = h3.port, .fresh_until_ns = now_ns +| h3.max_age_s *| constants.nanoseconds_per_second },
    };
}
