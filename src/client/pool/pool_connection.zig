//! The calls a pool makes on the connection of one of its slots (decision 125): the QUIC
//! connection in the QUIC slot, and a TCP connection in each TCP slot. A pool with no QUIC
//! (decision 124) holds no QUIC connection, so each step on one is out of its code at build time.
//! The module's root does not export this file.
const tls = @import("tls");
const event = @import("../event.zig");
const pool_handle = @import("pool_handle.zig");

const RequestId = event.RequestId;
const Request = event.Request;
const Response = event.Response;
const Protocol = event.Protocol;

/// Whether `slot` is the QUIC slot of a pool that holds QUIC.
inline fn is_quic(pool: anytype, slot: u32) bool {
    return pool.capacity.quic and slot == pool_handle.quic_slot(pool);
}

/// The connection of `slot` takes `message` and `response`, and returns its own id for them.
pub fn request(pool: anytype, slot: u32, message: *const Request, response: *Response) !RequestId {
    if (is_quic(pool, slot)) return pool.quic.request(message, response);
    return pool.tcp[slot].request(message, response);
}

pub fn cancel(pool: anytype, slot: u32, carried_id: RequestId) void {
    if (is_quic(pool, slot)) return pool.quic.cancel(carried_id);
    pool.tcp[slot].cancel(carried_id);
}

/// The next event the connection of `slot` owes, read with no octets.
pub fn poll(pool: anytype, slot: u32, now_ns: u64) event.ReceiveResult {
    var none: [0]u8 = .{};
    if (is_quic(pool, slot)) return pool.quic.receive(&none, .not_ect, .{}, now_ns);
    return pool.tcp[slot].receive(&none, now_ns);
}

pub fn shutdown(pool: anytype, slot: u32) void {
    if (is_quic(pool, slot)) return pool.quic.shutdown();
    pool.tcp[slot].shutdown();
}

pub fn transport_closed(pool: anytype, slot: u32) void {
    if (is_quic(pool, slot)) return pool.quic.transport_closed();
    pool.tcp[slot].transport_closed();
}

/// Whether the connection of `slot` is over and its transport may close.
pub fn should_close(pool: anytype, slot: u32) bool {
    if (is_quic(pool, slot)) return pool.quic.closed or pool.quic.should_close();
    return pool.tcp[slot].should_close();
}

pub fn take_ticket(pool: anytype, slot: u32) ?tls.Ticket {
    if (is_quic(pool, slot)) return pool.quic.take_ticket();
    return pool.tcp[slot].take_ticket();
}

pub fn failed(pool: anytype, slot: u32) bool {
    if (is_quic(pool, slot)) return pool.quic.failed;
    return pool.tcp[slot].failed;
}

pub fn draining(pool: anytype, slot: u32) bool {
    if (is_quic(pool, slot)) return pool.quic.draining;
    return pool.tcp[slot].draining;
}

/// Whether the open connection of `slot` takes another exchange now (decision 125). A QUIC
/// connection and an h2 one take exchanges until their slots are full, which `request` says, and
/// the pool never counts them full: so it opens no other connection beside them, and RFC 9113 §9.1
/// asks that a client "SHOULD NOT open more than one HTTP/2 connection to a given host". An h11
/// connection pipelines in a pool of one TCP slot (decision 88), and in a pool of more it takes
/// one exchange at a time.
pub fn room(pool: anytype, slot: u32) bool {
    if (is_quic(pool, slot)) return true;
    const connection = &pool.tcp[slot];
    if (pool.tcp.len == 1 or connection.protocol() != Protocol.h11) return true;
    return connection.slots.idle();
}

/// Whether the open connection of `slot` takes an exchange now: it has room, and a free slot of
/// its own. A connection with room and no free slot holds the waiting exchanges back until one of
/// its exchanges ends.
pub fn takes(pool: anytype, slot: u32) bool {
    if (!room(pool, slot)) return false;
    if (is_quic(pool, slot)) return !pool.quic.slots.full();
    return !pool.tcp[slot].slots.full();
}
