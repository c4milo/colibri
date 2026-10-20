//! The choice between QUIC and TCP for one origin (decision 100, design §8 step 17d), and of the
//! TCP slot a pool opens next (decision 125), as spec/tla/client_exchanges models it (decision
//! 105): which connection the client opens next, and when it gives up on the exchanges waiting for
//! one. It reads a view of the pool and changes nothing.
const std = @import("std");
const assert = std.debug.assert;

pub const Transport = enum(u1) { quic, tcp };

/// A slot's connection, as the model's `phase` names it.
pub const Phase = enum {
    /// No connection was opened.
    none,
    /// The caller was asked to open the transport, and its handshake runs.
    handshake,
    /// Its handshake completed, and it takes exchanges.
    open,
    /// It takes no new exchange and carries those it holds: the server sent a GOAWAY, the client
    /// was shut down, or a connection of the other transport completed its handshake first.
    draining,
    /// It failed, or the client abandoned its handshake, and each exchange it held ended.
    failed,
    /// Its transport closed, and another connection may open in its slot.
    closed,

    /// Whether the slot has no connection.
    pub fn idle(phase: Phase) bool {
        return phase == .none or phase == .closed;
    }
};

/// What the choice reads of the pool at one instant.
pub const View = struct {
    /// The QUIC slot's phase, and whether this attempt opened it.
    quic: Phase,
    quic_tried: bool,
    /// QUIC may carry the pool's exchanges: h3 is offered, and known or tried first.
    quic_allowed: bool,
    /// TCP may carry them: the client speaks h11 or h2 (RFC 9114 §3.1, decision 117).
    tcp_allowed: bool,
    /// A TCP slot with no connection, which this attempt has not opened, or null.
    tcp_free: ?u32,
    /// The TCP slots whose handshake runs, and whether a TCP connection is open.
    tcp_opening: u32,
    tcp_open: bool,
    /// The exchanges that wait, and whether an open connection has room for one.
    waiting: u32,
    room: bool,
    /// The fallback delay passed while QUIC ran its handshake.
    fallback: bool,
    /// No slot has a connection.
    all_idle: bool,
};

/// The connection the client opens: QUIC's, or the one of a TCP slot.
pub const Choice = union(enum) {
    quic,
    tcp: u32,
};

/// The connection the client opens next, or null for none: the model's CanOpenQuic, then its
/// CanOpenTcp.
pub fn next_open(view: *const View) ?Choice {
    if (!wanted(view)) return null;
    if (can_open_quic(view)) return .quic;
    if (can_open_tcp(view)) |slot| return .{ .tcp = slot };
    return null;
}

/// Whether the client gives up on the waiting exchanges, the model's GiveUp: no connection is left
/// to take them, and the attempt may open no other.
pub fn give_up(view: *const View) bool {
    if (view.waiting == 0 or !view.all_idle) return false;
    return next_open(view) == null;
}

/// An exchange waits, and no open connection has room for it.
fn wanted(view: *const View) bool {
    return view.waiting > 0 and !view.room;
}

/// TCP carries the exchanges: a TCP connection is open, and the QUIC connection is not.
fn tcp_carries(view: *const View) bool {
    return view.tcp_open and view.quic != .open;
}

/// QUIC goes first when it is allowed (RFC 9114 §3.1), once an attempt, and not beside a TCP
/// connection that runs.
fn can_open_quic(view: *const View) bool {
    if (!view.quic_allowed or view.quic_tried) return false;
    return view.quic.idle() and !view.tcp_open and view.tcp_opening == 0;
}

/// A TCP slot opens once an attempt, and only when TCP is allowed: when QUIC is not allowed, when
/// the fallback delay passed during QUIC's handshake, when this attempt's QUIC failed, when a QUIC
/// connection still ends, or when TCP carries the exchanges and they need another connection: an
/// h11 one with no room (decision 125). RFC 9114 §3.1: a client that cannot establish QUIC "SHOULD
/// attempt to use TCP-based versions", and a client that speaks h3 alone has none (the model's
/// TcpWhenAllowed). Until TCP carries the exchanges, one TCP handshake runs at a time, so the pool
/// learns whether ALPN picks h2 before it opens a second connection.
fn can_open_tcp(view: *const View) ?u32 {
    if (!view.tcp_allowed) return null;
    const slot = view.tcp_free orelse return null;
    const grows = tcp_carries(view);
    if (view.tcp_opening > 0 and !grows) return null;
    // Decision 125: no more handshakes run than exchanges wait.
    if (view.tcp_opening >= view.waiting) return null;
    return if (grows or after_quic(view)) slot else null;
}

/// Whether QUIC leaves TCP to carry the exchanges: QUIC is not allowed, the fallback delay passed
/// during its handshake, this attempt's QUIC failed, or a QUIC connection still ends.
fn after_quic(view: *const View) bool {
    if (!view.quic_allowed) return true;
    if (view.quic == .handshake) return view.fallback;
    return view.quic_tried or !view.quic.idle();
}

const testing = std.testing;

/// A view with an exchange waiting, both transports allowed, and nothing opened. Test-only.
fn fresh() View {
    return .{
        .quic = .none,
        .quic_tried = false,
        .quic_allowed = true,
        .tcp_allowed = true,
        .tcp_free = 0,
        .tcp_opening = 0,
        .tcp_open = false,
        .waiting = 1,
        .room = false,
        .fallback = false,
        .all_idle = true,
    };
}

test "RFC 9114 §3.1: QUIC opens first when it is allowed, and TCP first when it is not" {
    var view = fresh();
    try testing.expectEqual(Choice.quic, next_open(&view).?);
    view.quic_allowed = false;
    try testing.expectEqual(Choice{ .tcp = 0 }, next_open(&view).?);
    // Nothing opens without an exchange waiting, or beside an open connection with room.
    view.waiting = 0;
    try testing.expectEqual(null, next_open(&view));
    view = fresh();
    view.tcp_open = true;
    view.room = true;
    try testing.expectEqual(null, next_open(&view));
    view = fresh();
    view.quic = .open;
    view.room = true;
    try testing.expectEqual(null, next_open(&view));
}

test "RFC 9114 §3.1: TCP waits while QUIC's handshake runs, and opens once the fallback delay passes" {
    var view = fresh();
    view.quic = .handshake;
    view.quic_tried = true;
    try testing.expectEqual(null, next_open(&view));
    view.fallback = true;
    try testing.expectEqual(Choice{ .tcp = 0 }, next_open(&view).?);
}

test "RFC 9114 §3.1: TCP opens once this attempt's QUIC failed, or while a QUIC connection ends" {
    var view = fresh();
    view.quic = .failed;
    view.quic_tried = true;
    try testing.expectEqual(Choice{ .tcp = 0 }, next_open(&view).?);
    view.quic = .closed;
    try testing.expectEqual(Choice{ .tcp = 0 }, next_open(&view).?);
    // A QUIC connection still ending, draining after a GOAWAY, leaves TCP to carry the exchanges.
    view = fresh();
    view.quic = .draining;
    try testing.expectEqual(Choice{ .tcp = 0 }, next_open(&view).?);
}

test "each slot opens once an attempt, and QUIC not beside a TCP handshake" {
    var view = fresh();
    view.quic_tried = true;
    view.tcp_free = null;
    try testing.expectEqual(null, next_open(&view));
    view = fresh();
    view.tcp_opening = 1;
    view.tcp_free = 1;
    try testing.expectEqual(null, next_open(&view));
    // A slot whose connection still runs is not free.
    view = fresh();
    view.quic_allowed = false;
    view.tcp_free = null;
    try testing.expectEqual(null, next_open(&view));
}

test "decision 125: TCP grows while it carries the exchanges in h11 and an exchange waits" {
    var view = fresh();
    view.quic_allowed = false;
    view.tcp_open = true;
    view.tcp_free = 1;
    view.waiting = 2;
    view.all_idle = false;
    try testing.expectEqual(Choice{ .tcp = 1 }, next_open(&view).?);
    // Beside one handshake that runs, another opens only while more requests wait.
    view.tcp_opening = 1;
    try testing.expectEqual(Choice{ .tcp = 1 }, next_open(&view).?);
    view.waiting = 1;
    try testing.expectEqual(null, next_open(&view));
    // QUIC never opens beside an open TCP connection.
    view.tcp_opening = 0;
    view.quic_allowed = true;
    try testing.expectEqual(Choice{ .tcp = 1 }, next_open(&view).?);
    // An open connection with room, as an h2 one always has (RFC 9113 §9.1), opens nothing.
    view.room = true;
    try testing.expectEqual(null, next_open(&view));
    // Until TCP carries the exchanges, one TCP handshake runs at a time.
    view = fresh();
    view.quic_allowed = false;
    view.tcp_opening = 1;
    view.tcp_free = 1;
    view.waiting = 2;
    view.all_idle = false;
    try testing.expectEqual(null, next_open(&view));
}

test "the client gives up once no connection is left and the attempt may open none" {
    var view = fresh();
    view.quic_tried = true;
    view.quic = .closed;
    view.tcp_free = null;
    try testing.expect(give_up(&view));
    // Not while a connection still ends, whose slot may carry the exchanges once it closes.
    view.all_idle = false;
    try testing.expect(!give_up(&view));
    // Not while a slot may still open, nor with no exchange waiting.
    view = fresh();
    try testing.expect(!give_up(&view));
    view.quic_tried = true;
    view.tcp_free = null;
    view.waiting = 0;
    try testing.expect(!give_up(&view));
}

test "RFC 9114 §3.1: a client that speaks h3 alone opens no TCP, and gives up once QUIC failed" {
    var view = fresh();
    view.tcp_allowed = false;
    try testing.expectEqual(Choice.quic, next_open(&view).?);
    // Neither the fallback delay nor a failed QUIC connection opens TCP.
    view.quic = .handshake;
    view.quic_tried = true;
    view.fallback = true;
    view.all_idle = false;
    try testing.expectEqual(null, next_open(&view));
    view.quic = .failed;
    try testing.expectEqual(null, next_open(&view));
    try testing.expect(!give_up(&view));
    view.quic = .closed;
    view.all_idle = true;
    try testing.expectEqual(null, next_open(&view));
    try testing.expect(give_up(&view));
    // With QUIC not allowed either, the attempt opens nothing and ends at once.
    view = fresh();
    view.tcp_allowed = false;
    view.quic_allowed = false;
    try testing.expectEqual(null, next_open(&view));
    try testing.expect(give_up(&view));
}

test "a slot is idle with no connection, and not while one runs" {
    try testing.expect(Phase.none.idle() and Phase.closed.idle() and !Phase.failed.idle());
    assert(!Phase.open.idle());
}
