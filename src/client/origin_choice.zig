//! The choice between QUIC and TCP for one origin (decision 100, design §8 step 17d), as
//! spec/tla/client_exchanges models it (decision 105): which transport the client opens next, and
//! when it gives up on the exchanges waiting for a connection. It reads a view of the origin and
//! changes nothing.
const std = @import("std");
const assert = std.debug.assert;

pub const Transport = enum(u1) { quic, tcp };

/// The other transport.
pub fn other(transport: Transport) Transport {
    return switch (transport) {
        .quic => .tcp,
        .tcp => .quic,
    };
}

/// A transport's connection, as the model's `phase` names it.
pub const Phase = enum {
    /// No connection was opened.
    none,
    /// The caller was asked to open the transport, and its handshake runs.
    handshake,
    /// Its handshake completed first, and it takes the exchanges.
    open,
    /// It takes no new exchange and carries those it holds: the server sent a GOAWAY, the client
    /// was shut down, or another connection's handshake completed first.
    draining,
    /// It failed, or the client abandoned its handshake, and each exchange it held ended.
    failed,
    /// Its transport closed, and another connection may open on it.
    closed,

    /// Whether the transport has no connection.
    pub fn idle(phase: Phase) bool {
        return phase == .none or phase == .closed;
    }
};

/// What the choice reads of the origin at one instant.
pub const View = struct {
    phases: std.EnumArray(Transport, Phase),
    /// An exchange waits for a connection.
    waiting: bool,
    /// QUIC may carry the origin's exchanges: h3 is offered, and known or tried first.
    quic_allowed: bool,
    /// The transports this attempt opened.
    tried: std.EnumArray(Transport, bool),
    /// The fallback delay passed while QUIC ran its handshake.
    fallback: bool,
};

/// The transport the client opens next, or null for none: the model's CanOpenQuic, then its
/// CanOpenTcp.
pub fn next_open(view: *const View) ?Transport {
    if (!wanted(view)) return null;
    if (can_open_quic(view)) return .quic;
    if (can_open_tcp(view)) return .tcp;
    return null;
}

/// Whether the client gives up on the waiting exchanges, the model's GiveUp: no connection is left
/// to take them, and the attempt may open neither transport.
pub fn give_up(view: *const View) bool {
    if (!view.waiting) return false;
    if (!view.phases.get(.quic).idle() or !view.phases.get(.tcp).idle()) return false;
    return next_open(view) == null;
}

/// An exchange waits, and no connection is open to take it.
fn wanted(view: *const View) bool {
    return view.waiting and view.phases.get(.quic) != .open and view.phases.get(.tcp) != .open;
}

/// QUIC goes first when it is allowed (RFC 9114 §3.1), once an attempt, and not beside a TCP
/// handshake already running.
fn can_open_quic(view: *const View) bool {
    if (!view.quic_allowed or view.tried.get(.quic)) return false;
    return view.phases.get(.quic).idle() and view.phases.get(.tcp) != .handshake;
}

/// TCP opens once an attempt: when QUIC is not allowed, when the fallback delay passed during
/// QUIC's handshake, when this attempt's QUIC failed, or when a QUIC connection still ends. RFC
/// 9114 §3.1: a client that cannot establish QUIC "SHOULD attempt to use TCP-based versions".
fn can_open_tcp(view: *const View) bool {
    if (view.tried.get(.tcp) or !view.phases.get(.tcp).idle()) return false;
    if (!view.quic_allowed) return true;
    const quic = view.phases.get(.quic);
    if (quic == .handshake) return view.fallback;
    return view.tried.get(.quic) or !quic.idle();
}

const testing = std.testing;

/// A view with an exchange waiting, QUIC allowed, and nothing opened. Test-only.
fn fresh() View {
    return .{
        .phases = .initFill(.none),
        .waiting = true,
        .quic_allowed = true,
        .tried = .initFill(false),
        .fallback = false,
    };
}

test "RFC 9114 §3.1: QUIC opens first when it is allowed, and TCP first when it is not" {
    var view = fresh();
    try testing.expectEqual(Transport.quic, next_open(&view).?);
    view.quic_allowed = false;
    try testing.expectEqual(Transport.tcp, next_open(&view).?);
    // Nothing opens without an exchange waiting, or beside an open connection.
    view.waiting = false;
    try testing.expectEqual(null, next_open(&view));
    view = fresh();
    view.phases.set(.tcp, .open);
    try testing.expectEqual(null, next_open(&view));
    view.phases.set(.tcp, .none);
    view.phases.set(.quic, .open);
    try testing.expectEqual(null, next_open(&view));
}

test "RFC 9114 §3.1: TCP waits while QUIC's handshake runs, and opens once the fallback delay passes" {
    var view = fresh();
    view.phases.set(.quic, .handshake);
    view.tried.set(.quic, true);
    try testing.expectEqual(null, next_open(&view));
    view.fallback = true;
    try testing.expectEqual(Transport.tcp, next_open(&view).?);
}

test "RFC 9114 §3.1: TCP opens once this attempt's QUIC failed, or while a QUIC connection ends" {
    var view = fresh();
    view.phases.set(.quic, .failed);
    view.tried.set(.quic, true);
    try testing.expectEqual(Transport.tcp, next_open(&view).?);
    view.phases.set(.quic, .closed);
    try testing.expectEqual(Transport.tcp, next_open(&view).?);
    // A QUIC connection still ending, draining after a GOAWAY, leaves TCP to carry the exchanges.
    view = fresh();
    view.phases.set(.quic, .draining);
    try testing.expectEqual(Transport.tcp, next_open(&view).?);
}

test "each transport opens once an attempt, and QUIC not beside a TCP handshake" {
    var view = fresh();
    view.tried.set(.quic, true);
    view.tried.set(.tcp, true);
    try testing.expectEqual(null, next_open(&view));
    view = fresh();
    view.phases.set(.tcp, .handshake);
    try testing.expectEqual(null, next_open(&view));
    // A transport whose connection still runs opens no second one.
    view = fresh();
    view.quic_allowed = false;
    view.phases.set(.tcp, .draining);
    try testing.expectEqual(null, next_open(&view));
}

test "the client gives up once no connection is left and the attempt may open neither transport" {
    var view = fresh();
    view.tried.set(.quic, true);
    view.tried.set(.tcp, true);
    view.phases.set(.quic, .closed);
    view.phases.set(.tcp, .closed);
    try testing.expect(give_up(&view));
    // Not while a connection still ends, whose transport may carry the exchanges once it closes.
    view.phases.set(.tcp, .failed);
    try testing.expect(!give_up(&view));
    // Not while a transport may still open, nor with no exchange waiting.
    view = fresh();
    try testing.expect(!give_up(&view));
    view.tried.set(.quic, true);
    view.tried.set(.tcp, true);
    view.waiting = false;
    try testing.expect(!give_up(&view));
}

test "the other transport of each is the one it is not" {
    try testing.expectEqual(Transport.tcp, other(.quic));
    try testing.expectEqual(Transport.quic, other(.tcp));
    try testing.expect(Phase.none.idle() and Phase.closed.idle() and !Phase.failed.idle());
    assert(!Phase.open.idle());
}
