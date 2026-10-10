//! One seed's plan for the endpoint check (design §8 step 21b.5, decision 119): the TCP and QUIC
//! peers that come to one endpoint, more of each kind than it has slots, when each arrives, and
//! whether the program shuts the endpoint down.
//!
//! Each TCP peer behaves as a peer of the deadline check (`deadline_plan.zig`) and each QUIC peer
//! as a peer of the h3 deadline check (`h3_deadline_plan.zig`), so the honest, flooding,
//! window-stalling and silent peers of both come here. On top of that, an honest peer may cancel
//! one of its requests, and a peer may close its connection early.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const deadline_plan = @import("../deadline_plan.zig");
const h3_deadline_plan = @import("../h3_deadline_plan.zig");

const Random = sim.Random;
const limits = sim.constants.endpoint;

/// What a peer does beside its behaviour: nothing more, cancel one of its requests, or close its
/// connection early.
pub const Overlay = enum { none, resetting, early_closing };

pub const TcpPeer = struct {
    security: server.Security,
    /// Its protocol, how it behaves, its pace and the deadlines the program sets for it. Its
    /// `base_ms` is not read: the run has one base.
    behaviour: deadline_plan.Plan,
    overlay: Overlay,
    arrive_ms: u64,
    /// A resetting peer cancels this exchange this long after the exchange's request.
    reset_exchange: u8,
    reset_after_ms: u64,
    /// An early-closing peer closes its socket this long after the endpoint accepted it.
    close_after_ms: u64,

    /// Whether colibri's client plays the peer, which no deadline may end.
    pub fn honest(peer: *const TcpPeer) bool {
        return peer.behaviour.honest();
    }
};

pub const QuicPeer = struct {
    /// How it behaves, its pace, and the deadlines the program sets for it. Its `base_ms` is not
    /// read: the run has one base.
    behaviour: h3_deadline_plan.Plan,
    overlay: Overlay,
    arrive_ms: u64,
    /// A resetting peer cancels its first request this long after it opened it.
    reset_after_ms: u64,
    /// An early-closing peer closes its connection this long after h3 started.
    close_after_ms: u64,

    pub fn honest(peer: *const QuicPeer) bool {
        return peer.behaviour.honest();
    }
};

pub const Plan = struct {
    /// The instant the run starts at, in milliseconds.
    base_ms: u64,
    /// When the program shuts the endpoint down, or null when it never does.
    shutdown_ms: ?u64,
    tcp: [limits.tcp_peers]TcpPeer,
    quic: [limits.quic_peers]QuicPeer,
};

pub fn draw(random: *Random) Plan {
    var plan: Plan = .{
        .base_ms = random.below(limits.base_ms_max),
        .shutdown_ms = null,
        .tcp = undefined,
        .quic = undefined,
    };
    if (random.below(limits.shutdown_one_in) == 0) plan.shutdown_ms = random.between(limits.shutdown_ms_min, limits.shutdown_ms_max);
    for (&plan.tcp) |*peer| peer.* = draw_tcp(random);
    for (&plan.quic) |*peer| peer.* = draw_quic(random);
    return plan;
}

/// A TCP peer. One that is honest at its full pace, or a silent one, runs TLS in one draw of
/// `tls_one_in`. Every other runs in cleartext: no peer of the simulator seals a hostile script
/// into records, and a paced peer's pace, drawn for cleartext, leaves the handshake, or a head its
/// client sealed into one record with content, past decision 110's first-request deadline.
fn draw_tcp(random: *Random) TcpPeer {
    const behaviour = deadline_plan.draw(random);
    const may_run_tls = behaviour.peer == .honest or behaviour.peer == .silent;
    const tls_drawn = random.below(limits.tls_one_in) == 0;
    var peer: TcpPeer = .{
        .security = if (may_run_tls and tls_drawn) .tls else .cleartext,
        .behaviour = behaviour,
        .overlay = draw_overlay(random, behaviour.honest(), behaviour.honest()),
        .arrive_ms = random.below(limits.arrive_ms_max + 1),
        .reset_exchange = 0,
        .reset_after_ms = random.below(limits.reset_after_ms_max + 1),
        .close_after_ms = random.below(limits.close_after_ms_max + 1),
    };
    if (behaviour.exchanges_len > 0) peer.reset_exchange = @intCast(random.below(behaviour.exchanges_len));
    return peer;
}

/// A QUIC peer, which may close early whatever it does.
fn draw_quic(random: *Random) QuicPeer {
    const behaviour = h3_deadline_plan.draw(random);
    return .{
        .behaviour = behaviour,
        .overlay = draw_overlay(random, behaviour.honest(), true),
        .arrive_ms = random.below(limits.arrive_ms_max + 1),
        .reset_after_ms = random.below(limits.reset_after_ms_max + 1),
        .close_after_ms = random.below(limits.close_after_ms_max + 1),
    };
}

/// A peer that may reset cancels a request in one draw of `resetting_one_in`; one that may close
/// early, and does not reset, closes early in one draw of `early_closing_one_in`.
fn draw_overlay(random: *Random, may_reset: bool, may_close: bool) Overlay {
    const resets = random.below(limits.resetting_one_in) == 0;
    const closes = random.below(limits.early_closing_one_in) == 0;
    if (may_reset and resets) return .resetting;
    if (may_close and closes) return .early_closing;
    return .none;
}

const testing = std.testing;

/// Seeds the test draws plans from.
const plan_seeds: u64 = 512;

/// What the plans of `plan_seeds` seeds drew at least once.
const Drawn = struct {
    security: [std.enums.values(server.Security).len]bool = @splat(false),
    tcp: [std.enums.values(deadline_plan.Peer).len]bool = @splat(false),
    quic: [std.enums.values(h3_deadline_plan.Peer).len]bool = @splat(false),
    overlay: [std.enums.values(Overlay).len]bool = @splat(false),
    shutdown: bool = false,

    fn note(drawn: *Drawn, plan: *const Plan) !void {
        if (plan.shutdown_ms != null) drawn.shutdown = true;
        for (&plan.tcp) |*peer| {
            drawn.security[@intFromEnum(peer.security)] = true;
            drawn.tcp[@intFromEnum(peer.behaviour.peer)] = true;
            drawn.overlay[@intFromEnum(peer.overlay)] = true;
            // No simulator peer seals a hostile script, and only an honest peer cancels or closes.
            if (peer.security == .tls) try testing.expect(peer.behaviour.peer == .honest or peer.behaviour.peer == .silent);
            if (peer.overlay != .none) try testing.expect(peer.honest());
        }
        for (&plan.quic) |*peer| {
            drawn.quic[@intFromEnum(peer.behaviour.peer)] = true;
            drawn.overlay[@intFromEnum(peer.overlay)] = true;
            if (peer.overlay == .resetting) try testing.expect(peer.honest());
        }
    }

    fn all(drawn: *const Drawn) bool {
        for (drawn.security) |seen| if (!seen) return false;
        for (drawn.tcp) |seen| if (!seen) return false;
        for (drawn.quic) |seen| if (!seen) return false;
        for (drawn.overlay) |seen| if (!seen) return false;
        return drawn.shutdown;
    }
};

test "decision 119: the plans draw every transport, every peer, every overlay and a shutdown" {
    var drawn: Drawn = .{};
    for (0..plan_seeds) |seed| {
        var random = Random.init(seed);
        const plan = draw(&random);
        try drawn.note(&plan);
        for (&plan.tcp) |*peer| try testing.expect(peer.arrive_ms <= limits.arrive_ms_max);
    }
    try testing.expect(drawn.all());
}
