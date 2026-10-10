//! What the peer of an h3 deadline run does, and when (`h3_deadline_plan.zig`): the requests it
//! opens, the content it sends a piece at a time, its PINGs, and the requests it cancels. Each
//! call acts on what is due at one instant, and leaves in `next_act_ms` the next instant the
//! script wants a call at.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const plan_module = @import("h3_deadline_plan.zig");
const peer_module = @import("h3_deadline_peer.zig");

const limits = sim.constants.h3_deadline;
const Plan = plan_module.Plan;
const Peer = peer_module.Peer;
const Fetch = peer_module.Fetch;
const Error = peer_module.Error;

/// Does what the plan's peer does at `now_ms`, and returns whether it did anything.
pub fn act(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    if (!peer.h3_started or !peer.active()) return false;
    return switch (plan.peer) {
        .honest, .slow_link, .deaf, .holds_credit, .holds_connection_credit, .reads_slowly => begin_all(peer, plan, now_ns),
        .slow_honest => late_heads(peer, plan, now_ns, now_ms),
        .upload => upload(peer, plan, now_ns, now_ms),
        .slow_reader => begin_next(peer, plan, 0, now_ns),
        .silent => false,
        .pinger => ping_every_gap(peer, plan, now_ms),
        .idle_pinger => idle_pinger(peer, plan, now_ns, now_ms),
        .slow_head => if (peer.fetches_len == 0) partial_head(peer, now_ns) else false,
        .slow_second_head => slow_second_head(peer, plan, now_ns, now_ms),
        .slow_body, .long_body => slow_body(peer, plan, now_ns, now_ms),
        .flooder => flood(peer, plan, now_ns, now_ms),
        .many_bodies => many_bodies(peer, now_ns, now_ms),
    };
}

/// What a peer that read a GOAWAY does: it opens no more requests and finishes those it began
/// (RFC 9114 §5.2): an upload's content and a late head's last octet. A hostile body keeps its
/// pace. The endpoint check's peers read one at its shutdown while they still act.
pub fn finish_begun(peer: *Peer, plan: *const Plan, now_ms: u64) bool {
    if (!peer.h3_started or !peer.active()) return false;
    return switch (plan.peer) {
        .upload => send_piece(peer, plan, true, now_ms),
        .slow_body, .long_body => send_piece(peer, plan, false, now_ms),
        .slow_honest => finish_head(peer, now_ms),
        else => false,
    };
}

/// Opens every exchange of the plan at once, each a GET whose stream ends with its head. A deaf
/// peer is muted once this instant's datagrams have left.
fn begin_all(peer: *Peer, plan: *const Plan, now_ns: u64) Error!bool {
    if (peer.exchanges_begun > 0) return false;
    for (0..plan.exchanges_len) |_| {
        const fetch = try peer.stage("GET", 0, now_ns) orelse return error.PeerFailed;
        peer.supply(fetch, fetch.prefix_len, true);
    }
    peer.exchanges_begun = plan.exchanges_len;
    peer.next_act_ms = null;
    peer.mute_pending = plan.peer == .deaf;
    return true;
}

/// Opens the plan's next exchange once the one before it has ended, with `content_len` octets of
/// content, of which it sends none yet.
fn begin_next(peer: *Peer, plan: *const Plan, content_len: usize, now_ns: u64) Error!bool {
    if (peer.exchanges_begun == plan.exchanges_len) return false;
    if (peer.exchanges_begun > 0 and peer.fetches[peer.exchanges_begun - 1].ended_ms == null) return false;
    const method = if (content_len > 0) "POST" else "GET";
    const fetch = try peer.stage(method, content_len, now_ns) orelse return error.PeerFailed;
    peer.supply(fetch, fetch.prefix_len, content_len == 0);
    peer.exchanges_begun += 1;
    return true;
}

/// An honest peer whose heads arrive late: one exchange at a time, each request's head without
/// its last octet, and that octet a gap after.
fn late_heads(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    if (peer.next_act_ms != null) return finish_head(peer, now_ms);
    if (peer.exchanges_begun == plan.exchanges_len) return false;
    if (peer.exchanges_begun > 0 and peer.fetches[peer.exchanges_begun - 1].ended_ms == null) return false;
    const fetch = try peer.stage("GET", 0, now_ns) orelse return error.PeerFailed;
    peer.supply(fetch, fetch.prefix_len - 1, false);
    peer.exchanges_begun += 1;
    peer.next_act_ms = now_ms + plan.gap_ms;
    return true;
}

/// Sends the last octet of the latest request's head once it is due.
fn finish_head(peer: *Peer, now_ms: u64) bool {
    const due_ms = peer.next_act_ms orelse return false;
    if (now_ms < due_ms) return false;
    const fetch = &peer.fetches[peer.fetches_len - 1];
    peer.supply(fetch, fetch.prefix_len, true);
    peer.next_act_ms = null;
    return true;
}

/// An honest upload: one exchange at a time, its content a piece every gap.
fn upload(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    const next_len = if (peer.exchanges_begun < plan.exchanges_len) plan.upload_len[peer.exchanges_begun] else 0;
    if (try begin_next(peer, plan, next_len, now_ns)) {
        peer.next_act_ms = now_ms;
        return true;
    }
    return send_piece(peer, plan, true, now_ms);
}

/// Sends the next piece of the latest request's content when it is due, and ends the stream with
/// the last piece when `finishes` is set.
fn send_piece(peer: *Peer, plan: *const Plan, finishes: bool, now_ms: u64) bool {
    const due_ms = peer.next_act_ms orelse return false;
    if (now_ms < due_ms or peer.fetches_len == 0) return false;
    const fetch = &peer.fetches[peer.fetches_len - 1];
    // A request the server answered, or reset, takes no more content.
    if (fetch.supplied == fetch.total() or fetch.status != null or fetch.reset != null) {
        peer.next_act_ms = null;
        return false;
    }
    const reaches = @min(fetch.supplied + plan.piece_len, fetch.total());
    const last = reaches == fetch.total();
    // A slow body never ends: it holds its last octet back.
    if (last and !finishes) {
        peer.next_act_ms = null;
        return false;
    }
    peer.supply(fetch, reaches, last);
    peer.next_act_ms = if (last) null else now_ms + plan.gap_ms;
    return true;
}

/// A PING every gap, the first at the first call.
fn ping_every_gap(peer: *Peer, plan: *const Plan, now_ms: u64) bool {
    const due_ms = peer.next_act_ms orelse now_ms;
    if (now_ms < due_ms) return false;
    peer.ping();
    peer.next_act_ms = now_ms + plan.gap_ms;
    return true;
}

/// One exchange, then a PING every gap from the instant its response ended.
fn idle_pinger(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    if (try begin_all(peer, plan, now_ns)) return true;
    const ended_ms = peer.fetches[0].ended_ms orelse return false;
    if (peer.next_act_ms == null) peer.next_act_ms = ended_ms + plan.gap_ms;
    return ping_every_gap(peer, plan, now_ms);
}

/// Opens a request and sends all of its head but the last octet.
fn partial_head(peer: *Peer, now_ns: u64) Error!bool {
    const fetch = try peer.stage("GET", 0, now_ns) orelse return error.PeerFailed;
    peer.supply(fetch, fetch.prefix_len - 1, false);
    peer.next_act_ms = null;
    return true;
}

/// One exchange, then a partial head the plan's gap after its response ended.
fn slow_second_head(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    if (try begin_all(peer, plan, now_ns)) return true;
    if (peer.fetches_len > plan.exchanges_len) return false;
    const ended_ms = peer.fetches[0].ended_ms orelse return false;
    const due_ms = ended_ms + plan.gap_ms;
    if (now_ms < due_ms) {
        peer.next_act_ms = due_ms;
        return false;
    }
    return partial_head(peer, now_ns);
}

/// A request's head, then its content a piece every gap and never its last octet: under the
/// minimum body rate, or over it for longer than the cap on a body.
fn slow_body(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    if (peer.fetches_len == 0) {
        const fetch = try peer.stage("POST", limits.slow_body_len, now_ns) orelse return error.PeerFailed;
        peer.supply(fetch, fetch.prefix_len, false);
        peer.exchanges_begun = 1;
        peer.next_act_ms = now_ms + plan.gap_ms;
        return true;
    }
    return send_piece(peer, plan, false, now_ms);
}

/// Opens a batch of requests and cancels each, every `flood_gap_ms`, for as many requests as the
/// peer holds. The server's limit on open streams (RFC 9000 §4.6) leaves some batches short.
fn flood(peer: *Peer, plan: *const Plan, now_ns: u64, now_ms: u64) Error!bool {
    if (peer.fetches_len == peer.fetches.len) return false;
    const due_ms = peer.next_act_ms orelse now_ms;
    if (now_ms < due_ms) return false;
    var moved = false;
    for (0..plan.flood_batch_len) |_| {
        const fetch = try peer.stage("GET", 0, now_ns) orelse break;
        peer.supply(fetch, fetch.prefix_len, true);
        peer.cancel(fetch);
        moved = true;
    }
    peer.next_act_ms = if (peer.fetches_len == peer.fetches.len) null else now_ms + limits.flood_gap_ms;
    return moved;
}

/// Two requests `second_body_after_ms` apart, each with content declared and none sent.
fn many_bodies(peer: *Peer, now_ns: u64, now_ms: u64) Error!bool {
    if (peer.fetches_len == many_bodies_len) return false;
    const due_ms = peer.next_act_ms orelse now_ms;
    if (now_ms < due_ms) return false;
    const fetch = try peer.stage("POST", limits.slow_body_len, now_ns) orelse return error.PeerFailed;
    peer.supply(fetch, fetch.prefix_len, false);
    peer.next_act_ms = if (peer.fetches_len == many_bodies_len) null else now_ms + limits.second_body_after_ms;
    return true;
}

/// The requests a peer with many bodies opens.
const many_bodies_len: usize = 2;
