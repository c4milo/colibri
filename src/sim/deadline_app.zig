//! The application of a deadline run (`deadline_run.zig`, decision 110): it notes each request the
//! server reads and when its body ends, answers it by its id once its delay has passed, and writes
//! the answer's content as the server takes it, a piece at a time when the peer reads slowly.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const plan_module = @import("deadline_plan.zig");

const limits = sim.constants.deadline;
const Plan = plan_module.Plan;

/// The server of a deadline run (design §8 step 21b.6): one connection in cleartext, and no QUIC.
pub const Endpoint = server.EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 });

pub const Error = error{
    /// The server refused an answer to an honest peer.
    ExchangeRefused,
};

/// A request the application read: when its body ended, when the application answered it, the
/// octets of its content the server took, and when the last of them left the server's output.
pub const Answer = struct {
    id: server.Id,
    read_ms: u64,
    body_end_ms: ?u64,
    answered_ms: ?u64,
    /// Whether the server's output once had no room for the answer's head. The application then
    /// writes it when the peer has taken octets, and no instant of its own is due for it.
    waited_for_room: bool,
    content_sent: u32,
    drained_ms: ?u64,
};

/// The status each answer carries: 200 (OK), RFC 9110 §15.3.1.
const answer_status: u16 = 200;

pub const Application = struct {
    answers: [limits.requests_max]Answer,
    answers_len: u8,
    /// The deadline that ended a request, as the application read it in `cancelled`.
    cancelled: ?server.Deadline,

    pub fn init(app: *Application) void {
        app.answers_len = 0;
        app.cancelled = null;
    }

    /// Notes each request the application must answer, when its body ends, and the deadline that
    /// cancelled one.
    pub fn note_event(app: *Application, reported: server.Event, now_ms: u64) void {
        switch (reported) {
            .request => |request| app.note_request(request.id, now_ms, request.end),
            .body => |body| if (body.end) app.note_body_end(body.id, now_ms),
            .trailers => |trailers| app.note_body_end(trailers.id, now_ms),
            .cancelled => |cancelled| if (cancelled.reason == .deadline) {
                app.cancelled = cancelled.reason.deadline;
            },
            .done => {},
            // The run keeps these: the application writes each answer again in every pass, and
            // the rest name the connection and no request.
            .writable, .send, .close, .ended, .closed => unreachable,
        }
    }

    fn note_request(app: *Application, id: server.Id, now_ms: u64, ended: bool) void {
        // The application answers as many requests as a peer makes whole.
        if (app.answers_len == limits.requests_max) return;
        app.answers[app.answers_len] = .{
            .id = id,
            .read_ms = now_ms,
            .body_end_ms = if (ended) now_ms else null,
            .answered_ms = null,
            .waited_for_room = false,
            .content_sent = 0,
            .drained_ms = null,
        };
        app.answers_len += 1;
    }

    fn note_body_end(app: *Application, id: server.Id, now_ms: u64) void {
        for (app.answers[0..app.answers_len]) |*pending| {
            if (pending.id == id) pending.body_end_ms = now_ms;
        }
    }

    /// Answers each request whose body has ended and whose delay has passed since, and writes as
    /// much of each answer's `content` as the server takes. Returns whether anything moved.
    pub fn answer(app: *Application, endpoint: *Endpoint, plan: *const Plan, content: []const u8, now_ms: u64) Error!bool {
        var moved = false;
        for (app.answers[0..app.answers_len], 0..) |*pending, index| {
            const body_end_ms = pending.body_end_ms orelse continue;
            if (now_ms < body_end_ms + plan.answer_delay_ms[index]) continue;
            moved = try write_answer(endpoint, plan, pending, content[0..plan.content_len[index]], now_ms) or moved;
        }
        return moved;
    }

    /// Notes when each answer whose content the server took whole has left its output, which
    /// holds `output_len` octets: the instant the idle deadline counts from (decision 110).
    pub fn note_drained(app: *Application, output_len: usize, plan: *const Plan, now_ms: u64) void {
        if (output_len > 0) return;
        for (app.answers[0..app.answers_len], 0..) |*pending, index| {
            if (pending.drained_ms != null or pending.answered_ms == null) continue;
            if (pending.content_sent < plan.content_len[index]) continue;
            pending.drained_ms = now_ms;
        }
    }

    /// The next instant an answer is due, or `current` when it is sooner or none is.
    pub fn next_ms(app: *const Application, plan: *const Plan, current: ?u64) ?u64 {
        var soonest = current;
        for (app.answers[0..app.answers_len], 0..) |pending, index| {
            if (pending.answered_ms != null or pending.waited_for_room) continue;
            const body_end_ms = pending.body_end_ms orelse continue;
            const due_ms = body_end_ms + plan.answer_delay_ms[index];
            soonest = @min(soonest orelse due_ms, due_ms);
        }
        return soonest;
    }

    /// The instant the last answer left the server's output.
    pub fn last_drained_ms(app: *const Application) u64 {
        var last: u64 = 0;
        for (app.answers[0..app.answers_len]) |answered| last = @max(last, answered.drained_ms.?);
        return last;
    }
};

/// Writes the answer's head, then as much of its content as the server takes. A server that ends
/// a hostile peer's request or connection takes nothing more, and the application stops.
fn write_answer(endpoint: *Endpoint, plan: *const Plan, pending: *Answer, content: []const u8, now_ms: u64) Error!bool {
    if (pending.answered_ms == null) {
        endpoint.respond(pending.id, .{ .status = answer_status, .end = content.len == 0 }) catch |failure| {
            if (failure != error.NoSpaceLeft) return give_up(plan, pending, content, now_ms);
            // `SendError.NoSpaceLeft`: the output has no room for the head, and the caller writes
            // it again once the peer has taken octets.
            pending.waited_for_room = true;
            return false;
        };
        pending.answered_ms = now_ms;
        return true;
    }
    if (pending.content_sent == content.len) return false;
    const rest = content[pending.content_sent..];
    const taken = endpoint.write_body(pending.id, .{ .octets = rest, .end = true }) catch |failure| {
        // The output or the peer's window has no room, and the application writes again later.
        if (failure == error.Blocked) return false;
        return give_up(plan, pending, content, now_ms);
    };
    assert(taken <= rest.len);
    pending.content_sent += @intCast(taken);
    return taken > 0;
}

/// An honest peer's answer the server refused is an error of the run; a hostile peer's ends the
/// application's writing.
fn give_up(plan: *const Plan, pending: *Answer, content: []const u8, now_ms: u64) Error!bool {
    if (plan.honest()) return error.ExchangeRefused;
    pending.answered_ms = pending.answered_ms orelse now_ms;
    pending.content_sent = @intCast(content.len);
    return false;
}
