//! The application of an h3 deadline run (`h3_deadline_run.zig`, decision 110 as amended): it
//! notes each request the server reads and when its content ends, answers it once its delay has
//! passed, and notes each request the server reports done or cancelled.
//!
//! It writes an answer whole, or in two halves a gap apart, as a program that produces a response
//! slowly does. An answer that stays open has no end at all.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const plan_module = @import("h3_deadline_plan.zig");

const limits = sim.constants.h3_deadline;
const Plan = plan_module.Plan;

/// The server's endpoint, which holds the run's one QUIC connection.
pub const Endpoint = server.EndpointOf(.{ .quic_connections = 1 });

pub const Error = error{
    /// The server refused an answer to an honest peer.
    ExchangeRefused,
};

/// A request the application read: when its content ended, when the application began its answer
/// and when it ended it, when the server reported it done, and the deadline that cancelled it.
pub const Answer = struct {
    id: server.Id,
    read_ms: u64,
    content_end_ms: ?u64 = null,
    answered_ms: ?u64 = null,
    finished_ms: ?u64 = null,
    done_ms: ?u64 = null,
    cancelled: ?server.Deadline = null,
    cancelled_ms: ?u64 = null,
};

/// The status each answer carries: 200 (OK), RFC 9110 §15.3.1.
const answer_status: u16 = 200;

/// The halves an answer written in two has.
const halves: usize = 2;

pub const Application = struct {
    answers: [limits.exchanges_max]Answer,
    answers_len: u8,
    /// The requests the server reported, the application's answers and a flooder's among them.
    requests_read: u32,

    pub fn init(app: *Application) void {
        app.answers_len = 0;
        app.requests_read = 0;
    }

    /// Notes each request the application must answer, when its content ends, and what the server
    /// reports of it after.
    pub fn note_event(app: *Application, reported: server.Event, now_ms: u64) void {
        switch (reported) {
            .request => |request| app.note_request(request.id, now_ms),
            .body => |body| if (body.end) app.note_content_end(body.id.number, now_ms),
            .trailers => |trailers| app.note_content_end(trailers.id.number, now_ms),
            .cancelled => |cancelled| if (app.find(cancelled.id.number)) |pending| {
                pending.cancelled_ms = now_ms;
                if (cancelled.reason == .deadline) pending.cancelled = cancelled.reason.deadline;
            },
            .done => |done| if (app.find(done.id.number)) |pending| {
                pending.done_ms = now_ms;
            },
            .writable => {},
            // The run reads `ended`. A QUIC connection owes no `send` or `close`, and the run never
            // shuts the endpoint down (decision 119).
            .send, .close, .ended, .closed => unreachable,
        }
    }

    fn note_request(app: *Application, id: server.Id, now_ms: u64) void {
        app.requests_read += 1;
        // The application answers as many requests as a peer makes whole.
        if (app.answers_len == limits.exchanges_max) return;
        app.answers[app.answers_len] = .{ .id = id, .read_ms = now_ms };
        app.answers_len += 1;
    }

    fn note_content_end(app: *Application, id: u64, now_ms: u64) void {
        const pending = app.find(id) orelse return;
        pending.content_end_ms = now_ms;
    }

    fn find(app: *Application, number: u64) ?*Answer {
        for (app.answers[0..app.answers_len]) |*pending| {
            if (pending.id.number == number) return pending;
        }
        return null;
    }

    /// Writes what each answer owes at `now_ms`, from the first octets of `content`, which stay
    /// the application's (decision 103): its head and first octets once the request's content has
    /// ended and its delay has passed, and the rest a gap after. Returns whether anything moved.
    pub fn answer(app: *Application, endpoint: *Endpoint, plan: *const Plan, content: []const u8, now_ms: u64) Error!bool {
        var moved = false;
        for (app.answers[0..app.answers_len], 0..) |*pending, index| {
            const due_ms = next_write_ms(pending, plan, index) orelse continue;
            if (now_ms < due_ms) continue;
            moved = true;
            write(endpoint, pending, plan, content[0..plan.content_len[index]], index, now_ms) catch {
                // A server that ended a hostile peer's request takes no answer to it.
                if (plan.honest()) return error.ExchangeRefused;
            };
        }
        return moved;
    }

    /// The next instant an answer owes a write, or `current` when it is sooner or none does.
    pub fn next_ms(app: *const Application, plan: *const Plan, current: ?u64) ?u64 {
        var soonest = current;
        for (app.answers[0..app.answers_len], 0..) |*pending, index| {
            const due_ms = next_write_ms(pending, plan, index) orelse continue;
            soonest = @min(soonest orelse due_ms, due_ms);
        }
        return soonest;
    }

    /// The instant the server reported the last answer done.
    pub fn last_done_ms(app: *const Application) ?u64 {
        var last: ?u64 = null;
        for (app.answers[0..app.answers_len]) |answered| {
            const done_ms = answered.done_ms orelse continue;
            last = @max(last orelse done_ms, done_ms);
        }
        return last;
    }

    /// The first request a deadline cancelled, or null.
    pub fn first_cancelled(app: *const Application) ?*const Answer {
        for (app.answers[0..app.answers_len]) |*answered| {
            if (answered.cancelled != null) return answered;
        }
        return null;
    }
};

/// The instant `pending` owes its next write: its first once its request's content has ended and
/// its delay has passed, and its second a gap after the first. Null for an answer that owes none.
fn next_write_ms(pending: *const Answer, plan: *const Plan, index: usize) ?u64 {
    if (pending.cancelled_ms != null or pending.finished_ms != null) return null;
    const first_ms = pending.answered_ms orelse {
        return (pending.content_end_ms orelse return null) + plan.answer_delay_ms[index];
    };
    // An answer that stays open has written all it will.
    if (plan.answer_stays_open()) return null;
    return first_ms + plan.answer_gap_ms[index];
}

/// Writes the answer's head and first octets, or its last octets and its end. QUIC reads the
/// octets in place until the peer acknowledges them.
fn write(endpoint: *Endpoint, pending: *Answer, plan: *const Plan, content: []const u8, index: usize, now_ms: u64) server.SendError!void {
    const in_two = plan.answer_gap_ms[index] > 0;
    const first_len = if (in_two) content.len / halves else content.len;
    if (pending.answered_ms != null) {
        pending.finished_ms = now_ms;
        return write_content(endpoint, pending.id, content[first_len..], true);
    }
    pending.answered_ms = now_ms;
    const ends = !in_two and !plan.answer_stays_open();
    if (ends) pending.finished_ms = now_ms;
    try endpoint.respond(pending.id, .{ .status = answer_status, .end = ends and content.len == 0 });
    if (first_len > 0) try write_content(endpoint, pending.id, content[0..first_len], ends);
}

fn write_content(endpoint: *Endpoint, id: server.Id, content: []const u8, end: bool) server.SendError!void {
    const taken = try endpoint.write_body(id, .{ .octets = content, .end = end });
    assert(taken == content.len);
}
