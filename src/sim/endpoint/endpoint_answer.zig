//! How the program of the endpoint check answers one request (design §8 step 21b.5, decision
//! 119): the word it sets, the content it writes in pieces of drawn lengths, the trailer section
//! some answers over h2 and h3 end with, and the requests it cancels part way. A write that finds
//! no room waits for the request's `writable`, and P6 repeats it once nothing moves: it must take
//! nothing still.
//!
//! Every draw comes from the program's own stream, in the order the requests' events arrive.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const ledger_module = @import("endpoint_ledger.zig");
const program_module = @import("endpoint_program.zig");

const Random = sim.Random;
const limits = sim.constants.endpoint;
const Request = ledger_module.Request;
const Program = program_module.Program;
const Violation = program_module.Violation;

/// The status of every answer: 200 (OK), RFC 9110 §15.3.1.
pub const status: u16 = 200;

/// The trailer section an answer that has one ends with (RFC 9110 §6.5).
const trailer_fields = [_]server.Field{.{ .name = "grpc-status", .value = "0" }};

/// The octets of every answer's content: letters alone.
pub const content_letters = "abcdefghijklmnopqrstuvwxyz";

/// Where an answer is: waiting for its request to end, then its head, its content and its trailer
/// section, and how it ended: written whole, cancelled by the program, or left when the
/// connection closed.
pub const Phase = enum { unready, head, content, trailers, ended, cancelled, abandoned };

pub const Answer = struct {
    phase: Phase = .unready,
    content_len: u32 = 0,
    /// The content the endpoint took so far.
    written: u32 = 0,
    /// The answer's longest piece, the piece it writes now and how much of that the endpoint took.
    longest: u32 = 0,
    piece_len: u32 = 0,
    piece_taken: u32 = 0,
    /// Pieces the endpoint took whole.
    pieces: u32 = 0,
    trailers: bool = false,
    /// The program cancels the request once this many pieces went out: 0 before its head.
    cancel_after: ?u32 = null,
    /// The last write found no room, so the request waits for its `writable`.
    waiting: bool = false,
    /// The instant of the run the program starts the answer at, at the earliest.
    due_ms: u64 = 0,
};

/// A request's head arrived: the program sets its word, in seven requests of eight, and draws its
/// answer, which it writes once the request has ended.
pub fn on_request(program: *Program, request: *Request, head: *const server.Request, random: *Random) Violation!void {
    // The word is never 0, so a word lost on its way back reads as another.
    const word: usize = @intCast(random.next() | 1);
    if (random.below(limits.word_zero_one_in) != 0) try program.set_user_data(request, word);
    request.answer = draw(random, head.version.major);
    request.answer.due_ms = program.now_ms + delay_of(random);
    if (head.end) request.answer.phase = .head;
}

/// The request's content ended: its answer may start.
pub fn on_request_end(request: *Request) void {
    if (request.answer.phase == .unready) request.answer.phase = .head;
}

/// In one body event of `reword_one_in`, the program sets the request's word again.
pub fn reword(program: *Program, request: *Request, random: *Random) Violation!void {
    const word: usize = @intCast(random.next() | 1);
    if (random.below(limits.reword_one_in) == 0) try program.set_user_data(request, word);
}

fn draw(random: *Random, major: u8) Answer {
    const tier = random.below(limits.answer_tiers);
    const small_len = random.below(limits.answer_small_len_max + 1);
    const medium_len = random.between(limits.answer_medium_len_min, limits.answer_medium_len_max);
    const long_len = random.between(limits.answer_long_len_min, limits.answer_long_len_max);
    const longest = random.between(limits.piece_len_min, limits.piece_len_max);
    // h11 carries trailers only on chunked content (RFC 9112 §7.1.2), so only h2 and h3 answers end
    // with one here.
    const trailers = random.below(limits.trailers_one_in) == 0 and major >= h2_major;
    const cancels = random.below(limits.cancel_one_in) == 0;
    const cancel_after = random.below(limits.cancel_after_pieces_max + 1);
    const content_len = if (tier < limits.answer_small_below) small_len else if (tier == limits.answer_medium_draw) medium_len else long_len;
    return .{
        .content_len = @intCast(content_len),
        .longest = @intCast(longest),
        .trailers = trailers,
        .cancel_after = if (cancels) @intCast(cancel_after) else null,
    };
}

/// How long after its request's head the program starts an answer: at once, or in one answer of
/// `answer_delay_one_in` up to `answer_delay_ms_max` later.
fn delay_of(random: *Random) u64 {
    const delay_ms = random.below(limits.answer_delay_ms_max + 1);
    return if (random.below(limits.answer_delay_one_in) == 0) delay_ms else 0;
}

/// RFC 9110 §2.5: h2 is version 2.0 and h3 version 3.0.
const h2_major: u8 = 2;

/// What one write did to an answer.
const Step = enum { more, moved, stopped };

/// Writes what the request's answer owes, until it is whole, waits for room, or is cancelled.
/// Returns whether the endpoint took anything.
pub fn write(program: *Program, request: *Request, random: *Random) Violation!bool {
    if (request.answer.waiting or !request.open or program.now_ms < request.answer.due_ms) return false;
    var moved = false;
    // Bounded: each pass takes a piece whole, or stops.
    for (0..limits.pieces_max + passes_besides_pieces) |_| {
        switch (try step(program, request, random)) {
            .more => moved = true,
            .moved => return true,
            .stopped => return moved,
        }
    }
    unreachable;
}

/// The writes of an answer besides its pieces: its head, its trailer section and its cancel.
const passes_besides_pieces: u32 = 3;

fn step(program: *Program, request: *Request, random: *Random) Violation!Step {
    const answer = &request.answer;
    const writing = answer.phase == .head or answer.phase == .content;
    if (writing and answer.cancel_after == answer.pieces) {
        try program.cancel(request);
        answer.phase = .cancelled;
        return .moved;
    }
    return switch (answer.phase) {
        .head => write_head(program, request),
        .content => write_content(program, request, random),
        .trailers => write_trailer_section(program, request),
        .unready, .ended, .cancelled, .abandoned => .stopped,
    };
}

fn write_head(program: *Program, request: *Request) Violation!Step {
    const answer = &request.answer;
    const end = answer.content_len == 0 and !answer.trailers;
    if (try program.respond(request.id, .{ .status = status, .end = end })) |failure| return refused(program, request, failure);
    answer.phase = if (end) .ended else if (answer.content_len == 0) .trailers else .content;
    return .more;
}

fn write_content(program: *Program, request: *Request, random: *Random) Violation!Step {
    const answer = &request.answer;
    assert(answer.written < answer.content_len);
    if (answer.piece_len == 0) {
        const drawn = random.between(answer.longest / limits.piece_len_divisor, answer.longest);
        answer.piece_len = @intCast(@min(drawn, answer.content_len - answer.written));
        answer.piece_taken = 0;
    }
    const octets = piece_of(program, answer);
    const end = answer.written + octets.len == answer.content_len and !answer.trailers;
    const written = try program.write_body(request.id, .{ .octets = octets, .end = end });
    if (written.failure) |failure| return refused(program, request, failure);
    answer.written += @intCast(written.taken);
    answer.piece_taken += @intCast(written.taken);
    if (written.taken < octets.len) {
        answer.waiting = true;
        return if (written.taken > 0) .moved else .stopped;
    }
    answer.pieces += 1;
    answer.piece_len = 0;
    if (answer.written == answer.content_len) answer.phase = if (answer.trailers) .trailers else .ended;
    return .more;
}

/// The rest of the piece the answer writes now.
fn piece_of(program: *Program, answer: *const Answer) []const u8 {
    const left = answer.piece_len - answer.piece_taken;
    return program.content[answer.written..][0..left];
}

fn write_trailer_section(program: *Program, request: *Request) Violation!Step {
    if (try program.write_trailers(request.id, &trailer_fields)) |failure| return refused(program, request, failure);
    request.answer.phase = .ended;
    return .more;
}

/// A write found no room, so the request waits for its `writable`; or its connection closes and
/// writes no more, so the program waits for its `cancelled`.
fn refused(program: *Program, request: *Request, failure: server.SendError) Violation!Step {
    switch (failure) {
        error.NoSpaceLeft, error.Blocked => request.answer.waiting = true,
        error.ConnectionClosed => request.answer.phase = .abandoned,
        // P3: an open request's id names it until its ending.
        error.RequestUnknown => return program.fail(error.RequestLost, "write", request.id.connection, request.id.number),
        else => return program.fail(error.WriteRefused, "write", request.id.connection, request.id.number),
    }
    return .stopped;
}

/// The instant after `now_ms` an answer the program delayed starts, or null.
pub fn due_ms(request: *const Request, now_ms: u64) ?u64 {
    const answer = &request.answer;
    if (!request.open or answer.waiting or answer.due_ms <= now_ms) return null;
    return switch (answer.phase) {
        .head, .content, .trailers => answer.due_ms,
        .unready, .ended, .cancelled, .abandoned => null,
    };
}

/// P6: repeats the write a waiting request found no room for. Returns whether the endpoint took
/// it, which it may not with no `writable` first.
pub fn probe(program: *Program, request: *Request) Violation!bool {
    const answer = &request.answer;
    assert(answer.waiting);
    switch (answer.phase) {
        .head => {
            const end = answer.content_len == 0 and !answer.trailers;
            const failure = try program.respond(request.id, .{ .status = status, .end = end }) orelse return true;
            return probe_taken(program, request, failure);
        },
        .content => {
            const octets = piece_of(program, answer);
            const end = answer.written + octets.len == answer.content_len and !answer.trailers;
            const written = try program.write_body(request.id, .{ .octets = octets, .end = end });
            // A take of nothing is the endpoint's refusal too.
            const failure = written.failure orelse return written.taken > 0;
            return probe_taken(program, request, failure);
        },
        .trailers => {
            const failure = try program.write_trailers(request.id, &trailer_fields) orelse return true;
            return probe_taken(program, request, failure);
        },
        .unready, .ended, .cancelled, .abandoned => unreachable,
    }
}

/// Whether a repeated write took anything: it did unless the endpoint refused it as it documents
/// for that write, `respond` with `NoSpaceLeft`, `write_body` with `Blocked` or `NoSpaceLeft`, and
/// `write_trailers` with either, or any of them on a connection that closes. P3: once the
/// endpoint owes no event, an open request's id names it still.
fn probe_taken(program: *Program, request: *const Request, failure: server.SendError) Violation!bool {
    return switch (failure) {
        error.NoSpaceLeft, error.ConnectionClosed => false,
        error.Blocked => request.answer.phase == .head,
        error.RequestUnknown => program.fail(error.RequestLost, "probe", request.id.connection, request.id.number),
        else => true,
    };
}
