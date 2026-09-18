//! The stream state machine of RFC 9113 §5.1, as pure functions over a state. This file keeps no
//! record and no table: the stream record, the identifier rules of §5.1.1 and the concurrency
//! limit of §5.1.2 are the next layer's, over core's slot pool (decision 14). A verdict is a pure
//! function of the state, how a closed stream closed, the frame kind, its END_STREAM flag, the
//! endpoint's role and whether the peer initiated the stream, which keeps a connection's output a
//! function of its inputs (invariant 6).
//!
//! `on_receive` and `on_send` decide a frame on the stream it names, one rule per state in
//! `stream_receive.zig` and `stream_send.zig`. `on_reserve` decides the promised stream of a
//! PUSH_PROMISE, which §5.1 moves from idle to reserved. `closed_kind_after` names how a frame
//! closed a stream. CONTINUATION never arrives here: §5.1 makes it part of the HEADERS or
//! PUSH_PROMISE it follows, with no transition of its own.
//!
//! Each entry point decides in this order (invariant 7):
//!   1. the contract, asserted because both values are the caller's own computation: `closed` is
//!      set exactly when the state is closed, and END_STREAM is set only on DATA or HEADERS;
//!   2. the state selects its rule, one function per state and direction;
//!   3. within a state, PRIORITY and an unknown kind are ignored (§5.1, §5.5), the kinds the
//!      state's paragraph names take their transition, and every other kind takes the error or
//!      the refusal that paragraph states;
//!   4. a DATA or HEADERS frame with END_STREAM takes a second transition from the state the
//!      first left, because §5.1 processes the flag as a separate event.
//!
//! On receive, a frame the state forbids is a connection error or a stream error with the code
//! §5.1 names; invariant 27 keeps the two apart and the codes are `constants.zig`'s (invariant
//! 28). On send, a frame colibri may not send is `illegal`, which the connection reports to its
//! caller and never writes. No assertion reads a wire value (invariant 24).
//!
//! Where §5.1 leaves a choice, colibri takes the strict side. A frame other than PRIORITY,
//! WINDOW_UPDATE or RST_STREAM received on a stream closed by END_STREAM in both directions is a
//! connection error of STREAM_CLOSED, the MAY of §5.1 that h2spec expects, and so is any frame
//! but PRIORITY and RST_STREAM after a RST_STREAM was received: §5.4.2 lets the peer send
//! additional RST_STREAM frames, and colibri cannot see the round-trip condition that permits
//! them, so a second RST_STREAM is discarded. After a RST_STREAM colibri sent, every frame is
//! discarded after the minimal processing the connection does before it asks here (§5.1, §5.4.2).
//! Who may push (§6.6, §8.4) and decision 17's refusal of push are the connection's rules; these
//! files apply §5.1 alone to a PUSH_PROMISE they are shown.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const Role = @import("../role.zig").Role;
const receive = @import("stream_receive.zig");
const send = @import("stream_send.zig");

/// The seven states of RFC 9113 §5.1, Figure 2.
pub const State = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// How a closed stream closed. RFC 9113 §5.1 treats a late frame differently in each case, so
/// the record keeps it beside the state.
pub const Closed = enum {
    /// Both endpoints sent END_STREAM.
    end_stream,
    /// colibri sent RST_STREAM.
    rst_stream_sent,
    /// The peer sent RST_STREAM.
    rst_stream_received,
};

/// The frame kinds RFC 9113 §5.1 names in its transitions. `push_promise` is a PUSH_PROMISE on
/// this stream, the associated stream; the promised stream goes through `on_reserve`. `unknown`
/// is a frame of a type RFC 9113 does not define, which §5.5 discards.
pub const Kind = enum {
    data,
    headers,
    priority,
    rst_stream,
    window_update,
    push_promise,
    unknown,
};

/// Whether colibri sends the frame or receives it.
pub const Direction = enum { send, receive };

/// What the stream does with a frame.
pub const Verdict = union(enum) {
    /// The frame is permitted; the connection processes it and the stream is now in this state,
    /// which may be the state it was in.
    state: State,
    /// The frame changes no state and raises no error. On receive, §5.1 or §5.5 says to
    /// discard it after the minimal processing the connection does before it asks here. On send,
    /// colibri may send it and the stream records nothing.
    ignore,
    /// Receiving the frame in this state is a connection error (RFC 9113 §5.4.1) with this code.
    connection_error: u32,
    /// Receiving the frame in this state is a stream error (RFC 9113 §5.4.2) with this code.
    stream_error: u32,
    /// colibri may not send the frame in this state. The connection reports it to its caller as
    /// an API error and writes nothing.
    illegal,
};

/// The connection error of PROTOCOL_ERROR that RFC 9113 §5.1 gives a frame a state forbids.
pub const protocol_error: Verdict = .{ .connection_error = constants.error_protocol_error };
/// The connection error of STREAM_CLOSED that RFC 9113 §5.1 gives a frame on a closed stream.
pub const stream_closed_connection_error: Verdict = .{ .connection_error = constants.error_stream_closed };
/// The stream error of STREAM_CLOSED that RFC 9113 §5.1 gives a frame on a half-closed (remote)
/// stream.
pub const stream_closed_stream_error: Verdict = .{ .stream_error = constants.error_stream_closed };

/// The verdict for a frame the peer sent on a stream in `state`. `closed` is set exactly when the
/// state is closed. `end_stream` is the END_STREAM flag of a DATA or HEADERS frame and false for
/// every other kind: RFC 9113 §4.1 ignores an undefined flag, so the caller masks by type. `role`
/// and `peer_initiated` decide only the parity rule of an idle stream.
pub fn on_receive(
    state: State,
    closed: ?Closed,
    kind: Kind,
    end_stream: bool,
    role: Role,
    peer_initiated: bool,
) Verdict {
    assert_contract(state, closed, kind, end_stream);
    const verdict = switch (state) {
        .idle => receive.in_idle(kind, end_stream, role, peer_initiated),
        .reserved_local => receive.in_reserved_local(kind),
        .reserved_remote => receive.in_reserved_remote(kind, end_stream),
        .open => receive.in_open(kind, end_stream),
        .half_closed_local => receive.in_half_closed_local(kind, end_stream),
        .half_closed_remote => receive.in_half_closed_remote(kind),
        .closed => receive.in_closed(kind, closed.?),
    };
    assert_closes_by_a_named_kind(verdict, .receive, kind, end_stream);
    return verdict;
}

/// The verdict for a frame colibri is asked to send on a stream in `state`. The parameters are
/// `on_receive`'s.
pub fn on_send(
    state: State,
    closed: ?Closed,
    kind: Kind,
    end_stream: bool,
    role: Role,
    peer_initiated: bool,
) Verdict {
    assert_contract(state, closed, kind, end_stream);
    const verdict = switch (state) {
        .idle => send.in_idle(kind, end_stream, role, peer_initiated),
        .reserved_local => send.in_reserved_local(kind, end_stream),
        .reserved_remote => send.in_reserved_remote(kind),
        .open => send.in_open(kind, end_stream),
        .half_closed_local => send.in_half_closed_local(kind),
        .half_closed_remote => send.in_half_closed_remote(kind, end_stream),
        .closed => send.in_closed(kind),
    };
    assert_closes_by_a_named_kind(verdict, .send, kind, end_stream);
    return verdict;
}

/// The verdict for the promised stream of a PUSH_PROMISE colibri sends or receives on another
/// stream: idle becomes reserved (local) or reserved (remote) by direction (RFC 9113 §5.1).
pub fn on_reserve(state: State, direction: Direction) Verdict {
    if (state != .idle) return switch (direction) {
        // RFC 9113 §6.6: a PUSH_PROMISE that promises a stream not currently idle promises an
        // illegal identifier, a connection error of PROTOCOL_ERROR.
        .receive => protocol_error,
        // RFC 9113 §5.1: only an idle stream is reserved, and §6.6 makes a promise of any other
        // stream illegal, so colibri never sends one.
        .send => .illegal,
    };
    // RFC 9113 §5.1: sending a PUSH_PROMISE makes the promised stream reserved (local), and
    // receiving one makes it reserved (remote).
    return .{ .state = if (direction == .send) .reserved_local else .reserved_remote };
}

/// How the frame closed the stream, for the record to keep: RST_STREAM by direction, else
/// END_STREAM, else null because the frame closes nothing. Meaningful when the verdict's state is
/// closed, where both entry points assert it is not null. It is a function apart from `Verdict`
/// so that the verdict stays one state and the record's `closed` field is computed from three
/// values the caller already holds.
pub fn closed_kind_after(direction: Direction, kind: Kind, end_stream: bool) ?Closed {
    assert(!end_stream or kind == .data or kind == .headers);
    if (kind == .rst_stream) return if (direction == .send) .rst_stream_sent else .rst_stream_received;
    if (end_stream) return .end_stream;
    return null;
}

/// The state after a DATA or HEADERS frame a state permits: `state_after` its own transition,
/// then the second transition of its END_STREAM flag when set.
pub fn after_frame(state_after: State, end_stream: bool, direction: Direction) Verdict {
    return .{ .state = if (end_stream) after_end_stream(state_after, direction) else state_after };
}

/// True when the stream's identifier has the server's parity (RFC 9113 §5.1.1).
pub fn initiated_by_server(role: Role, peer_initiated: bool) bool {
    return (role == .server) != peer_initiated;
}

/// The contract of both entry points: `closed` is set exactly for a closed stream, and END_STREAM
/// is a flag of DATA (RFC 9113 §6.1) and HEADERS (§6.2) alone.
fn assert_contract(state: State, closed: ?Closed, kind: Kind, end_stream: bool) void {
    assert((state == .closed) == (closed != null));
    assert(!end_stream or kind == .data or kind == .headers);
}

/// The postcondition of both entry points: a verdict that closes the stream closes it by a kind
/// `closed_kind_after` names.
fn assert_closes_by_a_named_kind(verdict: Verdict, direction: Direction, kind: Kind, end_stream: bool) void {
    const closes = verdict == .state and verdict.state == .closed;
    assert(!closes or closed_kind_after(direction, kind, end_stream) != null);
}

/// The transition END_STREAM causes from the state the frame's own transition left. RFC 9113
/// §5.1 processes the flag as a separate event: receiving it moves open to half-closed (remote),
/// sending it moves open to half-closed (local), and either closes a stream already half-closed
/// in the other direction.
fn after_end_stream(state: State, direction: Direction) State {
    assert(state == .open or state == .half_closed_local or state == .half_closed_remote);
    if (state == .open) return if (direction == .receive) .half_closed_remote else .half_closed_local;
    assert((state == .half_closed_local) == (direction == .receive));
    return .closed;
}

// Tests of the entry points' shared rules. The per-state walks are in the direction files.

const testing = std.testing;

test "on_reserve: an idle stream becomes reserved by direction, and a promise of any other stream is refused (§5.1, §6.6)" {
    try testing.expectEqual(Verdict{ .state = .reserved_local }, on_reserve(.idle, .send));
    try testing.expectEqual(Verdict{ .state = .reserved_remote }, on_reserve(.idle, .receive));
    for (std.enums.values(State)) |state| {
        if (state == .idle) continue;
        try testing.expectEqual(protocol_error, on_reserve(state, .receive));
        try testing.expectEqual(Verdict.illegal, on_reserve(state, .send));
    }
}

test "each verdict constant carries the error kind and the RFC 9113 §7 code its name promises" {
    // RFC 9113 §7: PROTOCOL_ERROR is 0x01 and STREAM_CLOSED is 0x05. The literals are intentional:
    // the per-state walks compare against these constants, so only a test that states the code
    // and the kind on its own can tell a wrong code or a connection-versus-stream flip
    // (invariants 27 and 28).
    try testing.expectEqual(Verdict{ .connection_error = 0x01 }, protocol_error);
    try testing.expectEqual(Verdict{ .connection_error = 0x05 }, stream_closed_connection_error);
    try testing.expectEqual(Verdict{ .stream_error = 0x05 }, stream_closed_stream_error);
}

test "closed_kind_after names a RST_STREAM by direction, then END_STREAM, and nothing else" {
    try testing.expectEqual(Closed.rst_stream_sent, closed_kind_after(.send, .rst_stream, false));
    try testing.expectEqual(Closed.rst_stream_received, closed_kind_after(.receive, .rst_stream, false));
    try testing.expectEqual(Closed.end_stream, closed_kind_after(.receive, .data, true));
    try testing.expectEqual(Closed.end_stream, closed_kind_after(.send, .headers, true));
    try testing.expectEqual(null, closed_kind_after(.send, .headers, false));
    try testing.expectEqual(null, closed_kind_after(.receive, .window_update, false));
    try testing.expectEqual(null, closed_kind_after(.receive, .priority, false));
}

test "END_STREAM is a second transition: open half-closes by direction, and a half-closed stream closes (§5.1)" {
    try testing.expectEqual(Verdict{ .state = .open }, after_frame(.open, false, .receive));
    try testing.expectEqual(Verdict{ .state = .half_closed_remote }, after_frame(.open, true, .receive));
    try testing.expectEqual(Verdict{ .state = .half_closed_local }, after_frame(.open, true, .send));
    try testing.expectEqual(Verdict{ .state = .closed }, after_frame(.half_closed_local, true, .receive));
    try testing.expectEqual(Verdict{ .state = .closed }, after_frame(.half_closed_remote, true, .send));
}

test "a stream is server-initiated when its parity is the server's, seen from either role (§5.1.1)" {
    try testing.expect(initiated_by_server(.server, false));
    try testing.expect(initiated_by_server(.client, true));
    try testing.expect(!initiated_by_server(.server, true));
    try testing.expect(!initiated_by_server(.client, false));
}

test "PRIORITY and an unknown kind are ignored in every state, both ways (§5.1, §5.5)" {
    for (std.enums.values(State)) |state| {
        for (std.enums.values(Closed)) |closed_kind| {
            const closed: ?Closed = if (state == .closed) closed_kind else null;
            for ([_]Kind{ .priority, .unknown }) |kind| {
                try testing.expectEqual(Verdict.ignore, on_receive(state, closed, kind, false, .server, true));
                try testing.expectEqual(Verdict.ignore, on_send(state, closed, kind, false, .client, false));
            }
        }
    }
}

/// Runs both entry points on `kind` with and without END_STREAM where the contract admits it.
/// The postcondition inside asserts that every verdict of closed has a kind `closed_kind_after`
/// names, so the walk shows that assertion is reached for every admitted input and none aborts.
fn walk_end_stream(state: State, closed: ?Closed, kind: Kind) void {
    const carries_end_stream = kind == .data or kind == .headers;
    for ([_]bool{ false, true }) |end_stream| {
        if (end_stream and !carries_end_stream) continue;
        _ = on_receive(state, closed, kind, end_stream, .server, true);
        _ = on_send(state, closed, kind, end_stream, .client, false);
    }
}

test "every verdict of closed closes by a kind closed_kind_after names, in every state and direction" {
    for (std.enums.values(State)) |state| {
        for (std.enums.values(Closed)) |closed_kind| {
            const closed: ?Closed = if (state == .closed) closed_kind else null;
            for (std.enums.values(Kind)) |kind| walk_end_stream(state, closed, kind);
        }
    }
}
