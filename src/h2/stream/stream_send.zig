//! The send side of the stream state machine of RFC 9113 §5.1: one function per state, each the
//! verdict for a frame colibri is asked to send on a stream in that state. `stream.zig` is the
//! entry point that dispatches here after asserting the contract, and its header gives the order
//! every rule decides in (invariant 7): PRIORITY and an unknown kind are ignored (§5.1, §5.5), the
//! kinds the state's paragraph names take their transition, and every other kind is `illegal`,
//! which the connection reports to its caller and never writes, with END_STREAM as a second
//! transition. A verdict here is a pure function of its parameters (invariant 6).
//!
//! An unknown kind is `ignore` on send in every state, the closed states included. §5.1's closing
//! paragraph limits every rule in the section, its MUST NOTs on sending among them, to the frames
//! RFC 9113 defines, and §5.5 says the conditions for sending an extension frame are unknown to
//! it. The extension that defines a frame carries its own rule, and colibri sends none.
const std = @import("std");
const stream = @import("stream.zig");
const Role = @import("../role.zig").Role;

const Closed = stream.Closed;
const Kind = stream.Kind;
const State = stream.State;
const Verdict = stream.Verdict;
const after_frame = stream.after_frame;

/// Idle: a client's HEADERS opens the stream, PRIORITY may be sent, and no other frame sent
/// leaves the idle state (RFC 9113 §5.1, §6.4).
pub fn in_idle(kind: Kind, end_stream: bool, role: Role, peer_initiated: bool) Verdict {
    return switch (kind) {
        .headers => headers_in_idle(end_stream, role, peer_initiated),
        // RFC 9113 §5.1: PRIORITY can be sent in any stream state; RFC 9113 §5.5: §5.1's rules do
        // not apply to a frame it does not define.
        .priority, .unknown => .ignore,
        // RFC 9113 §6.4: RST_STREAM frames MUST NOT be sent for a stream in the idle state.
        .rst_stream => .illegal,
        // RFC 9113 §5.1: no other frame sent leaves the idle state.
        .data, .window_update, .push_promise => .illegal,
    };
}

fn headers_in_idle(end_stream: bool, role: Role, peer_initiated: bool) Verdict {
    // RFC 9113 §5.1: sending a HEADERS frame as a client opens the stream; a server reserves a
    // stream with PUSH_PROMISE and sends HEADERS from reserved (local).
    if (role != .client) return .illegal;
    // RFC 9113 §5.1.1: a stream a client initiates uses an odd identifier, its own parity.
    if (peer_initiated) return .illegal;
    return after_frame(.open, end_stream, .send);
}

/// Reserved (local): HEADERS opens the stream half-closed (remote), RST_STREAM closes, PRIORITY
/// may be sent, and no other frame may (RFC 9113 §5.1).
pub fn in_reserved_local(kind: Kind, end_stream: bool) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: sending a HEADERS frame opens the stream in half-closed (remote).
        .headers => after_frame(.half_closed_remote, end_stream, .send),
        // RFC 9113 §5.1: either endpoint can send a RST_STREAM frame to close the stream.
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: an endpoint MUST NOT send any type of frame other than HEADERS,
        // RST_STREAM, or PRIORITY in this state.
        .data, .window_update, .push_promise => .illegal,
    };
}

/// Reserved (remote): RST_STREAM closes, WINDOW_UPDATE and PRIORITY may be sent, and no other
/// frame may (RFC 9113 §5.1).
pub fn in_reserved_remote(kind: Kind) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: either endpoint can send a RST_STREAM frame to close the stream.
        .rst_stream => .{ .state = .closed },
        .window_update => .{ .state = .reserved_remote },
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: an endpoint MUST NOT send any type of frame other than RST_STREAM,
        // WINDOW_UPDATE, or PRIORITY in this state.
        .data, .headers, .push_promise => .illegal,
    };
}

/// Open: any kind, END_STREAM makes half-closed (local), RST_STREAM closes (RFC 9113 §5.1).
pub fn in_open(kind: Kind, end_stream: bool) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: an open stream may be used by both peers to send frames of any type,
        // and sending END_STREAM makes it half-closed (local).
        .data, .headers => after_frame(.open, end_stream, .send),
        .window_update, .push_promise => .{ .state = .open },
        // RFC 9113 §5.1: either endpoint can send a RST_STREAM frame, which closes the stream.
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
    };
}

/// Half-closed (local): WINDOW_UPDATE, PRIORITY and RST_STREAM alone, and nothing else may be
/// sent (RFC 9113 §5.1).
pub fn in_half_closed_local(kind: Kind) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: a half-closed (local) stream can send WINDOW_UPDATE, PRIORITY and
        // RST_STREAM, and RST_STREAM closes it.
        .window_update => .{ .state = .half_closed_local },
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: a half-closed (local) stream cannot be used for sending frames other
        // than WINDOW_UPDATE, PRIORITY, and RST_STREAM.
        .data, .headers, .push_promise => .illegal,
    };
}

/// Half-closed (remote): any kind, END_STREAM or RST_STREAM closes (RFC 9113 §5.1).
pub fn in_half_closed_remote(kind: Kind, end_stream: bool) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: the endpoint can send frames of any type, and closes the stream by
        // sending a frame with END_STREAM.
        .data, .headers => after_frame(.half_closed_remote, end_stream, .send),
        .window_update, .push_promise => .{ .state = .half_closed_remote },
        // RFC 9113 §5.1: the stream closes when either peer sends a RST_STREAM frame.
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
    };
}

/// Closed: PRIORITY alone, however the stream closed (RFC 9113 §5.1, §5.4.2, §6.4).
pub fn in_closed(kind: Kind) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: PRIORITY can be sent in any stream state.
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: an endpoint MUST NOT send frames other than PRIORITY on a closed stream.
        // RFC 9113 §6.4: after receiving a RST_STREAM, no frame but PRIORITY may follow. RFC 9113
        // §5.4.2: an endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM.
        .data, .headers, .rst_stream, .window_update, .push_promise => .illegal,
    };
}

// Tests. Each walks one state over every kind through `stream.on_send`, naming the RFC 9113 §5.1
// paragraph it checks. The idle walk leaves HEADERS to the parity test, which fixes the role.

const testing = std.testing;

/// One frame and the verdict RFC 9113 §5.1 gives it.
const Case = struct { kind: Kind, end_stream: bool = false, verdict: Verdict };

/// Runs every case in `state` under both roles and both parities, which decide nothing outside
/// idle, so a walk also shows the state's rule is independent of them.
fn expect_walk(state: State, closed: ?Closed, cases: []const Case) !void {
    for (cases) |case| {
        for ([_]Role{ .client, .server }) |role| {
            for ([_]bool{ false, true }) |peer_initiated| {
                const verdict = stream.on_send(state, closed, case.kind, case.end_stream, role, peer_initiated);
                testing.expectEqual(case.verdict, verdict) catch |err| {
                    std.debug.print("send {s} {s} end_stream={}\n", .{ @tagName(state), @tagName(case.kind), case.end_stream });
                    return err;
                };
            }
        }
    }
}

test "idle: HEADERS aside, PRIORITY alone is permitted and every other kind is illegal (§5.1, §6.4)" {
    try expect_walk(.idle, null, &.{
        .{ .kind = .data, .verdict = .illegal },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .illegal },
        .{ .kind = .window_update, .verdict = .illegal },
        .{ .kind = .push_promise, .verdict = .illegal },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "idle, HEADERS: only a client on its own parity opens the stream (§5.1, §5.1.1)" {
    try testing.expectEqual(Verdict{ .state = .open }, stream.on_send(.idle, null, .headers, false, .client, false));
    try testing.expectEqual(Verdict{ .state = .half_closed_local }, stream.on_send(.idle, null, .headers, true, .client, false));
    try testing.expectEqual(Verdict.illegal, stream.on_send(.idle, null, .headers, false, .client, true));
    try testing.expectEqual(Verdict.illegal, stream.on_send(.idle, null, .headers, false, .server, false));
    try testing.expectEqual(Verdict.illegal, stream.on_send(.idle, null, .headers, false, .server, true));
}

test "reserved (local): HEADERS opens half-closed (remote), RST_STREAM closes, the rest is illegal (§5.1)" {
    try expect_walk(.reserved_local, null, &.{
        .{ .kind = .data, .verdict = .illegal },
        .{ .kind = .headers, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .headers, .end_stream = true, .verdict = .{ .state = .closed } },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .illegal },
        .{ .kind = .push_promise, .verdict = .illegal },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "reserved (remote): RST_STREAM closes, WINDOW_UPDATE and PRIORITY may go, the rest is illegal (§5.1)" {
    try expect_walk(.reserved_remote, null, &.{
        .{ .kind = .data, .verdict = .illegal },
        .{ .kind = .headers, .verdict = .illegal },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .reserved_remote } },
        .{ .kind = .push_promise, .verdict = .illegal },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "open: any kind, END_STREAM makes half-closed (local), RST_STREAM closes (§5.1)" {
    try expect_walk(.open, null, &.{
        .{ .kind = .data, .verdict = .{ .state = .open } },
        .{ .kind = .data, .end_stream = true, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .headers, .verdict = .{ .state = .open } },
        .{ .kind = .headers, .end_stream = true, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .open } },
        .{ .kind = .push_promise, .verdict = .{ .state = .open } },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "half-closed (local): WINDOW_UPDATE, PRIORITY and RST_STREAM alone, the rest is illegal (§5.1)" {
    try expect_walk(.half_closed_local, null, &.{
        .{ .kind = .data, .verdict = .illegal },
        .{ .kind = .headers, .verdict = .illegal },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .push_promise, .verdict = .illegal },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "half-closed (remote): any kind, END_STREAM or RST_STREAM closes (§5.1)" {
    try expect_walk(.half_closed_remote, null, &.{
        .{ .kind = .data, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .data, .end_stream = true, .verdict = .{ .state = .closed } },
        .{ .kind = .headers, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .headers, .end_stream = true, .verdict = .{ .state = .closed } },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .push_promise, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "closed: PRIORITY alone, however the stream closed, and never a RST_STREAM in answer to one (§5.1, §5.4.2, §6.4)" {
    for (std.enums.values(Closed)) |closed| {
        try expect_walk(.closed, closed, &.{
            .{ .kind = .data, .verdict = .illegal },
            .{ .kind = .headers, .verdict = .illegal },
            .{ .kind = .priority, .verdict = .ignore },
            .{ .kind = .rst_stream, .verdict = .illegal },
            .{ .kind = .window_update, .verdict = .illegal },
            .{ .kind = .push_promise, .verdict = .illegal },
            .{ .kind = .unknown, .verdict = .ignore },
        });
    }
}
