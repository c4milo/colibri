//! The receive side of the stream state machine of RFC 9113 §5.1: one function per state, each
//! the verdict for a frame the peer sent on a stream in that state. `stream.zig` is the entry
//! point that dispatches here after asserting the contract, and its header gives the order every
//! rule decides in (invariant 7): PRIORITY and an unknown kind are ignored (§5.1, §5.5), the kinds
//! the state's paragraph names take their transition, and every other kind takes the connection
//! error or the stream error that paragraph states, with END_STREAM as a second transition. A
//! verdict here is a pure function of its parameters (invariant 6), and no assertion reads a wire
//! value (invariant 24).
const std = @import("std");
const stream = @import("stream.zig");
const Role = @import("../role.zig").Role;

const Closed = stream.Closed;
const Kind = stream.Kind;
const State = stream.State;
const Verdict = stream.Verdict;
const after_frame = stream.after_frame;
const protocol_error = stream.protocol_error;
const stream_closed_connection_error = stream.stream_closed_connection_error;
const stream_closed_stream_error = stream.stream_closed_stream_error;

/// Idle: HEADERS opens the stream under the parity rule, PRIORITY may arrive, and anything else is
/// a connection error (RFC 9113 §5.1).
pub fn in_idle(kind: Kind, end_stream: bool, role: Role, peer_initiated: bool) Verdict {
    return switch (kind) {
        .headers => headers_in_idle(end_stream, role, peer_initiated),
        // RFC 9113 §5.1: PRIORITY can be received in any stream state. RFC 9113 §5.5: a frame of
        // unknown type is discarded, and §5.1's rules apply only to the frames it defines.
        .priority, .unknown => .ignore,
        // RFC 9113 §6.4: a RST_STREAM frame identifying an idle stream is a connection error of
        // PROTOCOL_ERROR.
        .rst_stream => protocol_error,
        // RFC 9113 §5.1: receiving any frame other than HEADERS or PRIORITY on an idle stream is a
        // connection error of PROTOCOL_ERROR.
        .data, .window_update, .push_promise => protocol_error,
    };
}

fn headers_in_idle(end_stream: bool, role: Role, peer_initiated: bool) Verdict {
    // RFC 9113 §5.1: if the stream is initiated by the server (§5.1.1), receiving a HEADERS frame
    // is a connection error of PROTOCOL_ERROR.
    if (stream.initiated_by_server(role, peer_initiated)) return protocol_error;
    // RFC 9113 §5.1: receiving a HEADERS frame as a server opens the stream. A client has no such
    // transition, and a frame a state does not expressly permit is a connection error of
    // PROTOCOL_ERROR.
    if (role != .server) return protocol_error;
    return after_frame(.open, end_stream, .receive);
}

/// Reserved (local): RST_STREAM closes, PRIORITY and WINDOW_UPDATE may arrive, and anything else
/// is a connection error (RFC 9113 §5.1).
pub fn in_reserved_local(kind: Kind) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: either endpoint can send a RST_STREAM frame to close the stream.
        .rst_stream => .{ .state = .closed },
        // RFC 9113 §5.1: a PRIORITY or WINDOW_UPDATE frame MAY be received in this state.
        .window_update => .{ .state = .reserved_local },
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: receiving any type of frame other than RST_STREAM, PRIORITY, or
        // WINDOW_UPDATE in this state is a connection error of PROTOCOL_ERROR.
        .data, .headers, .push_promise => protocol_error,
    };
}

/// Reserved (remote): HEADERS moves to half-closed (local), RST_STREAM closes, PRIORITY may
/// arrive, and anything else is a connection error (RFC 9113 §5.1).
pub fn in_reserved_remote(kind: Kind, end_stream: bool) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: receiving a HEADERS frame moves the stream to half-closed (local).
        .headers => after_frame(.half_closed_local, end_stream, .receive),
        // RFC 9113 §5.1: either endpoint can send a RST_STREAM frame to close the stream.
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: receiving any type of frame other than HEADERS, RST_STREAM, or PRIORITY
        // in this state is a connection error of PROTOCOL_ERROR.
        .data, .window_update, .push_promise => protocol_error,
    };
}

/// Open: any kind, END_STREAM makes half-closed (remote), RST_STREAM closes (RFC 9113 §5.1).
pub fn in_open(kind: Kind, end_stream: bool) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: an open stream may be used by both peers to send frames of any type,
        // and receiving END_STREAM makes it half-closed (remote).
        .data, .headers => after_frame(.open, end_stream, .receive),
        .window_update, .push_promise => .{ .state = .open },
        // RFC 9113 §5.1: either endpoint can send a RST_STREAM frame, which closes the stream.
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
    };
}

/// Half-closed (local): any kind, END_STREAM or RST_STREAM closes (RFC 9113 §5.1).
pub fn in_half_closed_local(kind: Kind, end_stream: bool) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: an endpoint can receive any type of frame in this state, and the stream
        // closes when a frame with END_STREAM is received.
        .data, .headers => after_frame(.half_closed_local, end_stream, .receive),
        .window_update, .push_promise => .{ .state = .half_closed_local },
        // RFC 9113 §5.1: the stream closes when either peer sends a RST_STREAM frame.
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
    };
}

/// Half-closed (remote): WINDOW_UPDATE, PRIORITY and RST_STREAM alone, and anything else is a
/// stream error of STREAM_CLOSED (RFC 9113 §5.1).
pub fn in_half_closed_remote(kind: Kind) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: WINDOW_UPDATE, PRIORITY and RST_STREAM are the frames the peer may still
        // send, and RST_STREAM closes the stream.
        .window_update => .{ .state = .half_closed_remote },
        .rst_stream => .{ .state = .closed },
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: receiving frames other than WINDOW_UPDATE, PRIORITY, or RST_STREAM on a
        // half-closed (remote) stream is a stream error of STREAM_CLOSED.
        .data, .headers, .push_promise => stream_closed_stream_error,
    };
}

/// Closed: the verdict for a late frame depends on how the stream closed (RFC 9113 §5.1, §5.4.2).
pub fn in_closed(kind: Kind, closed: Closed) Verdict {
    return switch (closed) {
        .end_stream => in_closed_by_end_stream(kind),
        // RFC 9113 §5.1: an endpoint that sent RST_STREAM minimally processes and then discards
        // any frame it receives on the stream; RFC 9113 §5.4.2: the peer may have sent them before
        // it saw the RST_STREAM.
        .rst_stream_sent => .ignore,
        .rst_stream_received => in_closed_by_rst_stream_received(kind),
    };
}

fn in_closed_by_end_stream(kind: Kind) Verdict {
    return switch (kind) {
        // RFC 9113 §5.1: an endpoint that sent END_STREAM might receive a WINDOW_UPDATE or
        // RST_STREAM before the peer processes the frame that closed the stream.
        .window_update, .rst_stream => .ignore,
        .priority, .unknown => .ignore,
        // RFC 9113 §5.1: an endpoint MAY treat receipt of any other type of frame on a closed
        // stream as a connection error of STREAM_CLOSED, and colibri does.
        .data, .headers, .push_promise => stream_closed_connection_error,
    };
}

fn in_closed_by_rst_stream_received(kind: Kind) Verdict {
    return switch (kind) {
        .priority, .unknown => .ignore,
        // RFC 9113 §5.4.2: an endpoint MAY send additional RST_STREAM frames if it receives frames
        // on a closed stream after more than a round-trip time. The receiver cannot see that
        // condition, so a further RST_STREAM from the peer that reset the stream is discarded.
        .rst_stream => .ignore,
        // RFC 9113 §5.1: receipt of a frame other than PRIORITY on a closed stream is a connection
        // error of STREAM_CLOSED, and on a stream the peer closed no frame still in transit
        // excuses a late one.
        .data, .headers, .window_update, .push_promise => stream_closed_connection_error,
    };
}

// Tests. Each walks one state over every kind through `stream.on_receive`, naming the RFC 9113
// §5.1 paragraph it checks. The idle walk leaves HEADERS to the parity test, which fixes the role.

const testing = std.testing;

/// One frame and the verdict RFC 9113 §5.1 gives it.
const Case = struct { kind: Kind, end_stream: bool = false, verdict: Verdict };

/// Runs every case in `state` under both roles and both parities, which decide nothing outside
/// idle, so a walk also shows the state's rule is independent of them.
fn expect_walk(state: State, closed: ?Closed, cases: []const Case) !void {
    for (cases) |case| {
        for ([_]Role{ .client, .server }) |role| {
            for ([_]bool{ false, true }) |peer_initiated| {
                const verdict = stream.on_receive(state, closed, case.kind, case.end_stream, role, peer_initiated);
                testing.expectEqual(case.verdict, verdict) catch |err| {
                    std.debug.print("receive {s} {s} end_stream={}\n", .{ @tagName(state), @tagName(case.kind), case.end_stream });
                    return err;
                };
            }
        }
    }
}

test "idle: HEADERS aside, PRIORITY alone is permitted and every other kind is a PROTOCOL_ERROR (§5.1, §6.4)" {
    try expect_walk(.idle, null, &.{
        .{ .kind = .data, .verdict = protocol_error },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = protocol_error },
        .{ .kind = .window_update, .verdict = protocol_error },
        .{ .kind = .push_promise, .verdict = protocol_error },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "idle, HEADERS: only a server on a client-initiated stream opens it (§5.1, §5.1.1)" {
    try testing.expectEqual(Verdict{ .state = .open }, stream.on_receive(.idle, null, .headers, false, .server, true));
    try testing.expectEqual(Verdict{ .state = .half_closed_remote }, stream.on_receive(.idle, null, .headers, true, .server, true));
    // The stream is server-initiated: the server's own parity, or the client's peer's.
    try testing.expectEqual(protocol_error, stream.on_receive(.idle, null, .headers, false, .server, false));
    try testing.expectEqual(protocol_error, stream.on_receive(.idle, null, .headers, false, .client, true));
    // A client-initiated stream the client never opened.
    try testing.expectEqual(protocol_error, stream.on_receive(.idle, null, .headers, false, .client, false));
}

test "reserved (local): RST_STREAM closes, WINDOW_UPDATE and PRIORITY may arrive, the rest is a PROTOCOL_ERROR (§5.1)" {
    try expect_walk(.reserved_local, null, &.{
        .{ .kind = .data, .verdict = protocol_error },
        .{ .kind = .headers, .verdict = protocol_error },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .reserved_local } },
        .{ .kind = .push_promise, .verdict = protocol_error },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "reserved (remote): HEADERS moves to half-closed (local), RST_STREAM closes, the rest is a PROTOCOL_ERROR (§5.1)" {
    try expect_walk(.reserved_remote, null, &.{
        .{ .kind = .data, .verdict = protocol_error },
        .{ .kind = .headers, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .headers, .end_stream = true, .verdict = .{ .state = .closed } },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = protocol_error },
        .{ .kind = .push_promise, .verdict = protocol_error },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "open: any kind, END_STREAM makes half-closed (remote), RST_STREAM closes (§5.1)" {
    try expect_walk(.open, null, &.{
        .{ .kind = .data, .verdict = .{ .state = .open } },
        .{ .kind = .data, .end_stream = true, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .headers, .verdict = .{ .state = .open } },
        .{ .kind = .headers, .end_stream = true, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .open } },
        .{ .kind = .push_promise, .verdict = .{ .state = .open } },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "half-closed (local): any kind, END_STREAM or RST_STREAM closes (§5.1)" {
    try expect_walk(.half_closed_local, null, &.{
        .{ .kind = .data, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .data, .end_stream = true, .verdict = .{ .state = .closed } },
        .{ .kind = .headers, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .headers, .end_stream = true, .verdict = .{ .state = .closed } },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .push_promise, .verdict = .{ .state = .half_closed_local } },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "half-closed (remote): WINDOW_UPDATE, PRIORITY and RST_STREAM alone, the rest is a stream error STREAM_CLOSED (§5.1)" {
    try expect_walk(.half_closed_remote, null, &.{
        .{ .kind = .data, .verdict = stream_closed_stream_error },
        .{ .kind = .headers, .verdict = stream_closed_stream_error },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .{ .state = .closed } },
        .{ .kind = .window_update, .verdict = .{ .state = .half_closed_remote } },
        .{ .kind = .push_promise, .verdict = stream_closed_stream_error },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "closed by END_STREAM: WINDOW_UPDATE and RST_STREAM are ignored, the rest is a connection error STREAM_CLOSED (§5.1)" {
    try expect_walk(.closed, .end_stream, &.{
        .{ .kind = .data, .verdict = stream_closed_connection_error },
        .{ .kind = .headers, .verdict = stream_closed_connection_error },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .ignore },
        .{ .kind = .window_update, .verdict = .ignore },
        .{ .kind = .push_promise, .verdict = stream_closed_connection_error },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "closed by a RST_STREAM colibri sent: every kind is ignored (§5.1, §5.4.2)" {
    try expect_walk(.closed, .rst_stream_sent, &.{
        .{ .kind = .data, .verdict = .ignore },
        .{ .kind = .headers, .verdict = .ignore },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .ignore },
        .{ .kind = .window_update, .verdict = .ignore },
        .{ .kind = .push_promise, .verdict = .ignore },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}

test "closed by a RST_STREAM received: PRIORITY and a further RST_STREAM are ignored, the rest is a connection error STREAM_CLOSED (§5.1, §5.4.2)" {
    try expect_walk(.closed, .rst_stream_received, &.{
        .{ .kind = .data, .verdict = stream_closed_connection_error },
        .{ .kind = .headers, .verdict = stream_closed_connection_error },
        .{ .kind = .priority, .verdict = .ignore },
        .{ .kind = .rst_stream, .verdict = .ignore },
        .{ .kind = .window_update, .verdict = stream_closed_connection_error },
        .{ .kind = .push_promise, .verdict = stream_closed_connection_error },
        .{ .kind = .unknown, .verdict = .ignore },
    });
}
