//! The frames that name a stream (RFC 9000 §19.4 to §19.14), taken on a packet that opened.
//!
//! They are apart from `connection_frames.zig` because they touch three things it does not: the
//! stream table, both state machines of §3.1 and §3.2, and both levels of flow control. Every
//! one of those was built and tested in step 9c; what is new here is the order they are asked in
//! for one frame off the wire.
//!
//! **The order is the rule.** A STREAM frame is checked against §2.1's identifier rules, then
//! §4.6's stream limit, then §4.1's connection-level limit, then the stream's own, and only then
//! does §4.5's final size see it. Each refusal has its own code, so asking in another order
//! would close the connection with the wrong one — a stream past the limit reported as a flow
//! control error, say. Invariant 7 is this: validation precedes interpretation.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const flow = @import("../flow.zig");
const frame_module = @import("../frame/frame.zig");
const frame_stream = @import("../frame/frame_stream.zig");
const stream_id_module = @import("../stream/stream_id.zig");
const stream_table = @import("../stream/stream_table.zig");
const stream_recv = @import("../stream/stream_recv.zig");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;
const Stream = stream_table.Stream;
const StreamId = stream_id_module.StreamId;
const Directionality = stream_id_module.Directionality;

/// Why a stream frame closed the connection. Each names one rule and one code.
pub const Error = error{
    /// RFC 9000 §4.1: the peer sent past a limit this endpoint advertised.
    FlowControl,
    /// RFC 9000 §4.6: the peer opened a stream past the limit this endpoint advertised.
    StreamLimit,
    /// RFC 9000 §4.5: a final size changed, or data arrived beyond one already known.
    FinalSize,
    /// RFC 9000 §3.2, §19.8: a frame on a stream the peer may not send on, or in a direction
    /// the stream does not have.
    StreamState,
    /// The stream table is full or the identifiers ran out, neither of which a peer can cause.
    Internal,
};

/// The code a CONNECTION_CLOSE carries for `failure` (RFC 9000 §20.1).
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        // RFC 9000 §4.1: "A receiver MUST close the connection with an error of type
        // FLOW_CONTROL_ERROR if the sender violates the advertised connection or stream data
        // limits."
        error.FlowControl => error_code.flow_control_error,
        // RFC 9000 §4.6: "An endpoint that receives a frame with a stream ID exceeding the limit
        // it has sent MUST treat this as a connection error of type STREAM_LIMIT_ERROR."
        error.StreamLimit => error_code.stream_limit_error,
        // RFC 9000 §4.5: every one of its rules names FINAL_SIZE_ERROR.
        error.FinalSize => error_code.final_size_error,
        // RFC 9000 §19.8: "An endpoint that receives a STREAM frame for a send-only stream MUST
        // terminate the connection with error STREAM_STATE_ERROR."
        error.StreamState => error_code.stream_state_error,
        // RFC 9000 §11: an endpoint with no more specific code sends INTERNAL_ERROR.
        error.Internal => error_code.internal_error,
    };
}

/// Acts on one frame that names a stream. A frame this file does not take is not one of them.
pub fn apply(connection: *Connection, frame: frame_module.Frame) Error!void {
    switch (frame) {
        .stream => |held| try take_stream(connection, held),
        .reset_stream => |held| try take_reset(connection, held.stream_id, held.final_size),
        .stop_sending => |held| try take_stop_sending(connection, held.stream_id),
        .max_stream_data => |held| try take_max_stream_data(connection, held.stream_id, held.maximum),
        // RFC 9000 §19.11: MAX_STREAMS raises how many this endpoint may open, and §4.6 makes a
        // value below the current one something to ignore rather than an error.
        .max_streams => |held| _ = connection.streams.raise_local_limit(directionality_of(held.directionality), held.maximum),
        // RFC 9000 §19.13, §19.14: the BLOCKED frames say the peer wants to send and cannot.
        // They oblige nothing; §4.1 has a receiver use them to tune, which colibri does not.
        .stream_data_blocked, .streams_blocked => {},
        else => {},
    }
}

/// A STREAM frame (RFC 9000 §19.8), checked in the order §4.1, §4.5 and §4.6 make their rules.
fn take_stream(connection: *Connection, held: frame_stream.Stream) Error!void {
    const id: StreamId = .{ .value = held.stream_id };
    const stream = try receivable_stream(connection, id) orelse return;
    const reached = held.offset + held.data.len;
    // RFC 9000 §4.1: the connection-level limit counts every octet of every stream, and it is
    // checked before the stream's own so a peer past both is told the connection is the reason.
    try spend_connection_credit(connection, stream, reached);
    // §4.1: the stream's own limit, which this endpoint advertised in MAX_STREAM_DATA.
    stream.receive_flow.use(reached, flow.Error.FlowControlExceeded) catch return Error.FlowControl;
    // RFC 9000 §4.5: the final size rules, which only make sense once the octets are admitted.
    stream.receiving.on_stream_frame(held.offset, held.data.len, held.fin) catch
        return Error.FinalSize;
    const event: stream_recv.Event = if (held.fin) .received_fin else .received_data;
    // §3.2: a frame the receiving state does not admit is not an error here — §3.2 has an
    // endpoint ignore data on a stream it has already reset or read to the end of.
    _ = stream.receiving.on(event);
}

/// RFC 9000 §4.1: the connection-level flow control counts what is new on this stream alone, so
/// a retransmission of octets already counted does not spend credit twice.
fn spend_connection_credit(connection: *Connection, stream: *Stream, reached: u64) Error!void {
    const already = stream.receive_flow.used;
    if (reached <= already) return;
    const fresh = reached - already;
    const total = connection.receive_flow.used + fresh;
    connection.receive_flow.use(total, flow.Error.FlowControlExceeded) catch return Error.FlowControl;
}

/// A RESET_STREAM frame (RFC 9000 §19.4). §4.5 makes its Final Size the stream's, and the octets
/// it names count against both flow control limits even though they never arrive.
fn take_reset(connection: *Connection, stream_id: u64, final_size: u64) Error!void {
    const id: StreamId = .{ .value = stream_id };
    const stream = try receivable_stream(connection, id) orelse return;
    try spend_connection_credit(connection, stream, final_size);
    stream.receive_flow.use(final_size, flow.Error.FlowControlExceeded) catch return Error.FlowControl;
    // RFC 9000 §4.5: a final size that changes, or one below what already arrived, closes the
    // connection with FINAL_SIZE_ERROR.
    stream.receiving.on_reset(final_size) catch return Error.FinalSize;
    _ = stream.receiving.on(.received_reset);
}

/// A STOP_SENDING frame (RFC 9000 §19.5): the peer wants nothing more on a stream this endpoint
/// sends on, and §3.5 has this endpoint answer with RESET_STREAM.
fn take_stop_sending(connection: *Connection, stream_id: u64) Error!void {
    const id: StreamId = .{ .value = stream_id };
    // RFC 9000 §19.5: "Receiving a STOP_SENDING frame for a locally initiated stream that has
    // not yet been created MUST be treated as a connection error of type STREAM_STATE_ERROR."
    // Checking the identifier is what this frame owes today; §3.5's RESET_STREAM answer is the
    // send path's, and `Sending` moves on `sent_reset` when that frame goes out, not here.
    _ = try sendable_stream(connection, id) orelse return;
}

/// A MAX_STREAM_DATA frame (RFC 9000 §19.10): the peer raised what this endpoint may send.
fn take_max_stream_data(connection: *Connection, stream_id: u64, maximum: u64) Error!void {
    const id: StreamId = .{ .value = stream_id };
    // RFC 9000 §19.10: "Receiving a MAX_STREAM_DATA frame for a receive-only stream MUST be
    // treated as a connection error of type STREAM_STATE_ERROR."
    const stream = try sendable_stream(connection, id) orelse return;
    // §4.1: a limit below one already given is ignored, because frames may be reordered.
    _ = stream.send_flow.raise(maximum);
}

/// The stream a peer's frame names, opening it when the peer's frame is what creates it
/// (RFC 9000 §3.2).
fn receivable_stream(connection: *Connection, id: StreamId) Error!?*Stream {
    // RFC 9000 §19.8: a STREAM frame for a send-only stream is STREAM_STATE_ERROR, which is what
    // this asks — whether the peer may send on a stream of this identifier at all.
    if (!id.is_receivable_by(initiator_of(connection))) return Error.StreamState;
    return open_or_find(connection, id);
}

/// The stream a peer's frame names in the other direction, for the frames that speak about what
/// this endpoint sends (RFC 9000 §19.5, §19.10).
fn sendable_stream(connection: *Connection, id: StreamId) Error!?*Stream {
    if (!id.is_sendable_by(initiator_of(connection))) return Error.StreamState;
    return open_or_find(connection, id);
}

/// Finds the stream, or opens it because RFC 9000 §3.2 makes a peer's frame what creates one.
/// Null means the stream has closed and the frame is ignored.
fn open_or_find(connection: *Connection, id: StreamId) Error!?*Stream {
    switch (connection.streams.lookup(id)) {
        .live => |stream| return stream,
        // RFC 9000 §4.5: a receiver "SHOULD treat receipt of data at or beyond the final size as
        // an error ... even after a stream is closed", and then says generating it "is not
        // mandatory, because requiring that an endpoint generate these errors also means that
        // the endpoint needs to maintain the final size state for closed streams". colibri keeps
        // none, so it cannot answer and ignores the frame. A retransmission arriving after the
        // application finished reading is ordinary, and closing on one would be wrong.
        .closed => return null,
        .unopened => {},
    }
    // RFC 9000 §3.2: "An endpoint that receives a frame for a stream that it has not created
    // creates that stream", and §4.6's limit is what refuses one past what was advertised.
    const stream = connection.streams.open_peer(id) catch |failure| switch (failure) {
        error.StreamLimitReached => return Error.StreamLimit,
        error.Full, error.IdentifiersExhausted => return Error.Internal,
    };
    initialise_flow(connection, stream, id);
    return stream;
}

/// Gives a stream the two limits RFC 9000 §18.2 fixes for it. The table cannot do this: §18.2
/// has three stream data parameters and which one applies depends on who initiated the stream
/// and which direction is being asked about, which is the connection's knowledge.
///
/// §18.2 names them from the sender's own side. What this endpoint may receive comes from the
/// parameters it sent, and what it may send comes from the peer's, so the same stream reads a
/// different parameter in each direction and `_local` and `_remote` swap between them.
pub fn initialise_flow(connection: *Connection, stream: *Stream, id: StreamId) void {
    const mine = connection.local_parameters;
    const receive_limit = if (id.directionality() == .unidirectional)
        // §18.2: initial_max_stream_data_uni is "the initial flow control limit for unidirectional
        // streams", and a unidirectional stream this endpoint receives on is the peer's.
        mine.initial_max_stream_data_uni
    else if (id.is_initiated_by(initiator_of(connection)))
        // §18.2: initial_max_stream_data_bidi_local applies to "locally initiated bidirectional
        // streams", locally meaning the endpoint that sent the parameter.
        mine.initial_max_stream_data_bidi_local
    else
        // §18.2: initial_max_stream_data_bidi_remote applies to "peer-initiated bidirectional
        // streams".
        mine.initial_max_stream_data_bidi_remote;
    stream.receive_flow = receiver_for(receive_limit);
    // What this endpoint may send starts at zero until the peer's parameters arrive, which §7.4
    // puts in the handshake. `apply_peer_parameters` does not reach streams opened before it, so
    // a stream opened after reads them and one opened before is raised by MAX_STREAM_DATA.
    stream.send_flow = flow.Sender.init(send_limit(connection, id));
}

/// What the peer's parameters allow this endpoint to send on `id`, or zero before they arrive.
fn send_limit(connection: *const Connection, id: StreamId) u64 {
    const peer = connection.peer_parameters orelse return 0;
    if (id.directionality() == .unidirectional) return peer.initial_max_stream_data_uni;
    // The peer wrote these from its own side, so the endpoint that initiated the stream is
    // "remote" to the peer exactly when it is this endpoint.
    if (id.is_initiated_by(initiator_of(connection))) return peer.initial_max_stream_data_bidi_remote;
    return peer.initial_max_stream_data_bidi_local;
}

/// RFC 9000 §18.2: a stream data limit that is "absent or zero" admits nothing, which
/// `flow.Receiver.init` cannot express because decision 49's window must be above zero.
fn receiver_for(limit: u64) flow.Receiver {
    if (limit == 0) return flow.Receiver.none();
    return flow.Receiver.init(limit, limit);
}

/// RFC 9000 §19.11's bit and §2.1's bit stand for the same thing under two names: the frame
/// layer's and the stream table's. Translating here keeps `quic.frame` free of the stream table.
fn directionality_of(held: frame_module.Directionality) Directionality {
    return switch (held) {
        .bidirectional => .bidirectional,
        .unidirectional => .unidirectional,
    };
}

fn initiator_of(connection: *const Connection) stream_id_module.Initiator {
    return switch (connection.role) {
        .client => .client,
        .server => .server,
    };
}

test {
    _ = @import("connection_stream_frames_test.zig");
}
