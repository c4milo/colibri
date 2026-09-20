//! The frames about who the connection is and where it runs: NEW_TOKEN (RFC 9000 §19.7), the two
//! connection ID frames (§19.15, §19.16) and the two path frames (§19.17, §19.18).
//!
//! They are together because none of them touches a stream and each acts on state the connection
//! holds once: the connection IDs each side issued, and the path. What they have in common with
//! `connection_stream_frames.zig` is only that `connection_frames.zig` would not stay inside 500
//! lines holding all three.
//!
//! **Two of these frames owe an answer and this file writes neither.** §8.2.2 has a
//! PATH_CHALLENGE answered with a PATH_RESPONSE and §19.16 has a retired connection ID replaced,
//! and both answers are frames the send path writes. What happens here is that the connection
//! records what it owes; design §8 step 9e's send path is what pays it.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const connection_id = @import("../connection_id.zig");
const frame_module = @import("../frame/frame.zig");
const frame_control = @import("../frame/frame_control.zig");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;

/// Why one of these frames closed the connection.
pub const Error = error{
    /// RFC 9000 §19.7: "Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt of a
    /// NEW_TOKEN frame as a connection error of type PROTOCOL_VIOLATION."
    NewTokenFromClient,
    /// RFC 9000 §19.15, §19.16, §5.1.1: what `connection_id.Error` names.
    ConnectionId,
};

/// The code a CONNECTION_CLOSE carries for `failure` (RFC 9000 §20.1). A connection ID failure
/// keeps its own, which `connection_id.connection_error_code` gives, because §5.1.1's limit and
/// §19.16's refusals do not share one.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        error.NewTokenFromClient => error_code.protocol_violation,
        error.ConnectionId => error_code.protocol_violation,
    };
}

/// What one of these frames left for the send path to answer.
pub const Owed = struct {
    /// RFC 9000 §8.2.2: "On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by echoing
    /// the data contained in the PATH_CHALLENGE frame in a PATH_RESPONSE frame." Null when none
    /// is owed. Only the last is kept: a peer that challenges twice before colibri answers gets
    /// one response, and §8.2.1 lets it challenge again.
    path_response: ?[constants.path_challenge_len]u8 = null,
    /// RFC 9000 §19.7: the token a server gave, which a client MAY use on a future connection.
    /// It points into the packet, so a caller that wants it copies it before reading on; colibri
    /// has no state outside one connection and so cannot hold it (decision 35).
    new_token: ?[]const u8 = null,
};

/// Acts on one frame about the connection's identity or its path.
pub fn apply(connection: *Connection, frame: frame_module.Frame, addressed_to: ?u64, owed: *Owed) Error!void {
    switch (frame) {
        .new_token => |held| try take_new_token(connection, held.token, owed),
        .new_connection_id => |held| try take_new_connection_id(connection, held),
        .retire_connection_id => |held| try take_retire(connection, held.sequence_number, addressed_to),
        // RFC 9000 §8.2.2: the response is the send path's to write, and it must carry these
        // exact octets, so they are what the connection remembers.
        .path_challenge => |held| owed.path_response = held.data.*,
        .path_response => |held| take_path_response(connection, held.data.*),
        else => {},
    }
}

/// RFC 9000 §19.7: a server issues a token and a client uses it on a later connection.
fn take_new_token(connection: *Connection, token: []const u8, owed: *Owed) Error!void {
    // §19.7: "A server MUST treat receipt of a NEW_TOKEN frame as a connection error of type
    // PROTOCOL_VIOLATION", because only a server sends one. An empty token is refused by the
    // frame layer already (§19.7 makes it a FRAME_ENCODING_ERROR).
    if (connection.role == .server) return Error.NewTokenFromClient;
    owed.new_token = token;
}

/// RFC 9000 §19.15: the peer offered another connection ID for colibri to address it by.
fn take_new_connection_id(connection: *Connection, held: frame_control.NewConnectionId) Error!void {
    var entry: connection_id.Entry = .{
        .sequence_number = held.sequence_number,
        .len = @intCast(held.connection_id.len),
        .octets = @splat(0),
        .stateless_reset_token = held.stateless_reset_token.*,
    };
    @memcpy(entry.octets[0..held.connection_id.len], held.connection_id);
    // §5.1.1 measures the result against this endpoint's own active_connection_id_limit, which
    // §18.2 makes a value it advertised and therefore its own parameters'.
    connection.remote_ids.offer(entry, held.retire_prior_to, connection.local_parameters.active_connection_id_limit) catch
        return Error.ConnectionId;
}

/// RFC 9000 §19.16: the peer will no longer use one of the connection IDs colibri issued.
fn take_retire(connection: *Connection, sequence_number: u64, addressed_to: ?u64) Error!void {
    // §19.16: "The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to
    // the Destination Connection ID field of the packet in which the frame is contained. The
    // peer MAY treat this as a connection error of type PROTOCOL_VIOLATION." colibri takes the
    // MAY, because it holds the octets that answer it (§5.1.1) and design §8 step 9c already
    // settled that colibri answers an optional check it has the state for.
    connection.local_ids.retire(sequence_number, addressed_to) catch return Error.ConnectionId;
}

/// RFC 9000 §19.18: the peer echoed a PATH_CHALLENGE colibri sent, which §8.2.3 makes validation.
fn take_path_response(connection: *Connection, data: [constants.path_challenge_len]u8) void {
    // §8.2.3: whether the challenge's datagram was expanded decides whether the path MTU was
    // validated too, and `Path.Challenge` does not remember it. False is the safe answer: it
    // validates the address and leaves §8.2.3's second validation owed, where claiming true
    // would skip an MTU check that never happened.
    const challenge_was_expanded = false;
    _ = connection.path.on_response(data, challenge_was_expanded);
}

test {
    _ = @import("connection_path_frames_test.zig");
}
