//! The tests of `connection_path_frames.zig`. The frames come through `connection_frames.process`,
//! so what they drive is the whole path from a packet's payload down to the connection IDs and
//! the path.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const connection_id = @import("../connection_id.zig");
const frame_module = @import("../frame/frame.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const frames = @import("connection_frames.zig");
const path_frames = @import("connection_path_frames.zig");

const testing = std.testing;

/// RFC 9000 §19.16's rule turns on which connection ID a packet was addressed to, and a case
/// that is not about that rule says the packet named none this endpoint issued.
const addressed_to_none: ?u64 = null;
const Writer = core.Writer;
const Frame = frame_module.Frame;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

var test_connection: Connection = undefined;
const payload_len: usize = 256;
var payload: [payload_len]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

const offered_octet: u8 = 0x2f;
const offered_id: [id_len]u8 = @splat(offered_octet);
const reset_token_octet: u8 = 0x9b;
const reset_token: [constants.stateless_reset_token_len]u8 = @splat(reset_token_octet);

const challenge_octet: u8 = 0x7e;
const challenge_data: [constants.path_challenge_len]u8 = @splat(challenge_octet);
const other_challenge_octet: u8 = 0x1d;
const other_challenge: [constants.path_challenge_len]u8 = @splat(other_challenge_octet);

const token_octet: u8 = 0xab;
const token_len: usize = 12;
const server_token: [token_len]u8 = @splat(token_octet);

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

fn open_as(role: connection_module.Role) void {
    test_connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
}

fn run(list: []const Frame) frames.Error!frames.Report {
    var writer = Writer.init(&payload);
    for (list) |held| frame_module.write(&writer, held) catch unreachable;
    return frames.process(&test_connection, .application, writer.written(), test_now_ns, addressed_to_none);
}

test "RFC 9000 §19.7: only a client may receive a NEW_TOKEN frame" {
    open_as(.client);
    const report = try run(&.{.{ .new_token = .{ .token = &server_token } }});
    // The octets point into the packet, which the caller owns: colibri keeps no state outside
    // one connection, so a client that wants the token for a later one copies it.
    try testing.expectEqualSlices(u8, &server_token, report.owed.new_token.?);

    // §19.7: "Clients MUST NOT send NEW_TOKEN frames. A server MUST treat receipt of a NEW_TOKEN
    // frame as a connection error of type PROTOCOL_VIOLATION."
    open_as(.server);
    try testing.expectError(frames.Error.Path, run(&.{.{ .new_token = .{ .token = &server_token } }}));
    try testing.expectEqual(
        error_code.protocol_violation,
        path_frames.connection_error_code(path_frames.Error.NewTokenFromClient),
    );
}

test "RFC 9000 §8.2.2: a PATH_CHALLENGE leaves a response owed" {
    open_as(.client);
    const report = try run(&.{.{ .path_challenge = .{ .data = &challenge_data } }});
    // "An endpoint MUST respond by echoing the data contained in the PATH_CHALLENGE frame in a
    // PATH_RESPONSE frame", so the exact octets are what the connection remembers.
    try testing.expectEqualSlices(u8, &challenge_data, &report.owed.path_response.?);

    // A packet with no challenge in it leaves nothing owed, so a caller cannot answer twice.
    const quiet = try run(&.{.ping});
    try testing.expectEqual(null, quiet.owed.path_response);
}

test "RFC 9000 §8.2.3: a PATH_RESPONSE validates the path its challenge went out on" {
    open_as(.client);
    // A server's path begins unvalidated, which is the state §8 measures its limit against.
    test_connection.path.init(.unvalidated);
    test_connection.path.on_challenge_sent(challenge_data, test_now_ns, test_now_ns);
    _ = try run(&.{.{ .path_response = .{ .data = &challenge_data } }});
    try testing.expectEqual(.validated, test_connection.path.state());
    // §8.2.3: the address is validated and the path MTU is not, because nothing remembers
    // whether the challenge's datagram was expanded.
    try testing.expect(!test_connection.path.mtu_validated);
}

test "RFC 9000 §8.2.3: a PATH_RESPONSE carrying other octets validates nothing" {
    open_as(.client);
    test_connection.path.init(.unvalidated);
    test_connection.path.on_challenge_sent(challenge_data, test_now_ns, test_now_ns);
    // "Path validation succeeds when a PATH_RESPONSE frame is received that contains the data
    // that was sent in a previous PATH_CHALLENGE frame", and these are not those octets.
    _ = try run(&.{.{ .path_response = .{ .data = &other_challenge } }});
    try testing.expectEqual(.challenging, test_connection.path.state());
}

test "RFC 9000 §19.15: a NEW_CONNECTION_ID joins the set colibri may address the peer by" {
    open_as(.client);
    _ = try run(&.{new_connection_id(1, 0)});
    const active = test_connection.remote_ids.active().?;
    try testing.expectEqualSlices(u8, &offered_id, active.value());

    // §5.1.1: more active connection IDs than this endpoint's own active_connection_id_limit
    // closes the connection. The default is 2 (§18.2), so a third is one too many.
    _ = try run(&.{new_connection_id(2, 0)});
    try testing.expectError(frames.Error.Path, run(&.{new_connection_id(3, 0)}));
    try testing.expectEqual(
        error_code.connection_id_limit_error,
        connection_id.connection_error_code(connection_id.Error.ConnectionIdLimitExceeded),
    );
}

test "RFC 9000 §19.16: a RETIRE_CONNECTION_ID naming an unissued number closes the connection" {
    open_as(.client);
    // §5.1.1 gives the identity's own Source Connection ID sequence number 0, so 0 is issued
    // and 1 is not: "a sequence number greater than any previously sent to the peer".
    const unissued: u64 = 1;
    try testing.expectError(
        frames.Error.Path,
        run(&.{.{ .retire_connection_id = .{ .sequence_number = unissued } }}),
    );
    // A second one issued makes the same frame legal.
    open_as(.client);
    try testing.expectEqual(unissued, test_connection.local_ids.issue(&offered_id).?);
    _ = try run(&.{.{ .retire_connection_id = .{ .sequence_number = unissued } }});
    try testing.expectEqual(1, test_connection.local_ids.active_len());
}

test "RFC 9000 §19.16: a frame cannot retire the connection ID its own packet arrived on" {
    open_as(.client);
    const second = test_connection.local_ids.issue(&offered_id).?;
    // §19.16: "The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to
    // the Destination Connection ID field of the packet in which the frame is contained."
    // colibri takes the MAY and closes, which needs the packet to say what it was addressed to.
    var writer = Writer.init(&payload);
    frame_module.write(&writer, .{ .retire_connection_id = .{ .sequence_number = second } }) catch unreachable;
    try testing.expectError(frames.Error.Path, frames.process(
        &test_connection,
        .application,
        writer.written(),
        test_now_ns,
        second,
    ));
    // The same frame on a packet addressed to the other connection ID is legal, which is what
    // makes the refusal about the packet and not about the number.
    const first: u64 = 0;
    _ = try frames.process(&test_connection, .application, writer.written(), test_now_ns, first);
    try testing.expectEqual(1, test_connection.local_ids.active_len());
}

test "RFC 9000 §5.1.1: the identity's own Source Connection ID is sequence number 0" {
    open_as(.client);
    // "The initial connection ID issued by an endpoint is sent in the Source Connection ID field
    // of the long packet header during the handshake. The sequence number of the initial
    // connection ID is 0."
    try testing.expectEqual(1, test_connection.local_ids.active_len());
    try testing.expectEqual(0, test_connection.local_ids.sequence_number_of(&local_id).?);
    // And a connection ID this endpoint never issued names no sequence number at all.
    try testing.expectEqual(null, test_connection.local_ids.sequence_number_of(&offered_id));
}

fn new_connection_id(sequence_number: u64, retire_prior_to: u64) Frame {
    return .{ .new_connection_id = .{
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .connection_id = &offered_id,
        .stateless_reset_token = &reset_token,
    } };
}
