//! The 100 (Continue) a server connection over QUIC owes (RFC 9110 §10.1.1, decision 116, design
//! §8 step 17i), as `connection_continue.zig` writes it over TCP.
//!
//! A request whose Expect field names 100-continue is owed a 100 (Continue) from the `receive`
//! that reports its head. The connection writes it as an interim response on the request's stream
//! (RFC 9114 §4.1) the next time it settles its requests: at its next `receive`, at the next
//! datagram it takes, or before the next datagram it sends. A caller that answers the request
//! before then, with a final response, with its own 100 or with `cancel`, has answered first, and
//! the request gets no other 100.
//!
//! h3 reports a request's end apart from its head (RFC 9114 §4.1), so the head does not say
//! whether content follows. The connection learns it from the stream when it writes the 100: once
//! h3 has read the stream to its end, no content follows, and the request gets no 100.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const http = @import("http");
const event = @import("../event.zig");
const expect = @import("../expect.zig");
const quic_request = @import("quic_request.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = quic_request.Request;
const Stream = quic.stream.Stream;

/// RFC 9110 §15.2.1: 100 (Continue).
const continue_status: u16 = @intFromEnum(http.status.Code.@"continue");

/// Notes the 100 (Continue) the request of `record` is owed, when its head `request` expects one.
pub fn note(connection: *QuicConnection, record: *Request, request: event.Request) void {
    assert(record.in_use and !record.continue_owed);
    assert(record.stream_id == request.id);
    // RFC 9110 §10.1.1: a server that reads the 100-continue expectation "MUST send either" a
    // final response at once or "an immediate 100 (Continue) response".
    if (!expect.expects_continue(request)) return;
    record.continue_owed = true;
    connection.continue_owed = true;
}

/// A response's head with `status` went out on the stream of `record`.
pub fn on_response(record: *Request, status: u16) void {
    assert(record.in_use and status >= continue_status);
    // RFC 9110 §10.1.1: the request expects one 100 (Continue), so the caller's own is the one
    // it is owed.
    if (status == continue_status) record.continue_owed = false;
}

/// Writes the 100 (Continue) the request of `record` is owed on `stream`, its own. `settle` calls
/// it for each request the connection holds.
pub fn write(connection: *QuicConnection, record: *Request, stream: *const Stream) void {
    if (!record.continue_owed) return;
    assert(record.in_use and stream.id == record.stream_id);
    // RFC 9110 §10.1.1: a server "MAY omit sending a 100 (Continue) response if it has already
    // received some or all of the content", "or if the framing indicates that there is no
    // content". Once h3 has read the request's stream to its end, no content follows.
    if (read_to_end(stream)) {
        record.continue_owed = false;
        return;
    }
    quic_connection_h3.respond(connection, record.stream_id, .{ .status = continue_status, .end = false }) catch |failure| {
        // RFC 9000 §3.1: the response's runs leave as the peer acknowledges them, and the 100
        // is written once one is free.
        if (failure == error.NoSpaceLeft) {
            connection.continue_owed = true;
            return;
        }
        // RFC 9110 §10.1.1: a request the caller answered with a final response, or cancelled,
        // needs no 100, and `respond` refuses one.
        record.continue_owed = false;
    };
    assert(!record.continue_owed);
}

/// Whether h3 has taken every octet of `stream` below its final size (RFC 9000 §4.5): the stream
/// ended with the request's head, or every octet of its content has been read.
fn read_to_end(stream: *const Stream) bool {
    const final_size = stream.receiving.final_size orelse return false;
    assert(stream.receive_flow.consumed <= final_size);
    return stream.receive_flow.consumed == final_size;
}

/// Has the connection write each 100 (Continue) it owes before it sends a datagram at `now_ns`.
pub fn write_before_send(connection: *QuicConnection, now_ns: u64) void {
    assert(!connection.closed);
    if (!connection.continue_owed) return;
    connection.last_ns = now_ns;
    // RFC 9110 §10.1.1: the 100 (Continue) is "immediate", so it does not wait for the caller's
    // next `receive`.
    quic_connection_h3.settle(connection);
}
