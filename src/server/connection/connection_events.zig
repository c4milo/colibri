//! What a server connection over TCP notes of each event it reports, split off `connection.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md): the 100 (Continue)
//! a request is owed, whether its response may be coded, and where its deadlines stand.
const expect = @import("../expect.zig");
const event = @import("../event.zig");
const connection_module = @import("connection.zig");
const connection_coding = @import("connection_coding.zig");
const connection_deadline = @import("connection_deadline.zig");
const connection_bodies = @import("connection_bodies.zig");

const Connection = connection_module.Connection;

pub fn note(connection: *Connection, reported: event.Event) void {
    switch (reported) {
        .request => |request| {
            if (expect.expects_continue(request)) connection.continue_owed = request.id;
            connection_coding.on_request(connection, request);
            connection_deadline.on_request(connection);
            if (!request.end) connection_bodies.add(connection, request.id);
        },
        .body => |body| {
            // h11 counts its body's octets as it reads them, in `read_protocol`.
            if (connection.session == .h2) connection_bodies.count(connection, body.id, body.octets.len);
            if (body.end) connection_bodies.remove(connection, body.id);
        },
        .trailers => |trailers| connection_bodies.remove(connection, trailers.id),
        .cancelled => |cancelled| {
            connection_coding.forget(connection, cancelled.id);
            connection_bodies.remove(connection, cancelled.id);
        },
        .done => {},
    }
}
