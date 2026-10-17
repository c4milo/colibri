//! The tests of `values.Client.takes_tickets` over TCP
//! (https://github.com/c4milo/colibri/issues/104). They sit apart from `record_test.zig`, which
//! is near the 500 lines a file may hold (CLAUDE.md).
const std = @import("std");
const tls_provider = @import("tls_provider");
const values = @import("../values.zig");
const support = @import("record_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;
const to_client = &support.to_client;
const scratch = &support.scratch;

/// Opens the server's ticket record, which follows the handshake, and gives what the client kept.
fn ticket_after_handshake(resumption: ?values.Resumption) !?values.Ticket {
    try support.handshake_both(resumption);
    const receiver = client.provider();
    const opened = try receiver.vtable.decrypt_record(receiver.context, to_client.held(), scratch);
    try testing.expectEqual(tls_provider.Content.new_session_ticket, opened.content);
    return client.take_ticket();
}

test "RFC 9846 §4.7.1: a client that takes no tickets keeps none, and a ticket it offers resumes" {
    try support.configure(support.web_pki, .{ .tickets = true });
    var ticket = (try ticket_after_handshake(null)).?;
    defer ticket.wipe();
    client.close();
    server.close();
    var keeps_none = support.web_pki;
    keeps_none.takes_tickets = false;
    try support.configure(keeps_none, .{ .tickets = true });
    // The server still sends its ticket, and the client reads the record and keeps nothing.
    try testing.expectEqual(null, try ticket_after_handshake(null));
    try testing.expect(!client.resumed());
    client.close();
    server.close();
    // A ticket that another configuration kept still resumes.
    try support.handshake_both(.{ .ticket = &ticket, .age_ms = support.ms_per_second });
    try testing.expect(client.resumed() and server.resumed());
    try testing.expectEqual(null, client.take_ticket());
    client.close();
    server.close();
}
