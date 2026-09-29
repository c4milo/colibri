//! A resumption ticket between colibri's value (`values.Ticket`) and one chapulin object's, which
//! both the record and the QUIC sessions convert (design §8 step 16c). A ticket a client kept in
//! the value's fixed fields resumes a later connection of the transport and QUIC version that
//! issued it, and no other (RFC 9369 §5, chapulin's decision 79).
const std = @import("std");
const assert = std.debug.assert;
const values = @import("values.zig");

/// The ticket a connection offers, rebuilt in the object's type from the value the caller kept.
pub fn offered(comptime chapulin: type, resumption: values.Resumption) error{Invalid}!chapulin.Ticket {
    const kept = resumption.ticket;
    var fields: chapulin.Ticket.Fields = .{
        .identity = kept.identity[0..kept.identity_len],
        .psk = kept.psk[0..kept.psk_len],
        .age_add = kept.age_add,
        .lifetime_s = kept.lifetime_s,
        .binding = &kept.binding,
    };
    // RFC 9369 §5: a QUIC object's ticket names the version that issued it.
    if (@FieldType(chapulin.Ticket.Fields, "quic_version") != void) fields.quic_version = @enumFromInt(kept.quic_version);
    return chapulin.Ticket.fromFields(fields);
}

/// Whether a connection of QUIC version `version`, or 0 over TCP, may offer `kept`: RFC 9369 §5,
/// "Clients MUST NOT use a session ticket or token from a QUIC version 1 connection to initiate a
/// QUIC version 2 connection, and vice versa", and a TCP ticket names no version.
pub fn fits(kept: *const values.Ticket, version: u32) bool {
    return kept.quic_version == version;
}

/// chapulin's ticket in step 16c's fixed-size fields.
pub fn value_of(comptime chapulin: type, taken: *const chapulin.Ticket) values.Ticket {
    const issued = &taken.ticket;
    var ticket: values.Ticket = std.mem.zeroes(values.Ticket);
    // chapulin copies no identity longer than `CH_TICKET_ID_MAX` and no PSK longer than its hash.
    assert(issued.identity_len <= ticket.identity.len and issued.psk_len <= ticket.psk.len);
    @memcpy(ticket.identity[0..issued.identity_len], taken.identity[0..issued.identity_len]);
    ticket.identity_len = @intCast(issued.identity_len);
    @memcpy(ticket.psk[0..issued.psk_len], issued.psk[0..issued.psk_len]);
    ticket.psk_len = @intCast(issued.psk_len);
    ticket.age_add = issued.age_add;
    ticket.lifetime_s = issued.lifetime_s;
    ticket.binding = issued.binding;
    // A QUIC object's ticket records its version, and a TCP object's has no such field.
    ticket.quic_version = if (@hasField(@TypeOf(issued.*), "quic_version")) issued.quic_version else 0;
    return ticket;
}
