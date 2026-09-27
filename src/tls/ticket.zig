//! A resumption ticket between colibri's value (`values.Ticket`) and one chapulin object's, which
//! both the record and the QUIC sessions convert: a ticket a client kept in the value's fixed
//! fields may resume a later connection of either object (design §8 step 16c).
const std = @import("std");
const assert = std.debug.assert;
const values = @import("values.zig");

/// The ticket a connection offers, rebuilt in the object's type from the value the caller kept.
pub fn offered(comptime chapulin: type, resumption: values.Resumption) error{Invalid}!chapulin.Ticket {
    const kept = resumption.ticket;
    return chapulin.Ticket.fromFields(.{
        .identity = kept.identity[0..kept.identity_len],
        .psk = kept.psk[0..kept.psk_len],
        .age_add = kept.age_add,
        .lifetime_s = kept.lifetime_s,
        .binding = &kept.binding,
    });
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
    return ticket;
}
