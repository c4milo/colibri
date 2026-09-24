//! The expansion of a datagram to RFC 9000 §14.1's 1,200 octets, which §14.1 asks of Initial
//! packets and §8.2.1 and §8.2.2 of the path frames. Decision 54 puts the PADDING in the last
//! packet, because the AEAD covers the payload and nothing can be appended once it is sealed.
//! Split from `connection_send.zig`, which a hand-written file of 500 lines could not also hold.
const std = @import("std");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const packet_build = @import("packet_build/packet_build.zig");

const Connection = connection_module.Connection;

/// RFC 9000 §14.1's expansion, put on the datagram's last packet by decision 54.
pub fn expand_last(connection: *Connection, plans: []packet_build.Planned, planned_len: usize, ceiling: usize) void {
    const owed = owes_expansion(connection, plans);
    if (owed == .none) return;
    if (planned_len >= constants.datagram_len_min) return;
    // RFC 9000 §8.2.1 and §8.2.2 except a datagram §8's limit keeps below 1,200 octets, and one
    // padded part of the way validates no path MTU (§8.2.1). The octets are kept instead for the
    // PATH_CHALLENGE frames §13.3 sends after it, which the same limit bounds (decision 72).
    if (owed == .path_frames and ceiling < constants.datagram_len_min) return;
    const last = &plans[plans.len - 1];
    // RFC 9001 §5.4.2's widening of a tiny packet's number is what PADDING replaces once there is
    // any: padding the widened octets back in lands the datagram on 1,200 exactly, and when the
    // ceiling allows less the widening shrinks by as much as the padding grows.
    const widened_len = packet_build.widening_len(last.*);
    const wanted = constants.datagram_len_min - planned_len + widened_len;
    // The padding goes in the last packet's payload, so it is bounded by what that payload's
    // buffer still holds as well as by what the datagram needs.
    last.padding_len = @min(wanted, room_for_padding(last, ceiling, planned_len - widened_len));
}

/// How many octets of PADDING the last packet can still take.
fn room_for_padding(last: *const packet_build.Planned, ceiling: usize, planned_len: usize) usize {
    const spare_in_datagram = ceiling - planned_len;
    const spare_in_packet = last.shape.room - last.payload_len;
    return @min(spare_in_datagram, spare_in_packet);
}

/// Which rule, if any, requires this datagram to reach 1,200 octets.
const Expansion = enum { none, initial, path_frames };

/// RFC 9000 §14.1: "A client MUST expand the payload of all UDP datagrams carrying Initial packets
/// ... Similarly, a server MUST expand the payload of all UDP datagrams carrying ack-eliciting
/// Initial packets." §14.1 is asked first, because it holds whatever else the datagram carries.
fn owes_expansion(connection: *const Connection, plans: []const packet_build.Planned) Expansion {
    for (plans) |planned| {
        if (planned.level != .initial) continue;
        if (connection.role == .client) return .initial;
        // §14.1 asks a server only for the ack-eliciting ones, so an Initial carrying nothing but
        // an acknowledgment costs a server no padding.
        if (planned.ack_eliciting) return .initial;
    }
    // RFC 9000 §8.2.1: "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to
    // at least the smallest allowed maximum datagram size of 1200 bytes", and §8.2.2 says the
    // same of a PATH_RESPONSE.
    for (plans) |planned| {
        if (planned.path_challenge != null or planned.carries_path_response) return .path_frames;
    }
    return .none;
}
