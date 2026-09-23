//! Streams (RFC 9000 §2, §3, §4.5): the identifier, and the two state machines a stream has.
//! Part of design §8 step 9.
//!
//! A stream is two halves that move independently. §3.1's sending part and §3.2's receiving
//! part are separate machines with separate states, and a bidirectional stream has both while a
//! unidirectional one has whichever its direction gives this endpoint. Keeping them apart is
//! the RFC's own shape and not a convenience: the receiving part cannot see the sending part's
//! "Ready" state, and the sending part cannot see when the application read the data.
const std = @import("std");

pub const stream_id = @import("stream_id.zig");
pub const stream_send = @import("stream_send.zig");
pub const stream_recv = @import("stream_recv.zig");
pub const stream_table = @import("stream_table.zig");
pub const stream_outgoing = @import("stream_outgoing.zig");
pub const stream_lost = @import("stream_lost.zig");
pub const stream_provider = @import("stream_provider.zig");

pub const StreamId = stream_id.StreamId;
pub const Initiator = stream_id.Initiator;
pub const Directionality = stream_id.Directionality;
pub const Sending = stream_send.Sending;
pub const Receiving = stream_recv.Receiving;
pub const Streams = stream_table.Streams;
pub const Stream = stream_table.Stream;
pub const StreamProvider = stream_provider.StreamProvider;

test {
    std.testing.refAllDecls(@This());
    _ = stream_id;
    _ = stream_send;
    _ = stream_recv;
    _ = stream_table;
    _ = stream_outgoing;
    _ = stream_lost;
    _ = stream_provider;
    _ = @import("stream_test.zig");
}
