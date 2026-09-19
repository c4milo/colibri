//! QUIC packets: the version-independent reader of RFC 8999, packet number coding, and the
//! version 1 headers of RFC 9000 §17. Frames are not here; a packet's payload is opaque octets
//! until its protection is removed.
const std = @import("std");

pub const invariant = @import("invariant.zig");
pub const packet_number = @import("packet_number.zig");
pub const header = @import("packet_header.zig");
pub const header_write = @import("packet_header_write.zig");

test {
    std.testing.refAllDecls(@This());
    _ = invariant;
    _ = packet_number;
    _ = header;
    _ = header_write;
}
