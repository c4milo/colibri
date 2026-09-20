//! chapulin's `ch_tls` as storage colibri places and never reads (decision 35). Part of design
//! §8 step 5's TLS half.
//!
//! The size comes from chapulin's own header through `@cImport`, so a chapulin whose session grows
//! grows this too and no number is written down in colibri to drift. colibri names no field: what
//! the bytes mean is chapulin's, and the only colibri code that touches them is the adapter, which
//! passes their address.
const std = @import("std");

const c = @cImport({
    @cInclude("tls.h");
});

/// One chapulin session, aligned as chapulin aligns it.
pub const Session = extern struct {
    octets: [@sizeOf(c.ch_tls)]u8 align(@alignOf(c.ch_tls)),

    pub fn zeroed() Session {
        return .{ .octets = @splat(0) };
    }

    /// The address chapulin's calls take.
    pub fn handle(session: *Session) *anyopaque {
        return @ptrCast(&session.octets);
    }
};

test "the session is as large as chapulin says it is" {
    try std.testing.expect(@sizeOf(Session) == @sizeOf(c.ch_tls));
    try std.testing.expect(@sizeOf(Session) > 0);
}
