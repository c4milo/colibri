//! The TLS provider vtable, in both modes (decision 8). No production implementation is in this
//! tree; src/sim/ provides a null one, which is test-only and never packaged.
//!
//! Record mode serves h2 and is `provider.zig`. QUIC mode serves h3 and lands with design §8
//! step 9e, where RFC 9001 §4 replaces the record layer: step 7 shipped the packet formats and,
//! after decision 48, a `crypto.Suite` that protects packets and drives no handshake.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

pub const alert = @import("alert.zig");
pub const Alert = alert.Alert;
pub const AlertReport = alert.AlertReport;

pub const provider = @import("provider.zig");
pub const Provider = provider.Provider;
pub const VTable = provider.VTable;
pub const Content = provider.Content;
pub const Negotiated = provider.Negotiated;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = alert;
    _ = provider;
}
