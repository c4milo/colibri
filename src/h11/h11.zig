//! h11: HTTP/1.1 (RFC 9112), client and server, as decisions 88 and 91 rule it. Design §8 step 15
//! builds it in four parts; this module holds what 15a has built so far, the reading of one head.
//!
//! h11 imports `core` and `http` now, and design §3 gives it `tls` and stdx's decoders too, which
//! it takes when a part uses them.
const std = @import("std");

pub const constants = @import("constants.zig");
pub const message = @import("message/message.zig");
pub const chunked = @import("chunked/chunked.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("message/message_scan.zig");
    _ = @import("message/message_start.zig");
    _ = @import("message/message_fields.zig");
    _ = @import("message/message_target.zig");
    _ = @import("message/message_body.zig");
    _ = @import("chunked/chunked_line.zig");
}
