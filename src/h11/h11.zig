//! h11: HTTP/1.1 (RFC 9112), client and server, as decisions 88 and 91 rule it. Design §8 step 15
//! builds it in four parts: the messages (15a), the connection (15b), the `gzip` and `deflate`
//! codings (15c), and TLS with the endpoints (15d).
//!
//! h11 imports `core`, `http`, `tls_provider`, and stdx's `codec`, `gzip` and `zlib`, whose
//! decoders read the `gzip` and `deflate` transfer codings (decisions 90 and 91).
const std = @import("std");

pub const core = @import("core");
pub const http = @import("http");
pub const constants = @import("constants.zig");
pub const message = @import("message/message.zig");
pub const chunked = @import("chunked/chunked.zig");
pub const coding = @import("coding.zig");
pub const connection = @import("connection/connection.zig");
pub const connection_tls = @import("connection/connection_tls.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("message/message_scan.zig");
    _ = @import("message/message_start.zig");
    _ = @import("message/message_fields.zig");
    _ = @import("message/message_target.zig");
    _ = @import("message/message_body.zig");
    _ = @import("chunked/chunked_line.zig");
    _ = @import("message/message_write.zig");
    _ = @import("chunked/chunked_write.zig");
    _ = @import("message/message_fuzz.zig");
    _ = @import("connection/connection_server_test.zig");
    _ = @import("connection/connection_client_test.zig");
    _ = @import("connection/connection_tls_test.zig");
    _ = @import("connection/connection_coding_test.zig");
}
