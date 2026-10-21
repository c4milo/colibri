//! What a client connection refuses before an exchange takes a slot (decision 100): a request no
//! protocol could send, or one naming a field line the client writes itself.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");

const Request = event.Request;

/// What `check_request` refuses, on a connection and on a pool.
pub const CheckError = error{
    /// The method or the path is empty, or the method is CONNECT, whose tunnel is no exchange of
    /// a request and a response (RFC 9110 §9.3.6).
    RequestUnsupported,
    /// A field line the client writes itself, Host or Content-Length, or a connection-specific
    /// one, which h2 forbids (RFC 9113 §8.2.2), so a request means the same in every version.
    FieldReserved,
};

/// What a connection's `request` returns. The pool gives an exchange only to an open
/// connection, so the pool's own set has no `Draining` or `ConnectionClosed`.
pub const RequestError = CheckError || error{
    /// Every slot holds an exchange, until one's `finished` event is reported.
    Full,
    /// The connection takes no new request, as its `draining` event said.
    Draining,
    /// The connection is over.
    ConnectionClosed,
};

/// The names of the field lines `request` refuses, lowercase.
const reserved_names = [_][]const u8{
    // RFC 9112 §3.2 and RFC 9113 §8.3.1: the client names the authority itself.
    "host",
    // RFC 9110 §8.6: the client frames the content it sends.
    "content-length",
    // RFC 9113 §8.2.2: connection-specific fields.
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
};

/// Refuses a request no protocol could send, before its exchange takes a slot.
pub fn check_request(request: *const Request) CheckError!void {
    // The caller marks each of its field lines, or none.
    assert(request.never_indexed.headers.len == 0 or request.never_indexed.headers.len == request.headers.len);
    // RFC 9110 §9.1: a method is a token, which is never empty.
    if (request.method.len == 0) return error.RequestUnsupported;
    // RFC 9113 §8.3.1: `:path` "MUST NOT be empty" for an http or https URI, and RFC 9112 §3.2.1's
    // origin form starts with its absolute path.
    if (request.path.len == 0) return error.RequestUnsupported;
    // RFC 9110 §9.3.6: CONNECT asks for a tunnel, which is no exchange of a request and a response.
    if (std.mem.eql(u8, request.method, "CONNECT")) return error.RequestUnsupported;
    for (request.headers) |field| {
        for (reserved_names) |reserved| {
            // RFC 9113 §8.2.2, RFC 9112 §3.2 and RFC 9110 §8.6: see `reserved_names`. Field names
            // are case-insensitive (RFC 9110 §5.1).
            if (std.ascii.eqlIgnoreCase(field.name, reserved)) return error.FieldReserved;
        }
    }
}
