//! What a client connection refuses before an exchange takes a slot (decision 100): a request no
//! protocol could send, or one naming a field line the client writes itself.
const std = @import("std");
const assert = std.debug.assert;
const event = @import("../event.zig");

const HttpExchange = event.HttpExchange;

pub const RequestError = error{
    /// Every slot holds an exchange, until one's `finished` event is reported.
    Full,
    /// The connection takes no new request, as its `draining` event said.
    Draining,
    /// The connection is over.
    ConnectionClosed,
    /// The method or the path is empty, or the method is CONNECT, whose tunnel is no exchange of
    /// a request and a response (RFC 9110 §9.3.6).
    RequestUnsupported,
    /// A field line the client writes itself, Host or Content-Length, or a connection-specific
    /// one, which h2 forbids (RFC 9113 §8.2.2), so a request means the same in every version.
    FieldReserved,
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

/// Refuses what no protocol could send as an exchange, before the exchange takes a slot.
pub fn check_request(exchange: *const HttpExchange) RequestError!void {
    // The caller marks each of its field lines, or none.
    assert(exchange.never_indexed.fields.len == 0 or exchange.never_indexed.fields.len == exchange.fields.len);
    // RFC 9110 §9.1: a method is a token, which is never empty.
    if (exchange.method.len == 0) return error.RequestUnsupported;
    // RFC 9113 §8.3.1: `:path` "MUST NOT be empty" for an http or https URI, and RFC 9112 §3.2.1's
    // origin form starts with its absolute path.
    if (exchange.path.len == 0) return error.RequestUnsupported;
    // RFC 9110 §9.3.6: CONNECT asks for a tunnel, which is no exchange of a request and a response.
    if (std.mem.eql(u8, exchange.method, "CONNECT")) return error.RequestUnsupported;
    for (exchange.fields) |field| {
        for (reserved_names) |reserved| {
            // RFC 9113 §8.2.2, RFC 9112 §3.2 and RFC 9110 §8.6: see `reserved_names`. Field names
            // are case-insensitive (RFC 9110 §5.1).
            if (std.ascii.eqlIgnoreCase(field.name, reserved)) return error.FieldReserved;
        }
    }
}
