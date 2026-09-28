//! colibri's server (decision 100, design §8 step 17): HTTP responses behind one set of calls for
//! h11 and h2 over TCP, the version chosen by ALPN over TLS and named in cleartext. Step 17b adds
//! h3 over QUIC behind the same calls.
//!
//! A program makes one `Config`, then a `Connection` for each TCP connection it accepts, in
//! storage it owns. It passes the octets it read to `receive`, which returns at most one event: a
//! request's head, octets of its content, its trailer section, its cancellation, or that its
//! response is done. It answers each request by its id with `respond`, `write_body` and
//! `write_trailers`, and sends what `send` writes. colibri makes no system call and reads no
//! clock: time is a value the caller passes.
//!
//! Over TLS, the connection runs the handshake through `tls.record.Server` itself, so a program
//! that uses this module links chapulin. One that wants no TLS uses `h11` or `h2` directly.
const std = @import("std");

pub const constants = @import("constants.zig");
pub const event = @import("event.zig");
pub const connection = @import("connection/connection.zig");
pub const quic_connection = @import("quic/quic_connection.zig");
pub const endpoint = @import("endpoint/endpoint.zig");

pub const Config = connection.Config;
pub const Connection = connection.Connection;
pub const QuicConnection = quic_connection.QuicConnection;
pub const QuicConfig = quic_connection.Config;
pub const Endpoint = endpoint.Endpoint;
pub const EndpointOf = endpoint.EndpointOf;
pub const EndpointConfig = endpoint.Config;
pub const Error = connection.Error;
pub const StartError = connection.StartError;
pub const SendError = connection.SendError;
pub const Field = connection.Field;
pub const Id = event.Id;
pub const Protocol = event.Protocol;
pub const Version = event.Version;
pub const Fields = event.Fields;
pub const Event = event.Event;
pub const Request = event.Request;
pub const Body = event.Body;
pub const Trailers = event.Trailers;
pub const Cancelled = event.Cancelled;
pub const Done = event.Done;
pub const Received = event.Received;

test {
    std.testing.refAllDecls(@This());
    _ = @import("reason.zig");
    _ = @import("expect.zig");
    _ = @import("done.zig");
    _ = @import("quic/quic_response.zig");
    _ = @import("quic/quic_request.zig");
    _ = @import("quic/quic_connection_test.zig");
    _ = @import("quic/quic_connection_flow_test.zig");
    _ = @import("endpoint/endpoint_stateless.zig");
    _ = @import("endpoint/endpoint_test.zig");
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
