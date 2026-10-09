//! colibri's server (decision 100, design §8 step 17): HTTP responses behind one set of calls for
//! h11 and h2 over TCP, the version chosen by ALPN over TLS and by a connection's first octets in
//! cleartext (decision 117). Step 17b adds h3 over QUIC behind the same calls.
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
//!
//! When `Config` names content codings and an `EncoderPool`, a final response the caller marks
//! `codable` goes out coded in the coding its request's Accept-Encoding accepts (decision 101).
//! The pool is storage the caller places, and connections share it.
const std = @import("std");
const http = @import("http");
const h11 = @import("h11");
const quic = @import("quic");
const event = @import("event.zig");
const connection = @import("connection/connection.zig");
const quic_connection = @import("quic/quic_connection.zig");
const endpoint = @import("endpoint/endpoint.zig");
const alt_svc = @import("alt_svc.zig");
const coding_pool = @import("coding/coding_pool.zig");
const deadline = @import("deadline.zig");
const close_reason = @import("close_reason.zig");
const versions = @import("versions.zig");
const limits = @import("limits.zig");

/// The module's named limits and sizes (decision 35). It is the one file the root exports whole:
/// every other name below is a type a program names (design §8 step 17f).
pub const constants = @import("constants.zig");

pub const Config = connection.Config;
pub const Versions = versions.Versions;
pub const Limits = limits.Limits;
pub const Deadline = deadline.Deadline;
pub const Deadlines = deadline.Deadlines;
pub const CloseReason = close_reason.CloseReason;
pub const Limit = close_reason.Limit;
pub const Connection = connection.Connection;
pub const QuicConnection = quic_connection.QuicConnection;
pub const QuicConfig = quic_connection.Config;
pub const Endpoint = endpoint.Endpoint;
pub const EndpointOf = endpoint.EndpointOf;
pub const EndpointConfig = endpoint.Config;
pub const LogProvider = endpoint.LogProvider;
/// A datagram `Endpoint.send` wrote, with its ECN codepoint and the address it goes to.
pub const Sent = quic_connection.Sent;
/// An address and port as the program names a peer (decision 72): `Address.of(octets, port)`.
pub const Address = quic_connection.PeerAddress;
/// The ECN field of a datagram's IP header, by RFC 9000 §13.4's names, which a program reads and
/// sets when `QuicConfig.ecn` is set (decision 68).
pub const Ecn = quic.connection_send.Ecn;
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
pub const CancelReason = event.CancelReason;
pub const Done = event.Done;
pub const Response = event.Response;
pub const Content = event.Content;
pub const Received = event.Received;
pub const Alternative = alt_svc.Alternative;
/// The content codings a server applies (decision 101).
pub const Coding = http.content_coding.Coding;
pub const EncoderPool = coding_pool.EncoderPool;
pub const DefaultEncoderPool = coding_pool.DefaultEncoderPool;
pub const Encoders = coding_pool.Encoders;
/// The pool of decoders h11 removes the `gzip` and `deflate` transfer codings of a request with
/// (decision 91), which the caller places: `DecoderPool(count)` for `count` decoders, or
/// `DefaultDecoderPool`. A configuration holds it as `Decoders`, from `storage()` after `reset`.
pub const DecoderPool = h11.coding.Pool;
pub const DefaultDecoderPool = h11.coding.DefaultPool;
pub const Decoders = h11.coding.Storage;
/// The CPU features a pool's codecs run on, which its `reset` takes: `Features.detect()` asks the
/// CPU, as colibri never does itself, and `Features.target()` is what the build target guarantees.
pub const Features = coding_pool.Features;

test "design §8 step 17f: the root exports its constants and the types a program names" {
    // Design §8 step 21a adds `Versions` and `Limits` (decision 117).
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants",  "Config",       "Versions",           "Limits",         "Deadline",
        "Deadlines",  "CloseReason",  "Limit",              "Connection",     "QuicConnection",
        "QuicConfig", "Endpoint",     "EndpointOf",         "EndpointConfig", "LogProvider",
        "Sent",       "Address",      "Ecn",                "Error",          "StartError",
        "SendError",  "Field",        "Id",                 "Protocol",       "Version",
        "Fields",     "Event",        "Request",            "Body",           "Trailers",
        "Cancelled",  "CancelReason", "Done",               "Response",       "Content",
        "Received",   "Alternative",  "Coding",             "EncoderPool",    "DefaultEncoderPool",
        "Encoders",   "DecoderPool",  "DefaultDecoderPool", "Decoders",       "Features",
    });
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("versions.zig");
    _ = @import("reason.zig");
    _ = @import("expect.zig");
    _ = @import("done.zig");
    _ = @import("rate.zig");
    _ = @import("quic/quic_response.zig");
    _ = @import("quic/quic_request.zig");
    _ = @import("quic/quic_connection_test.zig");
    _ = @import("quic/quic_connection_flow_test.zig");
    _ = @import("quic/quic_connection_limit_test.zig");
    _ = @import("quic/quic_deadline_test.zig");
    _ = @import("quic/quic_deadline_credit_test.zig");
    _ = @import("quic/quic_body_test.zig");
    _ = @import("quic/quic_sends_test.zig");
    _ = @import("quic/quic_drain_test.zig");
    _ = @import("quic/quic_coding_test.zig");
    _ = @import("quic/quic_continue_test.zig");
    _ = @import("endpoint/endpoint_stateless.zig");
    _ = @import("endpoint/endpoint_test.zig");
    _ = @import("coding/coding_ring.zig");
    _ = @import("coding/coding_rules.zig");
    _ = @import("coding/coding_fields.zig");
    _ = @import("coding/coding_response.zig");
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
