//! colibri's server (decision 100, design §8 steps 17 and 21): HTTP responses behind one set of
//! calls for h11, h2 and h3. An `Endpoint` holds the connections one thread serves (decision 119):
//! the TCP connections a program accepts, which serve h11 or h2, the version chosen by ALPN over TLS and
//! by a connection's first octets in cleartext (decision 117), and the QUIC connections behind one
//! UDP socket, which serve h3 (decision 103).
//!
//! A program makes one `Config` and one `Endpoint` for each thread that serves, in storage it
//! owns. It calls `accept` for each TCP socket its listener accepts, and passes what each socket
//! read, and each datagram its UDP socket read, to `receive`. `receive` returns at most one event:
//! a request's head, octets of its content, its trailer section, its ending, or one of the
//! endpoint's own events, which `event.zig` lists. The program answers each request by its id with `respond`, `write_body` and `write_trailers`, and
//! sends what `send_stream` and `send_datagram` write. colibri makes no system call and reads no
//! clock: time is a value the caller passes.
//!
//! The endpoint runs each TLS handshake itself, so a program that uses this module links chapulin,
//! one that serves cleartext alone too. A program that wants no chapulin uses `h11` or `h2`
//! directly.
//!
//! When `Config` names content codings and an `EncoderPool`, a final response the caller marks
//! `codable` goes out coded in the coding its request's Accept-Encoding accepts (decision 101).
//! The pool is storage the caller places, and connections share it.
const std = @import("std");
const http = @import("http");
const h11 = @import("h11");
const quic = @import("quic");

/// The module's named limits and sizes (decision 35). It is the one file the root exports whole:
/// every other name below is a type a program names (design §8 step 17f).
pub const constants = @import("constants.zig");

/// Every file a name below comes from. None of these is exported: the names below are.
const files = struct {
    pub const event = @import("event.zig");
    pub const quic_connection = @import("quic/quic_connection.zig");
    pub const endpoint = @import("endpoint/endpoint.zig");
    pub const connection_errors = @import("connection/connection_errors.zig");
    pub const alt_svc = @import("alt_svc.zig");
    pub const coding_pool = @import("coding/coding_pool.zig");
    pub const deadline = @import("deadline.zig");
    pub const close_reason = @import("close_reason.zig");
    pub const versions = @import("versions.zig");
    pub const limits = @import("limits.zig");
};

/// What a program configures a server with, once: the endpoint reads it while it runs (decision
/// 119).
pub const Config = files.endpoint.Config;
pub const Versions = files.versions.Versions;
pub const Limits = files.limits.Limits;
pub const Deadline = files.deadline.Deadline;
pub const Deadlines = files.deadline.Deadlines;
pub const CloseReason = files.close_reason.CloseReason;
pub const Limit = files.close_reason.Limit;
pub const Endpoint = files.endpoint.Endpoint;
pub const EndpointOf = files.endpoint.EndpointOf;
pub const Capacity = files.endpoint.Capacity;
/// What `Endpoint.receive` takes: `.none`, the `StreamOctets` a program's TCP socket read, or a
/// `Datagram` its UDP socket read.
pub const Input = files.endpoint.Input;
pub const Datagram = files.endpoint.Datagram;
/// Whether a TCP connection `Endpoint.accept` takes runs TLS.
pub const Security = files.endpoint.Security;
pub const StreamOctets = files.endpoint.StreamOctets;
pub const LogProvider = files.endpoint.LogProvider;
/// A datagram `Endpoint.send_datagram` wrote, with its ECN codepoint and the address it goes to.
pub const Sent = files.quic_connection.Sent;
/// An address and port as the program names a peer (decision 72): `Address.of(octets, port)`.
pub const Address = quic.PeerAddress;
/// The ECN field of a datagram's IP header, by RFC 9000 §13.4's names, which a program reads and
/// sets when `Config.ecn` is set (decision 68).
pub const Ecn = quic.connection_send.Ecn;
pub const StartError = files.connection_errors.StartError;
pub const SendError = files.connection_errors.SendError;
pub const Field = http.Field;
pub const Id = files.event.Id;
pub const ConnectionHandle = files.event.ConnectionHandle;
pub const Version = files.event.Version;
pub const Fields = files.event.Fields;
pub const Event = files.event.Event;
pub const Request = files.event.Request;
pub const Body = files.event.Body;
pub const Trailers = files.event.Trailers;
pub const Cancelled = files.event.Cancelled;
pub const CancelReason = files.event.CancelReason;
pub const Done = files.event.Done;
pub const Writable = files.event.Writable;
pub const Ended = files.event.Ended;
pub const Response = files.event.Response;
pub const Content = files.event.Content;
pub const Received = files.event.Received;
pub const Alternative = files.alt_svc.Alternative;
/// The content codings a server applies (decision 101).
pub const Coding = http.content_coding.Coding;
pub const EncoderPool = files.coding_pool.EncoderPool;
pub const DefaultEncoderPool = files.coding_pool.DefaultEncoderPool;
pub const Encoders = files.coding_pool.Encoders;
/// The pool of decoders h11 removes the `gzip` and `deflate` transfer codings of a request with
/// (decision 91), which the caller places: `DecoderPool(count)` for `count` decoders, or
/// `DefaultDecoderPool`. A configuration holds it as `Decoders`, from `storage()` after `reset`.
pub const DecoderPool = h11.coding.Pool;
pub const DefaultDecoderPool = h11.coding.DefaultPool;
pub const Decoders = h11.coding.Storage;
/// The CPU features a pool's codecs run on, which its `reset` takes: `Features.detect()` asks the
/// CPU, as colibri never does itself, and `Features.target()` is what the build target guarantees.
pub const Features = files.coding_pool.Features;

test "design §8 step 17f: the root exports its constants and the types a program names" {
    // Design §8 step 21a adds `Versions` and `Limits` (decision 117), 21b.2 `ConnectionHandle`,
    // `Writable` and `Ended`, and 21b.3 `Capacity`, `Input` and `Datagram`. 21b.7 gives the name
    // `Config` to the type `EndpointConfig` named, which `QuicConfig` folded into in 21b.3, and
    // takes a TCP connection's own configuration out of the root (decision 119). 21d takes out
    // `Connection` and `QuicConnection`, which the endpoint holds, and `Error` and `Protocol`,
    // which only their calls return (decision 121).
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants",   "Config",             "Versions", "Limits",           "Deadline",
        "Deadlines",   "CloseReason",        "Limit",    "Endpoint",         "EndpointOf",
        "Capacity",    "Input",              "Datagram", "Security",         "StreamOctets",
        "LogProvider", "Sent",               "Address",  "Ecn",              "StartError",
        "SendError",   "Field",              "Id",       "ConnectionHandle", "Version",
        "Fields",      "Event",              "Request",  "Body",             "Trailers",
        "Cancelled",   "CancelReason",       "Done",     "Writable",         "Ended",
        "Response",    "Content",            "Received", "Alternative",      "Coding",
        "EncoderPool", "DefaultEncoderPool", "Encoders", "DecoderPool",      "DefaultDecoderPool",
        "Decoders",    "Features",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves.
    _ = @import("core").public_names.reference(@This(), &.{});
    // The TCP connection each slot of the endpoint holds. The root exports no name of it, and its
    // own test block runs its test files.
    _ = @import("connection/connection.zig");
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
    _ = @import("endpoint/endpoint_slots.zig");
    _ = @import("endpoint/endpoint_ready.zig");
    _ = @import("endpoint/endpoint_deadline_heap.zig");
    _ = @import("endpoint/endpoint_requests.zig");
    _ = @import("endpoint/endpoint_test.zig");
    _ = @import("endpoint/endpoint_held_test.zig");
    _ = @import("endpoint/endpoint_config.zig");
    _ = @import("endpoint/endpoint_writable_test.zig");
    _ = @import("endpoint/endpoint_tcp_test.zig");
    _ = @import("endpoint/endpoint_tcp_send_test.zig");
    _ = @import("endpoint/endpoint_tcp_writable_test.zig");
    _ = @import("quic/quic_connection_h3_room.zig");
    _ = @import("coding/coding_ring.zig");
    _ = @import("coding/coding_rules.zig");
    _ = @import("coding/coding_fields.zig");
    _ = @import("coding/coding_response.zig");
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
