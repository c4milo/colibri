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
    pub const protocols = @import("protocols.zig");
    pub const limits = @import("limits.zig");
    pub const path_parameters = @import("path_parameters.zig");
    pub const router = @import("router/router.zig");
    pub const router_pool = @import("router/router_pool.zig");
    pub const middleware = @import("middleware.zig");
    pub const response_writer = @import("response_writer/response_writer.zig");
};

/// What a program configures a server with, once: the endpoint reads it while it runs (decision
/// 119).
pub const Config = files.endpoint.Config;
pub const Protocols = files.protocols.Protocols;
pub const Limits = files.limits.Limits;
pub const Timeout = files.deadline.Timeout;
pub const Timeouts = files.deadline.Timeouts;
pub const CloseReason = files.close_reason.CloseReason;
pub const Limit = files.close_reason.Limit;
pub const Endpoint = files.endpoint.Endpoint;
pub const EndpointOf = files.endpoint.EndpointOf;
pub const Capacity = files.endpoint.Capacity;
/// What `Endpoint.receive` takes: `.none`, the `StreamBytes` a program's TCP socket read, or a
/// `Datagram` its UDP socket read.
pub const Input = files.endpoint.Input;
pub const Datagram = files.endpoint.Datagram;
pub const StreamBytes = files.endpoint.StreamBytes;
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
pub const Header = files.event.Header;
pub const RequestId = files.event.RequestId;
pub const ConnectionHandle = files.event.ConnectionHandle;
pub const Version = files.event.Version;
pub const Headers = files.event.Headers;
pub const Event = files.event.Event;
pub const Request = files.event.Request;
pub const RequestBody = files.event.RequestBody;
pub const Trailers = files.event.Trailers;
pub const CancelReason = files.event.CancelReason;
pub const Finished = files.event.Finished;
pub const Result = files.event.Result;
pub const Writable = files.event.Writable;
pub const Ended = files.event.Ended;
pub const Response = files.event.Response;
pub const ResponseBody = files.event.ResponseBody;
/// The response a route's function writes: a status, headers, and a body through a
/// `std.Io.Writer` (decision 127).
pub const ResponseWriter = files.response_writer.ResponseWriter;
pub const ReceiveResult = files.event.ReceiveResult;
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
/// The parameters of a path that a route table matched, which the program places and reads with
/// `get` (decision 122).
pub const PathParameters = files.path_parameters.PathParameters;

/// What a router's `handle` did with an event: it took it, or hands it back (decision 127).
pub const Handled = files.router_pool.Handled;

/// Builds a route table at compile time, which calls the program's functions in `handle`, and
/// whose `match` names the route of a method and a path (decisions 122 and 127). A function named
/// after its file is exported under its own name.
pub const router = files.router.router;

/// What a router's middleware returns (decision 127 ruling 5).
pub const middleware = struct {
    pub const Next = files.middleware.Next;
};

test "design §8 step 17f: the root exports its constants and the types a program names" {
    // Design §8 step 21a adds `Protocols` and `Limits` (decision 117), 21b.2 `ConnectionHandle`,
    // `Writable` and `Ended`, and 21b.3 `Capacity`, `Input` and `Datagram`. 21b.7 gives the name
    // `Config` to the type `EndpointConfig` named, which `QuicConfig` folded into in 21b.3, and
    // takes a TCP connection's own configuration out of the root (decision 119). 21d takes out
    // `Connection` and `QuicConnection`, which the endpoint holds, and `Error` and `Protocol`,
    // which only their calls return (decision 121). 21e adds `PathParameters` and `router`
    // (decision 122). 23.2 renames `StreamOctets`, `Field`, `Id`, `Fields`, `Body`, `Content` and
    // `Received` to `StreamBytes`, `Header`, `RequestId`, `Headers`, `RequestBody`,
    // `ResponseBody` and `ReceiveResult` (decision 126). 23.3 renames `Versions`, `Deadline` and
    // `Deadlines` to `Protocols`, `Timeout` and `Timeouts`, and 23.6 takes out `Security`. 23.7 puts
    // `Finished` and `Result` in place of `Done` and `Cancelled`. 25.2 adds `ResponseWriter`, 25.3 `Handled`, and 25.5 `middleware`.
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants",    "Config",             "Protocols",        "Limits",      "Timeout",
        "Timeouts",     "CloseReason",        "Limit",            "Endpoint",    "EndpointOf",
        "Capacity",     "Input",              "Datagram",         "StreamBytes", "LogProvider",
        "Sent",         "Address",            "Ecn",              "StartError",  "SendError",
        "Header",       "RequestId",          "ConnectionHandle", "Version",     "Headers",
        "Event",        "Request",            "RequestBody",      "Trailers",    "CancelReason",
        "Finished",     "Result",             "Writable",         "Ended",       "Response",
        "ResponseBody", "ResponseWriter",     "ReceiveResult",    "Alternative", "Coding",
        "EncoderPool",  "DefaultEncoderPool", "Encoders",         "DecoderPool", "DefaultDecoderPool",
        "Decoders",     "Features",           "PathParameters",   "Handled",     "router",
        "middleware",
    });
}

test "decision 121: StartError names what Endpoint.init returns, and no other error" {
    // A switch names each member of the set once. A member added to a set, or taken out of it,
    // stops the test from compiling. The endpoint changes chapulin's refusal of a TCP connection's
    // session into a null `accept`, so `init` never returns `TlsRefused`.
    const names = struct {
        fn of(comptime Set: type, failure: Set) []const u8 {
            return switch (failure) {
                error.TimeoutInvalid => "TimeoutInvalid",
                error.NoVersion => "NoVersion",
                error.IdentityRefused => "IdentityRefused",
                error.TooManyCertificates => "TooManyCertificates",
                error.TooManySuites => "TooManySuites",
                error.SuitesUnavailable => "SuitesUnavailable",
            };
        }
    };
    const Returned = @typeInfo(@typeInfo(@TypeOf(Endpoint.init)).@"fn".return_type.?).error_union.error_set;
    inline for (.{ StartError, Returned }) |Set| {
        inline for (@typeInfo(Set).error_set.?) |member| {
            try std.testing.expectEqualStrings(member.name, names.of(Set, @field(Set, member.name)));
        }
    }
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves.
    _ = @import("core").public_names.reference(@This(), &.{});
    // The TCP connection each slot of the endpoint holds. The root exports no name of it, and its
    // own test block runs its test files.
    _ = @import("connection/connection.zig");
    _ = @import("protocols.zig");
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
    _ = @import("quic/quic_head_test.zig");
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
    _ = @import("router/router_table.zig");
    _ = @import("router/router_test.zig");
    _ = @import("router/router_parameter_test.zig");
    _ = @import("router/router_fuzz_test.zig");
    _ = @import("router/router_refusal_test.zig");
    _ = @import("response_writer/response_writer_internal.zig");
    // `zig build router-hidden-check` runs `router/router_hidden_test.zig` and
    // `router/router_quota_test.zig`, each in a binary of its own, because each compile takes
    // about a minute (the owner's rulings of 2026-10-14).
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
