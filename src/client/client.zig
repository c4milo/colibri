//! colibri's client (decision 100, design §8 step 17): HTTP requests behind one set of calls for
//! h11, h2 and h3, over TCP or QUIC, the version chosen by ALPN over TLS and named in cleartext.
//!
//! A program makes one `Config` for an origin, then a `ConnectionPool` to it, in storage it owns
//! (decision 120). The pool says which transport to open and where, and the program starts the
//! connection it asked for on the socket it opened. For each exchange the program places a
//! `Request` and a `Response` in its own memory, and hands both to `request` (decision 124). It
//! passes what each socket read to `receive`, which returns at most one event, and sends what
//! `send_stream` and `send_datagram` write. colibri makes no system call and reads no clock: time
//! is a value the caller passes.
//!
//! The pool runs each connection's TLS handshake itself, so a program that uses this module
//! links chapulin. One that wants no TLS uses `h11` or `h2` directly.
const std = @import("std");
const quic = @import("quic");
const h11 = @import("h11");
const http = @import("http");

/// The module's named limits and sizes (decision 35). It is the one file the root exports whole:
/// every other name below is a type a program names (design §8 step 17f).
pub const constants = @import("constants.zig");

/// Every file a name below comes from. None of these is exported: the names below are.
const files = struct {
    pub const coding_pool = @import("coding_pool.zig");
    pub const event = @import("event.zig");
    pub const pool = @import("pool/pool.zig");
    pub const protocols = @import("protocols.zig");
};

pub const Config = files.pool.Config;
pub const Protocols = files.protocols.Protocols;
/// Why `ConnectionPool.init`, `ConnectionPool.start_tcp` or `ConnectionPool.start_quic` refused (decisions 120 and 123).
pub const StartError = files.pool.StartError;
pub const RequestError = files.pool.RequestError;
pub const Header = files.event.Header;
pub const RequestId = files.event.RequestId;
pub const Protocol = files.event.Protocol;
/// What a program sends, and where the response goes and what arrived (decision 124).
pub const Request = files.event.Request;
pub const Response = files.event.Response;
pub const WantedHeader = files.event.WantedHeader;
pub const Result = files.event.Result;
pub const Finished = files.event.Finished;
/// A datagram `ConnectionPool.send_datagram` wrote, with its ECN codepoint and the address it goes to.
pub const Sent = files.pool.Sent;
/// An address and port as the program names a peer (decision 72): `Address.of(octets, port)`.
pub const Address = files.pool.Address;
/// The ECN field of a datagram's IP header, by RFC 9000 §13.4's names, which a program reads and
/// sets when `Config.ecn` is set (decision 68).
pub const Ecn = quic.connection_send.Ecn;
pub const ConnectionPool = files.pool.ConnectionPool;
/// A pool that holds the connections a `Capacity` names (decision 124). `ConnectionPool` is
/// `ConnectionPoolOf(.{})`, and a program that never speaks h3 places a `ConnectionPoolOf(.{ .quic = false })`,
/// which holds no QUIC state.
pub const ConnectionPoolOf = files.pool.ConnectionPoolOf;
pub const Capacity = files.pool.Capacity;
/// The counts a pool holds, set at run time, and which `ConnectionPool.memory_bytes` sizes (decision 125).
pub const Options = files.pool.Options;
/// What DNS knows of the origin, which `ConnectionPool.init` takes, an HTTPS record's values in it, and
/// the h3 alternative a pool learned from Alt-Svc.
pub const Destination = files.pool.Destination;
pub const HttpsRecord = files.pool.HttpsRecord;
pub const Alternative = files.pool.Alternative;
/// What a program passes `ConnectionPool.receive`, and what it returns.
pub const Input = files.pool.Input;
/// The octets a TCP socket read, with the connection whose socket read them (decision 125).
pub const StreamBytes = files.pool.StreamBytes;
pub const Datagram = files.pool.Datagram;
pub const ReceiveResult = files.pool.ReceiveResult;
pub const Event = files.pool.Event;
/// The transport an `open` event asks for and where it goes, and which of the two transports a
/// pool's calls name.
pub const Open = files.pool.Open;
/// A connection of a pool, which its events and the calls about it name (decision 125), and the
/// connection that takes the exchanges with its version.
pub const ConnectionHandle = files.pool.ConnectionHandle;
pub const Connected = files.pool.Connected;
pub const Transport = files.pool.Transport;
/// Where a transport's connection stands at a pool, as spec/tla/client_exchanges names it
/// (decision 105). `ConnectionPool.phase` returns it, and the simulator's trace reads it. A program reads
/// the events.
pub const Phase = files.pool.Phase;
/// The pool a QUIC connection holds the server's unread octets in (decision 61), which the caller
/// places: `ReceivePool(capacity)` for `capacity` octets, a whole number of
/// `quic.constants.stream_receive_block_len` blocks, or the 1 MiB of `DefaultReceivePool`. The
/// capacity bounds every window the client advertises, and so how fast one connection receives.
pub const ReceivePool = quic.stream.stream_incoming.Pool;
pub const DefaultReceivePool = quic.stream.stream_incoming.DefaultPool;
pub const ReceiveStorage = files.pool.ReceiveStorage;
/// The content codings a client decodes (decision 101).
pub const Coding = http.content_coding.Coding;
/// The pool of decoders a client removes content codings with (decision 101), which the caller
/// places: `DecoderPool(count)` for `count` decoders, or `DefaultDecoderPool`. A configuration
/// holds it as `Decoders`, from `storage()` after `reset`, and connections may share one.
pub const DecoderPool = h11.coding.Pool;
pub const DefaultDecoderPool = h11.coding.DefaultPool;
pub const Decoders = h11.coding.Storage;
/// The pools of `zstd` and `br` decoders (decision 101 as amended), which the caller places and
/// resets as it does `DecoderPool`. Each decoder of a `ZstdDecoderPool(count)` holds an 8 MB window
/// (RFC 9659 §3), and each of a `BrotliDecoderPool(count)` a 16 MiB one (RFC 7932 §9.1);
/// docs/usage.md gives their sizes. A configuration holds each as `ZstdDecoders` or
/// `BrotliDecoders`, from `storage()`.
pub const ZstdDecoderPool = files.coding_pool.ZstdDecoderPool;
pub const ZstdDecoders = files.coding_pool.ZstdDecoders;
pub const BrotliDecoderPool = files.coding_pool.BrotliDecoderPool;
pub const BrotliDecoders = files.coding_pool.BrotliDecoders;
/// The CPU features a pool's codecs run on, which its `reset` takes: `Features.detect()` asks the
/// CPU, as colibri never does itself, and `Features.target()` is what the build target guarantees.
pub const Features = files.coding_pool.Features;

test "design §8 step 17f: the root exports its constants and the types a program names" {
    // Design §8 step 21d takes out `Connection` and `QuicConnection`, which the channel holds, and
    // `Event`, `Received` and `Advert`, which only their calls return (decision 121). It removes
    // the `Channel` prefix from the channel's types, and takes out `ChannelEntry`, which no call
    // of `Channel` takes or returns. Step 21f.2 puts `Request` and `Response` in place of
    // `HttpExchange` (decision 124). Step 21f.6 adds `ChannelOf` and `Capacity` (decision 124).
    // Step 22.2 renames `Channel` to `ConnectionPool` and `ChannelOf` to `ConnectionPoolOf`, step 22.3 adds
    // `Options`, and step 22.4 adds `StreamOctets`, `ConnectionHandle` and `Connected` (decision
    // 125). Step 23.2 renames `Field`, `Id`, `StreamOctets` and `Received` to `Header`,
    // `RequestId`, `StreamBytes` and `ReceiveResult` (decision 126). Step 23.3 renames `Versions`
    // to `Protocols`, and 23.4 renames `Pool`, `PoolOf`, `Values`, `Https`, `Wanted` and `Outcome`
    // to `ConnectionPool`, `ConnectionPoolOf`, `Destination`, `HttpsRecord`, `WantedHeader` and
    // `Result`.
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants",       "Config",         "Protocols",         "StartError",         "RequestError",
        "Header",          "RequestId",      "Protocol",          "Request",            "Response",
        "WantedHeader",    "Result",         "Finished",          "Sent",               "Address",
        "Ecn",             "ConnectionPool", "ConnectionPoolOf",  "Capacity",           "Options",
        "Destination",     "HttpsRecord",    "Alternative",       "Input",              "StreamBytes",
        "Datagram",        "ReceiveResult",  "Event",             "Open",               "ConnectionHandle",
        "Connected",       "Transport",      "Phase",             "ReceivePool",        "DefaultReceivePool",
        "ReceiveStorage",  "Coding",         "DecoderPool",       "DefaultDecoderPool", "Decoders",
        "ZstdDecoderPool", "ZstdDecoders",   "BrotliDecoderPool", "BrotliDecoders",     "Features",
    });
}

test "decision 124: StartError names what ConnectionPool.init and the two starts return, and no other error" {
    // A switch names each member of the set once. A member added to a set, or taken out of it,
    // stops the test from compiling. A pool with no QUIC returns the same set.
    const names = struct {
        fn of(comptime Set: type, failure: Set) []const u8 {
            return switch (failure) {
                error.TlsRefused => "TlsRefused",
                error.NoVersion => "NoVersion",
                error.TooManyAnchors => "TooManyAnchors",
                error.TooManySuites => "TooManySuites",
                error.SuitesUnavailable => "SuitesUnavailable",
                error.VersionUnavailable => "VersionUnavailable",
            };
        }

        fn returned(comptime Call: type) type {
            return @typeInfo(@typeInfo(Call).@"fn".return_type.?).error_union.error_set;
        }
    };
    const TcpAlone = ConnectionPoolOf(.{ .quic = false });
    const sets = .{
        StartError,                                        names.returned(@TypeOf(ConnectionPool.init)),
        names.returned(@TypeOf(ConnectionPool.start_tcp)), names.returned(@TypeOf(ConnectionPool.start_quic)),
        names.returned(@TypeOf(TcpAlone.init)),
    };
    inline for (sets) |Set| {
        inline for (@typeInfo(Set).error_set.?) |member| {
            try std.testing.expectEqualStrings(member.name, names.of(Set, @field(Set, member.name)));
        }
    }
}

test "decision 121: RequestError names what ConnectionPool.request returns, and no other error" {
    // A switch names each member of the set once. A member added to a set, or taken out of it,
    // stops the test from compiling. A connection that drains or closes gets no new exchange from
    // its pool, so `request` never returns `Draining` or `ConnectionClosed`.
    const names = struct {
        fn of(comptime Set: type, failure: Set) []const u8 {
            return switch (failure) {
                error.Full => "Full",
                error.RequestUnsupported => "RequestUnsupported",
                error.FieldReserved => "FieldReserved",
            };
        }
    };
    const Returned = @typeInfo(@typeInfo(@TypeOf(ConnectionPool.request)).@"fn".return_type.?).error_union.error_set;
    inline for (.{ RequestError, Returned }) |Set| {
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
    // The two connections the pool holds, and the file that reads a response's Alt-Svc field.
    // The root exports no name of them, and each one's own test block runs its test files.
    _ = @import("connection/connection.zig");
    _ = @import("quic/quic_connection.zig");
    _ = @import("alt_svc.zig");
    _ = @import("protocols.zig");
    _ = @import("slots.zig");
    _ = @import("response_write.zig");
    _ = @import("coding.zig");
    _ = @import("coding_pool.zig");
    _ = @import("owed.zig");
    _ = @import("event_internal.zig");
    _ = @import("pool/pool_choice.zig");
    _ = @import("pool/pool_config_test.zig");
    _ = @import("pool/pool_test.zig");
    _ = @import("pool/pool_h11_test.zig");
    _ = @import("pool/pool_tls_test.zig");
    _ = @import("pool/pool_limits_test.zig");
    _ = @import("pool/pool_capacity_test.zig");
    _ = @import("pool/pool_memory_test.zig");
    _ = @import("pool/pool_send_test.zig");
    _ = @import("pool/pool_send_h2_test.zig");
    _ = @import("pool/pool_grow_test.zig");
    _ = @import("pool/pool_connection.zig");
    _ = @import("pool/pool_links.zig");
    _ = @import("pool/pool_state.zig");
    _ = @import("pool/pool_handle.zig");
    _ = @import("pool/pool_quic_test.zig");
    _ = @import("pool/pool_quic_flow_test.zig");
    _ = @import("quic/quic_connection_test.zig");
    _ = @import("quic/quic_connection_flow_test.zig");
    _ = @import("quic/quic_connection_idle_test.zig");
    _ = @import("quic/quic_coding_test.zig");
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
