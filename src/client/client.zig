//! colibri's client (decision 100, design §8 step 17): HTTP requests behind one set of calls for
//! h11 and h2 over TCP, the version chosen by ALPN over TLS and named in cleartext. Step 17d adds
//! h3 over QUIC and the choice between the transports.
//!
//! A program makes one `Config` for an origin, then a `Connection` for each TCP connection it opens
//! to it, in storage it owns. For each request it places an `HttpExchange` in its own memory, which
//! holds the request and where the response goes, and hands it to `request`. It sends what `send`
//! writes and passes the octets it read to `receive`, which returns at most one event: the version
//! the connection speaks, a resumption ticket, an exchange's end, draining, or the close. colibri
//! makes no system call and reads no clock: time is a value the caller passes.
//!
//! Over TLS, the connection runs the handshake through `tls.record.Client` itself, so a program
//! that uses this module links chapulin. One that wants no TLS uses `h11` or `h2` directly.
const std = @import("std");
const quic = @import("quic");
const h11 = @import("h11");
const http = @import("http");
const coding_pool = @import("coding_pool.zig");
const event = @import("event.zig");
const connection = @import("connection/connection.zig");
const quic_connection = @import("quic/quic_connection.zig");
const channel = @import("channel/channel.zig");
const alt_svc = @import("alt_svc.zig");

/// The module's named limits and sizes (decision 35). It is the one file the root exports whole:
/// every other name below is a type a program names (design §8 step 17f).
pub const constants = @import("constants.zig");

pub const Config = connection.Config;
pub const Connection = connection.Connection;
pub const StartError = connection.StartError;
pub const RequestError = connection.RequestError;
pub const Field = event.Field;
pub const Id = event.Id;
pub const Protocol = event.Protocol;
pub const HttpExchange = event.HttpExchange;
pub const Wanted = event.Wanted;
pub const Outcome = event.Outcome;
pub const Event = event.Event;
pub const Finished = event.Finished;
pub const Received = event.Received;
/// What one response's Alt-Svc field says of h3 on the origin's host (RFC 7838 §3), which
/// `Connection.take_alt_svc` returns.
pub const Advert = alt_svc.Advert;
pub const QuicConnection = quic_connection.QuicConnection;
pub const QuicConfig = quic_connection.Config;
pub const QuicStart = quic_connection.Start;
pub const QuicStartError = quic_connection.StartError;
/// A datagram a QUIC connection or a channel wrote, with its ECN codepoint and the address it
/// goes to.
pub const Sent = quic_connection.Sent;
/// An address and port as the program names a peer (decision 72): `Address.of(octets, port)`.
pub const Address = channel.Address;
/// The ECN field of a datagram's IP header, by RFC 9000 §13.4's names, which a program reads and
/// sets when `QuicConfig.ecn` is set (decision 68).
pub const Ecn = quic.connection_send.Ecn;
pub const Channel = channel.Channel;
pub const ChannelConfig = channel.Config;
/// What DNS knows of the origin, which `Channel.init` takes, an HTTPS record's values in it, and
/// the h3 alternative a channel learned from Alt-Svc.
pub const ChannelValues = channel.Values;
pub const Https = channel.Https;
pub const Alternative = channel.Alternative;
/// What a program passes `Channel.receive`, and what it returns.
pub const ChannelInput = channel.Input;
pub const Datagram = channel.Datagram;
pub const ChannelReceived = channel.Received;
pub const ChannelEvent = channel.Event;
/// The transport an `open` event asks for and where it goes, and which of the two transports a
/// channel's calls name.
pub const ChannelOpen = channel.Open;
pub const Transport = channel.Transport;
/// Where a transport's connection and an exchange stand at a channel, as
/// spec/tla/client_exchanges names them (decision 105). The simulator's trace reads them: a
/// program reads the events.
pub const ChannelPhase = channel.Phase;
pub const ChannelEntry = channel.Entry;
/// The pool a QUIC connection holds the server's unread octets in (decision 61), which the caller
/// places: `ReceivePool(capacity)` for `capacity` octets, a whole number of
/// `quic.constants.stream_receive_block_len` blocks, or the 1 MiB of `DefaultReceivePool`. The
/// capacity bounds every window the client advertises, and so how fast one connection receives.
pub const ReceivePool = quic.stream.stream_incoming.Pool;
pub const DefaultReceivePool = quic.stream.stream_incoming.DefaultPool;
pub const ReceiveStorage = quic_connection.ReceiveStorage;
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
pub const ZstdDecoderPool = coding_pool.ZstdDecoderPool;
pub const ZstdDecoders = coding_pool.ZstdDecoders;
pub const BrotliDecoderPool = coding_pool.BrotliDecoderPool;
pub const BrotliDecoders = coding_pool.BrotliDecoders;
/// The CPU features a pool's codecs run on, which its `reset` takes: `Features.detect()` asks the
/// CPU, as colibri never does itself, and `Features.target()` is what the build target guarantees.
pub const Features = coding_pool.Features;

test "design §8 step 17f: the root exports its constants and the types a program names" {
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants",          "Config",             "Connection",      "StartError",     "RequestError",
        "Field",              "Id",                 "Protocol",        "HttpExchange",   "Wanted",
        "Outcome",            "Event",              "Finished",        "Received",       "Advert",
        "QuicConnection",     "QuicConfig",         "QuicStart",       "QuicStartError", "Sent",
        "Address",            "Ecn",                "Channel",         "ChannelConfig",  "ChannelValues",
        "Https",              "Alternative",        "ChannelInput",    "Datagram",       "ChannelReceived",
        "ChannelEvent",       "ChannelOpen",        "Transport",       "ChannelPhase",   "ChannelEntry",
        "ReceivePool",        "DefaultReceivePool", "ReceiveStorage",  "Coding",         "DecoderPool",
        "DefaultDecoderPool", "Decoders",           "ZstdDecoderPool", "ZstdDecoders",   "BrotliDecoderPool",
        "BrotliDecoders",     "Features",
    });
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("slots.zig");
    _ = @import("response.zig");
    _ = @import("coding.zig");
    _ = @import("coding_pool.zig");
    _ = @import("owed.zig");
    _ = @import("channel/channel_choice.zig");
    _ = @import("channel/channel_test.zig");
    _ = @import("channel/channel_quic_test.zig");
    _ = @import("channel/channel_quic_flow_test.zig");
    _ = @import("quic/quic_connection_test.zig");
    _ = @import("quic/quic_connection_flow_test.zig");
    _ = @import("quic/quic_connection_idle_test.zig");
    _ = @import("quic/quic_coding_test.zig");
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
