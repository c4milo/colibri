//! colibri's client (decision 100, design §8 step 17): HTTP requests behind one set of calls for
//! h11, h2 and h3, over TCP or QUIC, the version chosen by ALPN over TLS and named in cleartext.
//!
//! A program makes one `Config` for an origin, then a `Channel` to it, in storage it owns
//! (decision 120). The channel says which transport to open and where, and the program starts the
//! connection it asked for on the socket it opened. For each request the program places an
//! `HttpExchange` in its own memory, which holds the request and where the response goes, and
//! hands it to `request`. It passes what each socket read to `receive`, which returns at most one
//! event, and sends what `send_stream` and `send_datagram` write. colibri makes no system call and
//! reads no clock: time is a value the caller passes.
//!
//! The channel runs each connection's TLS handshake itself, so a program that uses this module
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
    pub const channel = @import("channel/channel.zig");
    pub const versions = @import("versions.zig");
};

pub const Config = files.channel.Config;
pub const Versions = files.versions.Versions;
/// Why `Channel.init`, `Channel.start_tcp` or `Channel.start_quic` refused (decision 120).
pub const StartError = files.channel.StartError;
pub const RequestError = files.channel.RequestError;
pub const Field = files.event.Field;
pub const Id = files.event.Id;
pub const Protocol = files.event.Protocol;
pub const HttpExchange = files.event.HttpExchange;
pub const Wanted = files.event.Wanted;
pub const Outcome = files.event.Outcome;
pub const Finished = files.event.Finished;
/// A datagram `Channel.send_datagram` wrote, with its ECN codepoint and the address it goes to.
pub const Sent = files.channel.Sent;
/// An address and port as the program names a peer (decision 72): `Address.of(octets, port)`.
pub const Address = files.channel.Address;
/// The ECN field of a datagram's IP header, by RFC 9000 §13.4's names, which a program reads and
/// sets when `Config.ecn` is set (decision 68).
pub const Ecn = quic.connection_send.Ecn;
pub const Channel = files.channel.Channel;
/// What DNS knows of the origin, which `Channel.init` takes, an HTTPS record's values in it, and
/// the h3 alternative a channel learned from Alt-Svc.
pub const Values = files.channel.Values;
pub const Https = files.channel.Https;
pub const Alternative = files.channel.Alternative;
/// What a program passes `Channel.receive`, and what it returns.
pub const Input = files.channel.Input;
pub const Datagram = files.channel.Datagram;
pub const Received = files.channel.Received;
pub const Event = files.channel.Event;
/// The transport an `open` event asks for and where it goes, and which of the two transports a
/// channel's calls name.
pub const Open = files.channel.Open;
pub const Transport = files.channel.Transport;
/// Where a transport's connection stands at a channel, as spec/tla/client_exchanges names it
/// (decision 105). `Channel.phase` returns it, and the simulator's trace reads it. A program reads
/// the events.
pub const Phase = files.channel.Phase;
/// The pool a QUIC connection holds the server's unread octets in (decision 61), which the caller
/// places: `ReceivePool(capacity)` for `capacity` octets, a whole number of
/// `quic.constants.stream_receive_block_len` blocks, or the 1 MiB of `DefaultReceivePool`. The
/// capacity bounds every window the client advertises, and so how fast one connection receives.
pub const ReceivePool = quic.stream.stream_incoming.Pool;
pub const DefaultReceivePool = quic.stream.stream_incoming.DefaultPool;
pub const ReceiveStorage = files.channel.ReceiveStorage;
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
    // of `Channel` takes or returns.
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants",         "Config",             "Versions",           "StartError",      "RequestError",
        "Field",             "Id",                 "Protocol",           "HttpExchange",    "Wanted",
        "Outcome",           "Finished",           "Sent",               "Address",         "Ecn",
        "Channel",           "Values",             "Https",              "Alternative",     "Input",
        "Datagram",          "Received",           "Event",              "Open",            "Transport",
        "Phase",             "ReceivePool",        "DefaultReceivePool", "ReceiveStorage",  "Coding",
        "DecoderPool",       "DefaultDecoderPool", "Decoders",           "ZstdDecoderPool", "ZstdDecoders",
        "BrotliDecoderPool", "BrotliDecoders",     "Features",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves.
    _ = @import("core").public_names.reference(@This(), &.{});
    // The two connections the channel holds, and the file that reads a response's Alt-Svc field.
    // The root exports no name of them, and each one's own test block runs its test files.
    _ = @import("connection/connection.zig");
    _ = @import("quic/quic_connection.zig");
    _ = @import("alt_svc.zig");
    _ = @import("versions.zig");
    _ = @import("slots.zig");
    _ = @import("response.zig");
    _ = @import("coding.zig");
    _ = @import("coding_pool.zig");
    _ = @import("owed.zig");
    _ = @import("channel/channel_choice.zig");
    _ = @import("channel/channel_config_test.zig");
    _ = @import("channel/channel_test.zig");
    _ = @import("channel/channel_h11_test.zig");
    _ = @import("channel/channel_tls_test.zig");
    _ = @import("channel/channel_quic_test.zig");
    _ = @import("channel/channel_quic_flow_test.zig");
    _ = @import("quic/quic_connection_test.zig");
    _ = @import("quic/quic_connection_flow_test.zig");
    _ = @import("quic/quic_connection_idle_test.zig");
    _ = @import("quic/quic_coding_test.zig");
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
