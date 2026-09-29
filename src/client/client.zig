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

pub const constants = @import("constants.zig");
pub const event = @import("event.zig");
pub const connection = @import("connection/connection.zig");
pub const quic_connection = @import("quic/quic_connection.zig");
pub const channel = @import("channel/channel.zig");
pub const alt_svc = @import("alt_svc.zig");

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
pub const QuicConnection = quic_connection.QuicConnection;
pub const QuicConfig = quic_connection.Config;
pub const QuicStart = quic_connection.Start;
pub const Channel = channel.Channel;
pub const ChannelConfig = channel.Config;
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

test {
    std.testing.refAllDecls(@This());
    _ = @import("slots.zig");
    _ = @import("response.zig");
    _ = @import("coding.zig");
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
