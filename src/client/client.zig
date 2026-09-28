//! colibri's client (decision 100, design §8 step 17): HTTP requests behind one set of calls for
//! h11 and h2 over TCP, the version chosen by ALPN over TLS and named in cleartext. Step 17d adds
//! h3 over QUIC and the choice between the transports.
//!
//! A program makes one `Config` for an origin, then a `Connection` for each TCP connection it opens
//! to it, in storage it owns. For each request it places an `Exchange` in its own memory, which
//! holds the request and where the response goes, and hands it to `request`. It sends what `send`
//! writes and passes the octets it read to `receive`, which returns at most one event: the version
//! the connection speaks, a resumption ticket, an exchange's end, draining, or the close. colibri
//! makes no system call and reads no clock: time is a value the caller passes.
//!
//! Over TLS, the connection runs the handshake through `tls.record.Client` itself, so a program
//! that uses this module links chapulin. One that wants no TLS uses `h11` or `h2` directly.
const std = @import("std");

pub const constants = @import("constants.zig");
pub const event = @import("event.zig");
pub const connection = @import("connection.zig");
pub const quic_connection = @import("quic_connection.zig");
pub const origin = @import("origin.zig");
pub const alt_svc = @import("alt_svc.zig");

pub const Config = connection.Config;
pub const Connection = connection.Connection;
pub const StartError = connection.StartError;
pub const RequestError = connection.RequestError;
pub const Field = event.Field;
pub const Id = event.Id;
pub const Protocol = event.Protocol;
pub const Exchange = event.Exchange;
pub const Wanted = event.Wanted;
pub const Outcome = event.Outcome;
pub const Event = event.Event;
pub const Finished = event.Finished;
pub const Received = event.Received;
pub const QuicConnection = quic_connection.QuicConnection;
pub const QuicConfig = quic_connection.Config;
pub const QuicStart = quic_connection.Start;
pub const Origin = origin.Origin;
pub const OriginConfig = origin.Config;

test {
    std.testing.refAllDecls(@This());
    _ = @import("slots.zig");
    _ = @import("response.zig");
    _ = @import("owed.zig");
    _ = @import("origin_choice.zig");
    _ = @import("origin_test.zig");
    _ = @import("origin_quic_test.zig");
    _ = @import("origin_quic_flow_test.zig");
    _ = @import("quic_connection_test.zig");
    _ = @import("quic_connection_flow_test.zig");
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
}
