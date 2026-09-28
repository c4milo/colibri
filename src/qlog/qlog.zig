//! qlog, the structured log of draft-ietf-quic-qlog-main-schema-14, in a buffer the caller owns
//! (decision 102). `quic` and `h3` fill its event records when their caller gives them a log, and
//! the caller writes the records where it wants. Imports `core` alone (docs/design.md §3).
const std = @import("std");

pub const constants = @import("constants.zig");

/// The JSON text of RFC 8259 that every record is.
pub const json = @import("json.zig");
pub const Json = json.Json;

/// The log: the header record and one record per event, as JSON Text Sequences (RFC 7464).
pub const log = @import("log.zig");
pub const Log = log.Log;
pub const Trace = log.Trace;
pub const VantagePoint = log.VantagePoint;

/// The QUIC frames of quic-events §8.13, one writer per frame type.
pub const quic_frame = @import("quic_frame.zig");

/// The QUIC events of quic-events §3 that `quic` logs.
pub const quic_event = @import("quic_event.zig");

/// The event schema of the QUIC events. Quic-events §2.1 has an implementation of draft 13 name
/// it with the draft number until the RFC publishes.
pub const quic_event_schema = "urn:ietf:params:qlog:events:quic-13";

/// The event schema of the HTTP/3 events, named the same way (h3-events §2.1).
pub const http3_event_schema = "urn:ietf:params:qlog:events:http3-13";

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = json;
    _ = log;
    _ = quic_frame;
    _ = quic_event;
}
