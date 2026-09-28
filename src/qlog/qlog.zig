//! qlog, the structured log of draft-ietf-quic-qlog-main-schema-14, in a buffer the caller owns
//! (decision 102). `quic` and `h3` fill its event records when their caller gives them a log, and
//! the caller writes the records where it wants. Imports stdx's `json` and `codec` (docs/design.md
//! §3).
const std = @import("std");

pub const constants = @import("constants.zig");

/// stdx's JSON module (decision 102 as amended). Every record is one text of a JSON text sequence
/// that its `TextWriter` writes, and its `TextReader` reads one back.
pub const json = @import("json");
pub const TextWriter = json.TextWriter;

/// The CPU features stdx's JSON writer may use, which a log's caller passes to `Log.init`
/// (decision 102 as amended), as it passes them to h11's decoder pool (decision 98).
pub const Features = @import("codec").Features;

/// One member of an object, its name and its value, which every record is made of.
pub const member = @import("member.zig");
pub const Error = member.Error;

/// The log: the header record and one record per event, as JSON Text Sequences (RFC 7464).
pub const log = @import("log.zig");
pub const Log = log.Log;
pub const Trace = log.Trace;
pub const VantagePoint = log.VantagePoint;

/// The QUIC frames of quic-events §8.13, one writer per frame type.
pub const quic_frame = @import("quic_frame.zig");

/// The QUIC events of quic-events §3 that `quic` logs.
pub const quic_event = @import("quic_event.zig");

/// The HTTP/3 events of h3-events §3 that `h3` logs, and the frames they carry.
pub const h3_event = @import("h3_event.zig");

/// The event schema of the QUIC events. Quic-events §2.1 has an implementation of draft 13 name
/// it with the draft number until the RFC publishes.
pub const quic_event_schema = "urn:ietf:params:qlog:events:quic-13";

/// The event schema of the HTTP/3 events, named the same way (h3-events §2.1).
pub const http3_event_schema = "urn:ietf:params:qlog:events:http3-13";

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = member;
    _ = log;
    _ = quic_frame;
    _ = quic_event;
    _ = h3_event;
}
