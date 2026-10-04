//! qlog, the structured log of draft-ietf-quic-qlog-main-schema-14, in a buffer the caller owns
//! (decision 102). `quic` and `h3` fill its event records when their caller gives them a log, and
//! the caller writes the records where it wants. Imports stdx's `json` and `codec` (docs/design.md
//! §3).
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

/// stdx's JSON module (decision 102 as amended). Every record is one text of a JSON text sequence,
/// and its `TextReader` reads one back.
pub const json = @import("json");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    /// One member of an object, its name and its value, which every record is made of.
    pub const member = @import("member.zig");
    /// The log: the header record and one record per event, as JSON Text Sequences (RFC 7464).
    pub const log = @import("log.zig");
    /// The QUIC frames of quic-events §8.13, one writer per frame type.
    pub const quic_frame = @import("quic_frame.zig");
    /// The QUIC events of quic-events §3 that `quic` logs.
    pub const quic_event = @import("quic_event.zig");
    /// The HTTP/3 events of h3-events §3 that `h3` logs, and the frames they carry.
    pub const h3_event = @import("h3_event.zig");
};

/// What writes a record: its tokens gathered and handed to stdx's `TextWriter` many at a call
/// (`batch.zig`), with `TextWriter`'s calls.
pub const TextWriter = @import("batch.zig").Batch;
/// The CPU features stdx's JSON writer may use, which a log's caller passes to `Log.init`
/// (decision 102 as amended), as it passes them to h11's decoder pool (decision 98).
pub const Features = @import("codec").Features;
pub const Error = files.member.Error;
pub const Log = files.log.Log;
pub const Trace = files.log.Trace;
pub const VantagePoint = files.log.VantagePoint;
/// The event schema of the QUIC events. Quic-events §2.1 has an implementation of draft 13 name
/// it with the draft number until the RFC publishes.
pub const quic_event_schema = "urn:ietf:params:qlog:events:quic-13";
/// The event schema of the HTTP/3 events, named the same way (h3-events §2.1).
pub const http3_event_schema = "urn:ietf:params:qlog:events:http3-13";

pub const member = struct {
    pub const unsigned = files.member.unsigned;
};

pub const quic_frame = struct {
    pub const Directionality = files.quic_frame.Directionality;
    pub const ErrorSpace = files.quic_frame.ErrorSpace;
    pub const ack_begin = files.quic_frame.ack_begin;
    pub const ack_end = files.quic_frame.ack_end;
    pub const ack_range = files.quic_frame.ack_range;
    pub const connection_close = files.quic_frame.connection_close;
    pub const crypto = files.quic_frame.crypto;
    pub const data_blocked = files.quic_frame.data_blocked;
    pub const handshake_done = files.quic_frame.handshake_done;
    pub const max_data = files.quic_frame.max_data;
    pub const max_stream_data = files.quic_frame.max_stream_data;
    pub const max_streams = files.quic_frame.max_streams;
    pub const new_connection_id = files.quic_frame.new_connection_id;
    pub const new_token = files.quic_frame.new_token;
    pub const padding = files.quic_frame.padding;
    pub const path_challenge = files.quic_frame.path_challenge;
    pub const path_response = files.quic_frame.path_response;
    pub const ping = files.quic_frame.ping;
    pub const reset_stream = files.quic_frame.reset_stream;
    pub const retire_connection_id = files.quic_frame.retire_connection_id;
    pub const stop_sending = files.quic_frame.stop_sending;
    pub const stream = files.quic_frame.stream;
    pub const stream_data_blocked = files.quic_frame.stream_data_blocked;
    pub const streams_blocked = files.quic_frame.streams_blocked;
};

pub const quic_event = struct {
    pub const AlpnInformation = files.quic_event.AlpnInformation;
    pub const ConnectionClosed = files.quic_event.ConnectionClosed;
    pub const ConnectionState = files.quic_event.ConnectionState;
    pub const ConnectionStateUpdated = files.quic_event.ConnectionStateUpdated;
    pub const Duration = files.quic_event.Duration;
    pub const Hex = files.quic_event.Hex;
    pub const Initiator = files.quic_event.Initiator;
    pub const LossTrigger = files.quic_event.LossTrigger;
    pub const PacketDropped = files.quic_event.PacketDropped;
    pub const PacketHeader = files.quic_event.PacketHeader;
    pub const PacketLost = files.quic_event.PacketLost;
    pub const PacketType = files.quic_event.PacketType;
    pub const ParametersSet = files.quic_event.ParametersSet;
    pub const Raw = files.quic_event.Raw;
    pub const RecoveryMetricsUpdated = files.quic_event.RecoveryMetricsUpdated;
    pub const TupleAssigned = files.quic_event.TupleAssigned;
    pub const TupleEndpointInfo = files.quic_event.TupleEndpointInfo;
    pub const VersionInformation = files.quic_event.VersionInformation;
    pub const begin_frames = files.quic_event.begin_frames;
    pub const end_frames = files.quic_event.end_frames;
    pub const field = files.quic_event.field;
    pub const name = files.quic_event.name;
};

pub const h3_event = struct {
    pub const ParametersSet = files.h3_event.ParametersSet;
    pub const SettingName = files.h3_event.SettingName;
    pub const StreamTypeSet = files.h3_event.StreamTypeSet;
    pub const begin_frame = files.h3_event.begin_frame;
    pub const begin_headers = files.h3_event.begin_headers;
    pub const begin_settings = files.h3_event.begin_settings;
    pub const end_frame = files.h3_event.end_frame;
    pub const end_headers = files.h3_event.end_headers;
    pub const end_settings = files.h3_event.end_settings;
    pub const field_line = files.h3_event.field_line;
    pub const frame_type_bytes = files.h3_event.frame_type_bytes;
    pub const name = files.h3_event.name;
    pub const setting = files.h3_event.setting;
};

test "decision 115: the root exports the names code outside the module uses" {
    const expected = [_][]const u8{
        "json",              "constants",          "TextWriter", "Features",
        "Error",             "Log",                "Trace",      "VantagePoint",
        "quic_event_schema", "http3_event_schema", "member",     "quic_frame",
        "quic_event",        "h3_event",
    };
    const declared = @typeInfo(@This()).@"struct".decls;
    var names: [declared.len][]const u8 = undefined;
    inline for (declared, &names) |declaration, *name| name.* = declaration.name;
    try std.testing.expectEqual(expected.len, names.len);
    for (expected, names) |want, have| try std.testing.expectEqualStrings(want, have);
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    _ = @import("batch.zig");
}
