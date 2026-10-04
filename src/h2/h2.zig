//! HTTP/2, RFC 9113. RFC 9113 obsoletes RFC 7540; 7540 is never read and never cited.
//!
//! The pieces, bottom up: `frame` reads and writes the ten frame types (§4, §6); `settings` holds
//! the six settings and the acknowledgment discipline (§6.5); `window` is the signed flow-control
//! window (§5.2, §6.9, invariant 15); `stream` is the state machine of §5.1 as pure functions;
//! `streams` is the stream table over core's slot pool (§5.1.1, §5.1.2, decision 14);
//! `field_block` reassembles a field block fragment by fragment into one field section (§4.3,
//! decision 40); `message` checks a decoded field section as a request, a response or a trailer
//! section (§8); `connection` ties them together, one frame in and one event out (decision 39).
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const hpack = @import("hpack");
pub const tls_provider = @import("tls_provider");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const role = @import("role.zig");
    pub const frame = @import("frame/frame.zig");
    pub const settings = @import("settings.zig");
    pub const window = @import("window.zig");
    pub const stream = @import("stream/stream.zig");
    pub const streams = @import("stream/streams.zig");
    pub const field_block = @import("field_block/field_block.zig");
    pub const message = @import("message/message.zig");
    pub const connection = @import("connection/connection.zig");
    pub const connection_tls = @import("connection/connection_tls.zig");
};

pub const Role = files.role.Role;
pub const FieldBlock = files.field_block.FieldBlock;
pub const Connection = files.connection.Connection;
pub const Event = files.connection.Event;
pub const Limit = files.connection.Limit;
pub const Window = files.window.Window;

pub const frame = struct {
    pub const Header = files.frame.Header;
    pub const ParseError = files.frame.ParseError;
    pub const Payload = files.frame.Payload;
    pub const Priority = files.frame.Priority;
    pub const Setting = files.frame.Setting;
    pub const Settings = files.frame.Settings;
    pub const Verdict = files.frame.Verdict;
    pub const has_flag = files.frame.has_flag;
    pub const parse = files.frame.parse;
    pub const read_header = files.frame.read_header;
    pub const verdict = files.frame.verdict;
    pub const write_altsvc = files.frame.write_altsvc;
    pub const write_continuation = files.frame.write_continuation;
    pub const write_data = files.frame.write_data;
    pub const write_goaway = files.frame.write_goaway;
    pub const write_header = files.frame.write_header;
    pub const write_headers = files.frame.write_headers;
    pub const write_ping = files.frame.write_ping;
    pub const write_priority = files.frame.write_priority;
    pub const write_push_promise = files.frame.write_push_promise;
    pub const write_rst_stream = files.frame.write_rst_stream;
    pub const write_settings = files.frame.write_settings;
    pub const write_settings_ack = files.frame.write_settings_ack;
    pub const write_window_update = files.frame.write_window_update;
};

pub const stream = struct {
    pub const Closed = files.stream.Closed;
    pub const State = files.stream.State;
};

pub const connection = struct {
    pub const AltSvc = files.connection.AltSvc;
    pub const Data = files.connection.Data;
    pub const DataWritten = files.connection.DataWritten;
    pub const Event = files.connection.Event;
    pub const Request = files.connection.Request;
    pub const RequestError = files.connection.RequestError;
    pub const RequestIndexing = files.connection.RequestIndexing;
    pub const Request_ = files.connection.Request_;
    pub const Response = files.connection.Response;
    pub const SendError = files.connection.SendError;
    pub const StreamReset = files.connection.StreamReset;
};

pub const connection_tls = struct {
    pub const RecordError = files.connection_tls.RecordError;
    pub const attach = files.connection_tls.attach;
    pub const close_notify = files.connection_tls.close_notify;
    pub const decrypt = files.connection_tls.decrypt;
    pub const encrypt = files.connection_tls.encrypt;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",         "wire",      "http",       "hpack",
        "tls_provider", "constants", "Role",       "FieldBlock",
        "Connection",   "Event",     "Limit",      "Window",
        "frame",        "stream",    "connection", "connection_tls",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{ "core", "wire", "http", "hpack", "tls_provider" });
    _ = @import("stream/streams_slot.zig");
    _ = @import("stream/streams_window.zig");
    _ = @import("field_block/field_block_decode.zig");
    _ = @import("field_block/field_block_limit.zig");
    _ = @import("connection/connection_receive.zig");
    _ = @import("connection/connection_control.zig");
    _ = @import("connection/connection_stream.zig");
    _ = @import("connection/connection_data.zig");
    _ = @import("connection/connection_headers.zig");
    _ = @import("connection/connection_reply.zig");
    _ = @import("connection/connection_send.zig");
    _ = @import("connection/connection_request.zig");
    _ = @import("connection/connection_tls.zig");
    _ = @import("connection/connection_altsvc.zig");
}
