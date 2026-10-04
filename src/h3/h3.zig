//! HTTP/3, RFC 9114.
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const qpack = @import("qpack");
pub const quic = @import("quic");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const frame = @import("frame.zig");
    pub const frame_write = @import("frame_write.zig");
    pub const stream = @import("stream.zig");
    pub const send_buffer = @import("send_buffer.zig");
    pub const connection = @import("connection/connection.zig");
    pub const message = @import("message/message.zig");
};

pub const Connection = files.connection.Connection;

pub const frame_write = struct {
    pub const write_header = files.frame_write.write_header;
};

pub const connection = struct {
    pub const Data = files.connection.Data;
    pub const Ended = files.connection.Ended;
    pub const Error = files.connection.Error;
    pub const Event = files.connection.Event;
    pub const HeadWait = files.connection.HeadWait;
    pub const Options = files.connection.Options;
    pub const Request = files.connection.Request;
    pub const Response = files.connection.Response;
    pub const SendError = files.connection.SendError;
};

pub const message = struct {
    pub const Request = files.message.Request;
    pub const Response = files.message.Response;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",       "wire",      "http",       "qpack",
        "quic",       "constants", "Connection", "frame_write",
        "connection", "message",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{ "core", "wire", "http", "qpack", "quic" });
    _ = @import("frame_fuzz.zig");
}
