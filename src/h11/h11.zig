//! h11: HTTP/1.1 (RFC 9112), client and server, as decisions 88 and 91 rule it. Design §8 step 15
//! builds it in four parts: the messages (15a), the connection (15b), the `gzip` and `deflate`
//! codings (15c), and TLS with the endpoints (15d).
//!
//! h11 imports `core`, `http`, `tls_provider`, and stdx's `codec`, `gzip` and `zlib`, whose
//! decoders read the `gzip` and `deflate` transfer codings (decisions 90 and 91).
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const http = @import("http");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const message = @import("message/message.zig");
    pub const chunked = @import("chunked/chunked.zig");
    pub const coding = @import("coding.zig");
    pub const connection = @import("connection/connection.zig");
    pub const connection_tls = @import("connection/connection_tls.zig");
};

pub const Connection = files.connection.Connection;

pub const message = struct {
    pub const Body = files.message.Body;
    pub const Coding = files.message.Coding;
    pub const Error = files.message.Error;
    pub const Length = files.message.Length;
    pub const RequestLine = files.message.RequestLine;
    pub const Role = files.message.Role;
    pub const Scanner = files.message.Scanner;
    pub const read_request = files.message.read_request;
    pub const read_response = files.message.read_response;
    pub const write_request_head = files.message.write_request_head;
    pub const write_response_head = files.message.write_response_head;
};

pub const chunked = struct {
    pub const Decoder = files.chunked.Decoder;
    pub const Error = files.chunked.Error;
    pub const write_chunk = files.chunked.write_chunk;
    pub const write_last_chunk = files.chunked.write_last_chunk;
};

pub const coding = struct {
    pub const Decoding = files.coding.Decoding;
    pub const DefaultPool = files.coding.DefaultPool;
    pub const Features = files.coding.Features;
    pub const Header = files.coding.Header;
    pub const Pool = files.coding.Pool;
    pub const Progress = files.coding.Progress;
    pub const Slot = files.coding.Slot;
    pub const Storage = files.coding.Storage;
    pub const begin = files.coding.begin;
    pub const decode = files.coding.decode;
    pub const finish = files.coding.finish;
    pub const release = files.coding.release;
    pub const reserve = files.coding.reserve;
    pub const start = files.coding.start;
};

pub const connection = struct {
    pub const Error = files.connection.Error;
    pub const Event = files.connection.Event;
    pub const Request = files.connection.Request;
    pub const SendError = files.connection.SendError;
};

pub const connection_tls = struct {
    pub const RecordError = files.connection_tls.RecordError;
    pub const close_notify = files.connection_tls.close_notify;
    pub const decrypt = files.connection_tls.decrypt;
    pub const encrypt = files.connection_tls.encrypt;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",           "http",    "constants", "Connection",
        "message",        "chunked", "coding",    "connection",
        "connection_tls",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{ "core", "http" });
    _ = @import("message/message_scan.zig");
    _ = @import("message/message_start.zig");
    _ = @import("message/message_fields.zig");
    _ = @import("message/message_target.zig");
    _ = @import("message/message_body.zig");
    _ = @import("chunked/chunked_line.zig");
    _ = @import("message/message_write.zig");
    _ = @import("chunked/chunked_write.zig");
    _ = @import("message/message_fuzz.zig");
    _ = @import("connection/connection_server_test.zig");
    _ = @import("connection/connection_client_test.zig");
    _ = @import("connection/connection_tls_test.zig");
    _ = @import("connection/connection_coding_test.zig");
}
