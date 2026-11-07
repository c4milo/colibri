//! The version-independent HTTP semantics core of RFC 9110 (decision 15). It holds no verdict: an
//! h2 verdict and an h3 verdict differ for the same predicate, so this module returns a reason and
//! the protocol module names the error.
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const field = @import("field.zig");
    pub const field_section = @import("field_section.zig");
    pub const connection_specific = @import("connection_specific.zig");
    pub const method = @import("method.zig");
    pub const status = @import("status.zig");
    pub const content_length = @import("content_length.zig");
    pub const message_lines = @import("message_lines.zig");
    pub const message_request = @import("message_request.zig");
    pub const uri = @import("uri/uri.zig");
    pub const uri_percent = @import("uri/uri_percent.zig");
    pub const uri_query = @import("uri/uri_query.zig");
    pub const content_coding = @import("content_coding.zig");
};

pub const FieldSection = files.field_section.FieldSection;
pub const Field = files.field.Field;
/// A response's status code: one non-exhaustive enum, whose `_` holds each code it does not name
/// (decision 158 ruling 5).
pub const Status = files.status.Status;
/// The `name=value` pairs of a query, which the program places and reads with `get` (decision
/// 127).
pub const QueryParameters = files.uri_query.QueryParameters;

pub const field = struct {
    pub const is_tchar = files.field.is_tchar;
    pub const names_equal = files.field.names_equal;
    pub const validate_name = files.field.validate_name;
    pub const validate_value = files.field.validate_value;
};

pub const connection_specific = struct {
    pub const classify = files.connection_specific.classify;
    pub const te_is_trailers = files.connection_specific.te_is_trailers;
};

pub const method = struct {
    pub const Standard = files.method.Standard;
    pub const standard = files.method.standard;
    pub const validate = files.method.validate;
};

pub const content_length = struct {
    pub const from_section = files.content_length.from_section;
    pub const name = files.content_length.name;
};

pub const message_lines = struct {
    pub const Kind = files.message_lines.Kind;
    pub const Seen = files.message_lines.Seen;
    pub const definitions = files.message_lines.definitions;
    pub const is_pseudo_header = files.message_lines.is_pseudo_header;
    pub const walk = files.message_lines.walk;
};

pub const message_request = struct {
    pub const Kind = files.message_request.Kind;
    pub const check = files.message_request.check;
};

pub const uri = struct {
    pub const absolute_uri = files.uri.absolute_uri;
    pub const is_host = files.uri.is_host;
    pub const is_host_port = files.uri.is_host_port;
    pub const is_origin_form = files.uri.is_origin_form;
    pub const is_port = files.uri.is_port;
    pub const split_host_port = files.uri.split_host_port;
    pub const decoded_at = files.uri_percent.decoded_at;
    pub const encoded_len = files.uri_percent.encoded_len;
};

pub const content_coding = struct {
    pub const Acceptance = files.content_coding.Acceptance;
    pub const Coding = files.content_coding.Coding;
    pub const from_name = files.content_coding.from_name;
    pub const weight_max = files.content_coding.weight_max;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",   "constants",       "FieldSection",  "Field",
        "Status", "QueryParameters", "field",         "connection_specific",
        "method", "content_length",  "message_lines", "message_request",
        "uri",    "content_coding",
    });
}

test "decision 158: a status is one enum, and its calls are declarations of it" {
    try core.public_names.expect(Status, &.{
        "Error", "Class", "from_code", "from_digits", "write_digits", "class", "is_recognized",
    });
}

test "decision 158: a field section is emptied by init alone" {
    // Decision 158 ruling 6 adds `AppendError` and `Iterator`, which `append` and `iterator`
    // return.
    try core.public_names.expect(FieldSection, &.{
        "AppendError", "Iterator", "init", "len", "append", "extend_last", "get", "iterator", "find",
    });
}

test "decision 158: a request's kind is a named value, not a bool" {
    try core.public_names.expect(message_request, &.{ "Kind", "check" });
}

test "decision 122: the method namespace exports the type the router's table names" {
    try core.public_names.expect(method, &.{ "Standard", "standard", "validate" });
}

test "decision 158: a public path follows the concept, not the file" {
    try core.public_names.expect(uri, &.{
        "absolute_uri", "is_host",         "is_host_port", "is_origin_form",
        "is_port",      "split_host_port", "decoded_at",   "encoded_len",
    });
    try core.public_names.expect(content_coding, &.{ "Acceptance", "Coding", "from_name", "weight_max" });
    try core.public_names.expect(content_coding.Acceptance, &.{ "read", "weight_of", "choose" });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{"core"});
}
