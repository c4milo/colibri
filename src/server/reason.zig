//! The reason phrase an h11 status line carries (RFC 9112 §4): the heading RFC 9110 §15 gives each
//! code it defines, and none for any other code. RFC 9112 §4 makes the phrase optional and has a
//! client ignore it, so a code with no phrase here sends the status line with an empty one.
const std = @import("std");
const http = @import("http");

const Code = http.status.Code;

/// The phrase for `status`, or an empty one for a code RFC 9110 §15 does not define.
pub fn of(status: u16) []const u8 {
    const code = std.enums.fromInt(Code, status) orelse return "";
    return switch (code) {
        // RFC 9110 §15.2.
        .@"continue" => "Continue",
        .switching_protocols => "Switching Protocols",
        // RFC 9110 §15.3.
        .ok => "OK",
        .created => "Created",
        .accepted => "Accepted",
        .non_authoritative_information => "Non-Authoritative Information",
        .no_content => "No Content",
        .reset_content => "Reset Content",
        .partial_content => "Partial Content",
        // RFC 9110 §15.4.
        .multiple_choices => "Multiple Choices",
        .moved_permanently => "Moved Permanently",
        .found => "Found",
        .see_other => "See Other",
        .not_modified => "Not Modified",
        .use_proxy => "Use Proxy",
        .temporary_redirect => "Temporary Redirect",
        .permanent_redirect => "Permanent Redirect",
        // RFC 9110 §15.5.
        .bad_request => "Bad Request",
        .unauthorized => "Unauthorized",
        .payment_required => "Payment Required",
        .forbidden => "Forbidden",
        .not_found => "Not Found",
        .method_not_allowed => "Method Not Allowed",
        .not_acceptable => "Not Acceptable",
        .proxy_authentication_required => "Proxy Authentication Required",
        .request_timeout => "Request Timeout",
        .conflict => "Conflict",
        .gone => "Gone",
        .length_required => "Length Required",
        .precondition_failed => "Precondition Failed",
        .content_too_large => "Content Too Large",
        .uri_too_long => "URI Too Long",
        .unsupported_media_type => "Unsupported Media Type",
        .range_not_satisfiable => "Range Not Satisfiable",
        .expectation_failed => "Expectation Failed",
        .misdirected_request => "Misdirected Request",
        .unprocessable_content => "Unprocessable Content",
        .upgrade_required => "Upgrade Required",
        // RFC 9110 §15.6.
        .internal_server_error => "Internal Server Error",
        .not_implemented => "Not Implemented",
        .bad_gateway => "Bad Gateway",
        .service_unavailable => "Service Unavailable",
        .gateway_timeout => "Gateway Timeout",
        .http_version_not_supported => "HTTP Version Not Supported",
    };
}

test "RFC 9110 §15: a defined code has its heading, and any other code none" {
    try std.testing.expectEqualStrings("OK", of(@intFromEnum(Code.ok)));
    try std.testing.expectEqualStrings("Content Too Large", of(@intFromEnum(Code.content_too_large)));
    try std.testing.expectEqualStrings("HTTP Version Not Supported", of(@intFromEnum(Code.http_version_not_supported)));
    // RFC 6585 §4's 429 is outside RFC 9110 §15, and RFC 9112 §4 lets its phrase be empty.
    const too_many_requests: u16 = 429;
    try std.testing.expectEqualStrings("", of(too_many_requests));
}
