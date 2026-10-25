//! `server.ResponseWriter`: the response to one request, which a route's function writes (decision
//! 127, design §8 step 25.2). The router places one in each request's entry, over the entry's
//! response memory, and passes a pointer to it. A program never makes one.
//!
//! A program sets `status`, adds headers with `header`, writes the body through the
//! `std.Io.Writer` that `body` returns, and calls `end`, or `trailers` to end with a trailer
//! section. `write_kept` sends bytes the program keeps, with no copy. The head goes to the endpoint
//! with the first bytes of the body that go, or with `end`.
//!
//! Over h3 the endpoint copies no body: the bytes stay the caller's until the request's `finished`
//! (decision 103). So the bytes of `body` stay in the entry's memory, and the memory serves one
//! response of `response_bytes` at most. A larger body goes through `write_kept`.
//!
//! When the endpoint takes less than the writer offers, the rest waits in the writer. The router
//! sends it on the request's `writable`, so a call that queues returns with no error.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const internal = @import("response_writer_internal.zig");

pub const ResponseWriter = struct {
    /// The status of the head, which a program sets before the head goes out. The endpoint refuses
    /// a code outside 100 to 599 and 101 (RFC 9110 §15).
    status: u16 = 200,

    // Each field below is colibri's. A program reads none of them.
    sink: internal.Sink,
    id: event.RequestId,
    /// The entry's response memory: header and trailer names and values, then the body.
    memory: []u8,
    /// The writer `body` returns. Its buffer is the part of `memory` that no run holds yet.
    writer: std.Io.Writer,
    /// Octets at the front of `memory` that header names and values hold.
    header_len: usize = 0,
    /// The headers, then the trailers.
    lines: [constants.response_headers_max]http.Field = undefined,
    header_count: u8 = 0,
    trailer_count: u8 = 0,
    /// The runs of body bytes, in order, and how far the endpoint took them.
    pieces: [constants.response_pieces_max][]const u8 = undefined,
    piece_count: u8 = 0,
    piece_sent: u8 = 0,
    piece_offset: usize = 0,
    /// The Content-Length value `end` adds to a head that carries the whole body.
    length_digits: [internal.length_digits_max]u8 = undefined,
    body_started: bool = false,
    head_out: bool = false,
    ended: bool = false,
    trailers_owed: bool = false,
    complete: bool = false,

    /// Adds one header to the head. Each name and value is copied into the entry's memory. A
    /// header after the body started is refused, as is one past `response_headers_max`.
    pub fn header(response: *ResponseWriter, name: []const u8, value: []const u8) internal.Error!void {
        // RFC 9110 §6.3: header fields go before the content.
        if (response.body_started) return error.SectionOutOfOrder;
        // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
        if (response.header_count == constants.response_headers_max) return error.SectionTooLarge;
        const copied = try internal.copy_line(response, response.header_len, name, value);
        response.lines[response.header_count] = copied.field;
        response.header_count += 1;
        response.header_len = copied.end;
    }

    /// The writer of the body, over the entry's memory after the headers. Its first call closes
    /// the headers. A write past the memory, or after `end`, fails with `error.WriteFailed`.
    pub fn body(response: *ResponseWriter) *std.Io.Writer {
        if (!response.body_started) internal.start_body(response);
        return &response.writer;
    }

    /// Sends `bytes` after the body written so far, with no copy. The program keeps them valid
    /// until the request's `finished`. The head goes out first, when it has not.
    pub fn write_kept(response: *ResponseWriter, bytes: []const u8) internal.Error!void {
        // RFC 9110 §6.4.1: the content ended, and nothing follows it.
        if (response.ended) return error.SectionOutOfOrder;
        if (!response.body_started) internal.start_body(response);
        try internal.cut(response);
        try internal.add_piece(response, bytes);
        try internal.push(response);
    }

    /// Ends the response. A head that has not gone out carries the whole body, so `end` adds its
    /// Content-Length when the program set none.
    pub fn end(response: *ResponseWriter) internal.Error!void {
        // RFC 9110 §6.4.1: the content ended, and nothing follows it.
        if (response.ended) return error.SectionOutOfOrder;
        if (!response.body_started) internal.start_body(response);
        try internal.cut(response);
        internal.close_body(response);
        if (!response.head_out) internal.add_content_length(response);
        try internal.push(response);
    }

    /// Ends the response with a trailer section (RFC 9110 §6.5). Each name and value is copied into
    /// the entry's memory after the body.
    pub fn trailers(response: *ResponseWriter, headers: []const http.Field) internal.Error!void {
        // RFC 9110 §6.4.1: the content ended, and nothing follows it.
        if (response.ended) return error.SectionOutOfOrder;
        if (!response.body_started) internal.start_body(response);
        try internal.cut(response);
        try internal.copy_trailers(response, headers);
        internal.close_body(response);
        response.trailers_owed = true;
        try internal.push(response);
    }

    /// Whether the head went to the endpoint. Before it has, the program may still choose the
    /// status, which an error function does.
    pub fn head_sent(response: *const ResponseWriter) bool {
        return response.head_out;
    }
};

test "decision 127: ResponseWriter exports header, body, write_kept, end, trailers and head_sent" {
    try @import("core").public_names.expect(ResponseWriter, &.{ "header", "body", "write_kept", "end", "trailers", "head_sent" });
}

test {
    _ = @import("response_writer_test.zig");
}
