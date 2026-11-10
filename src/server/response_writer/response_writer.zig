//! `server.ResponseWriter`: the response to one request, which a route's function writes (decision
//! 127, design §8 step 25.2). The router places one in each request's entry, over the entry's
//! response memory, and passes a pointer to it. A program never makes one.
//!
//! A program sets `status`, adds headers with `header`, writes the body through the
//! `std.Io.Writer` that `body` returns, and calls `end`, or `trailers` to end with a trailer
//! section. `write_kept` sends bytes the program keeps, with no copy. The head goes to the engine
//! with the first bytes of the body that go, or with `end`.
//!
//! The bytes of `body` go into the entry's memory after the headers. The writer writes again into
//! memory whose bytes the engine released (decisions 103 and 127 as amended, design §8 step 46):
//! at once over h11 and h2, and over h3 once the peer acknowledged them. So `response_bytes`
//! bounds the bytes in flight, not the response. One `writeAll` of one slice goes into the memory
//! whole, or fails with `error.WriteFailed` and writes nothing, and a route writes it again in
//! `on_writable`.
//!
//! A `flush` makes a run of the bytes the writer holds. The writer has `response_pieces_max`
//! slots for the runs the engine has not released. With a run in each slot, a `flush` adds its
//! bytes to the newest run (the owner's ruling of 2026-11-09). A run the engine took whole takes
//! none, and a run of `write_kept` takes none. The bytes then stay in the writer until a slot is
//! free, and that `flush` fails only when the memory is full too. A `flush` that fails keeps its
//! bytes, and the writer sends them later.
//!
//! A middleware's `wrap_response` may wrap the body's writer (design §8 step 25.6). `body` then
//! returns the wrapper, and `end` and `trailers` only record that the response ends: the router
//! ends it once each wrapper wrote what it owes.
//!
//! When the engine takes less than the writer offers, the rest waits in the writer. The router
//! sends it on the request's `writable`, so a call that queues returns with no error.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const internal = @import("response_writer_internal.zig");

pub const ResponseWriter = struct {
    /// The status of the head, which a program sets before the head goes out. The engine refuses
    /// a code outside 100 to 599 and 101 (RFC 9110 §15).
    status: http.Status = .ok,

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
    lines: [constants.limits.response_headers_max]http.Field = undefined,
    header_count: u8 = 0,
    trailer_count: u8 = 0,
    /// The runs of body bytes, in order, and how far the engine took them.
    pieces: [constants.limits.response_pieces_max][]const u8 = undefined,
    piece_count: u8 = 0,
    piece_sent: u8 = 0,
    piece_offset: usize = 0,
    /// The runs before `piece_released` the engine released, whose memory the writer may write
    /// again: `released_len` of the `taken_len` octets the engine took (design §8 step 46).
    piece_released: u8 = 0,
    taken_len: u64 = 0,
    released_len: u64 = 0,
    /// The writer asked the engine for a `writable` once it releases bytes.
    release_waited: bool = false,
    /// A cut found a run in every slot, and none took its bytes: they stay in the writer, and the
    /// next `writable` cuts again (the owner's ruling of 2026-11-09).
    cut_owed: bool = false,
    /// The Content-Length value `end` adds to a head that carries the whole body.
    length_digits: [internal.length_digits_max]u8 = undefined,
    body_started: bool = false,
    head_out: bool = false,
    ended: bool = false,
    trailers_owed: bool = false,
    complete: bool = false,
    /// The writer of the last middleware's `wrap_response`, which `body` returns in place of
    /// `writer` (design §8 step 25.6), or null.
    wrapped: ?*std.Io.Writer = null,
    /// How the program ended a wrapped response, which the router completes once the wrappers
    /// finish.
    end_asked: internal.EndAsked = .none,

    /// What `header`, `write_kept`, `end` and `trailers` return.
    pub const Error = internal.Error;

    /// Adds one header to the head. Each name and value is copied into the entry's memory. A
    /// header after the body started is refused, as is one past `response_headers_max`.
    pub fn header(response: *ResponseWriter, name: []const u8, value: []const u8) Error!void {
        // RFC 9110 §6.3: header fields go before the content.
        if (response.body_started) return error.SectionOutOfOrder;
        // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
        if (response.header_count == constants.limits.response_headers_max) return error.SectionTooLarge;
        const copied = try internal.copy_line(response, response.header_len, name, value);
        response.lines[response.header_count] = copied.field;
        response.header_count += 1;
        response.header_len = copied.end;
    }

    /// The writer of the body, over the entry's memory after the headers. Its first call closes
    /// the headers. One `writeAll` of one slice that does not fit the memory the engine released,
    /// or a write after `end`, fails with `error.WriteFailed` and writes nothing.
    pub fn body(response: *ResponseWriter) *std.Io.Writer {
        if (!response.body_started) internal.start_body(response);
        return response.wrapped orelse &response.writer;
    }

    /// Sends `bytes` after the body written so far, with no copy. The program keeps them valid
    /// until the request's `finished`. The head goes out first, when it has not.
    pub fn write_kept(response: *ResponseWriter, bytes: []const u8) Error!void {
        // RFC 9110 §6.4.1: the content ended, and nothing follows it.
        if (response.ended or response.end_asked != .none) return error.SectionOutOfOrder;
        if (!response.body_started) internal.start_body(response);
        // Design §8 step 25.6: a wrapper sees each byte, so the bytes are copied through it.
        if (response.wrapped) |wrapper| return wrapper.writeAll(bytes) catch error.NoSpaceLeft;
        try internal.cut(response);
        try internal.add_piece(response, bytes);
        try internal.push_open(response);
    }

    /// Ends the response. A head that has not gone out carries the whole body, so `end` adds its
    /// Content-Length when the program set none.
    pub fn end(response: *ResponseWriter) Error!void {
        // RFC 9110 §6.4.1: the content ended, and nothing follows it.
        if (response.ended or response.end_asked != .none) return error.SectionOutOfOrder;
        if (!response.body_started) internal.start_body(response);
        // Design §8 step 25.6: the router ends a wrapped response once each wrapper finishes.
        if (response.wrapped != null) {
            response.end_asked = .end;
            return;
        }
        return internal.end_now(response);
    }

    /// Ends the response with a trailer section (RFC 9110 §6.5). Each name and value is copied into
    /// the entry's memory after the body.
    pub fn trailers(response: *ResponseWriter, headers: []const http.Field) Error!void {
        // RFC 9110 §6.4.1: the content ended, and nothing follows it.
        if (response.ended or response.end_asked != .none) return error.SectionOutOfOrder;
        if (!response.body_started) internal.start_body(response);
        // Design §8 step 25.6: the trailers wait at the end of the memory while the wrappers
        // finish, since the program's slices may not live that long.
        if (response.wrapped != null) {
            try internal.copy_trailers_last(response, headers);
            response.end_asked = .trailers;
            return;
        }
        try internal.cut(response);
        try internal.copy_trailers(response, headers);
        return internal.trailers_now(response);
    }

    /// Whether the head went to the engine. Before it has, the program may still choose the
    /// status, which an error function does.
    pub fn head_sent(response: *const ResponseWriter) bool {
        return response.head_out;
    }
};

test "decision 127: ResponseWriter exports header, body, write_kept, end, trailers and head_sent" {
    // Decision 158 ruling 6 adds `Error`, which the calls return.
    try @import("core").public_names.expect(ResponseWriter, &.{
        "Error", "header", "body", "write_kept", "end", "trailers", "head_sent",
    });
}

test {
    _ = @import("response_writer_test.zig");
    _ = @import("response_writer_ring_test.zig");
}
