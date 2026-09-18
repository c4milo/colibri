//! Limits the test-only entry points of docs/design.md §9 own. Never written inline (CLAUDE.md
//! non-negotiable 4). Nothing here is packaged: `src/testing/` is excluded from the library.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");

/// Octets the server reads from a socket at once: one whole h2 frame, header included, so a
/// connection always makes progress on the largest frame colibri accepts (RFC 9113 §4.2).
pub const read_buffer_len: u32 = h2.constants.frame_header_len + h2.constants.frame_size_max;

/// Octets the server writes at once: a whole field block cut into frames, and the DATA frame of a
/// response body after it.
pub const write_buffer_len: u32 = h2.constants.send_block_len_max + read_buffer_len;

/// The instant one step of the server reports, in nanoseconds, and how far the next one is. The
/// server reads no clock: design §4.2 makes time a value the caller passes, and
/// `tools/lint/determinism.zig` holds `src/testing/` to it too. A fixed step keeps the rate limits
/// of RFC 9113 §10.5 advancing without a clock, and keeps one run byte-identical to the next.
pub const tick_ns: u64 = 1_000_000;

/// The port the server listens on when the caller names none.
pub const default_port: u16 = 8080;

/// The base a port is written in on the command line.
pub const port_radix: u8 = 10;

/// Most command-line arguments the server reads, which bounds the loop that reads them.
pub const arguments_max: u32 = 16;

/// Workers the server runs, one per core up to this many. Each has its own listening socket, its
/// own connections and its own thread, and reads no other worker's memory.
pub const workers_max: u32 = 8;

/// Connections one worker serves at once. SO_REUSEPORT ties a connection to the worker whose
/// listener the kernel picked, and that choice is a hash rather than a balance: several peers can
/// land on one worker while another sits idle. So a worker holds far more connections than an even
/// spread would need, and a peer that arrives when its worker is full waits in that listener's
/// backlog. A slot costs one session and its buffers, which the operating system maps only when a
/// connection touches it.
pub const connections_per_worker_max: u32 = 32;

/// Connections the kernel holds for a worker before it refuses one, which is listen's backlog.
pub const kernel_backlog: u31 = 64;

/// The width of a cache line on the hosts colibri is measured on: 64 octets on x86-64 and 128 on
/// Apple silicon. A worker is padded to a multiple of it, so no two workers write one line
/// (CLAUDE.md, Performance).
pub const cache_line_bytes: u32 = 128;

/// Most responses a session owes at once, one per request that ended and has not been answered
/// whole. It is one more than the streams the connection allows, so the queue never stops the
/// reading before the stream limit does: a peer that opens one stream too many is refused by
/// SETTINGS_MAX_CONCURRENT_STREAMS and its REFUSED_STREAM (RFC 9113 §5.1.2), not a server that
/// stopped reading.
pub const responses_owed_max: u32 = h2.constants.concurrent_streams_max + 1;

/// Most steps one session takes between two reads from the socket. A step that neither consumes
/// nor writes ends the loop, so this only bounds it: one step answers at most one request, and a
/// read holds at most one frame.
pub const steps_per_read_max: u32 = 64;

/// The body every response carries. Design §9 asks for a non-empty body, which is what h2load
/// measures and what h2spec's DATA cases need.
pub const response_body = "colibri\n";

/// The `content-type` of that body (RFC 9110 §8.3).
pub const response_content_type = "text/plain; charset=utf-8";

/// The status every request is answered with (RFC 9110 §15.3.1).
pub const response_status: u16 = 200;

/// Digits of the `content-length` the server writes, which is `response_body`'s length
/// (RFC 9110 §8.6).
pub const response_content_length = "8";

comptime {
    assert(read_buffer_len > h2.constants.frame_size_max);
    assert(write_buffer_len > read_buffer_len);
    assert(tick_ns > 0 and default_port > 0 and port_radix > 0);
    assert(arguments_max > 0 and steps_per_read_max > 0 and responses_owed_max > 0);
    assert(workers_max > 0 and connections_per_worker_max > 0 and kernel_backlog > 0);
    assert(cache_line_bytes > 0 and cache_line_bytes % @alignOf(u64) == 0);
    assert(response_body.len > 0);
    // The declared length is the body's, or a peer would wait for octets that never come.
    assert(response_content_length.len == 1 and response_content_length[0] - '0' == response_body.len);
}
