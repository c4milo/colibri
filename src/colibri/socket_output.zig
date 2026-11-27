//! The octets a client's TCP socket holds to send (design §8 step 79): what its connection wrote
//! and no send has taken. A server's socket holds none, since it sends what its engine lends
//! (decision 176). `client.ConnectionPool` has no such calls, so its `send_stream` copies into
//! this buffer. It writes after the octets a send in flight takes, and waits for the send once the
//! buffer is full (design §8 step 60).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub const Output = struct {
    octets: [constants.limits.socket_output_len]u8,
    /// Octets the connection wrote.
    len: usize,
    /// Octets a send took, which are always the first ones.
    sent: usize,

    /// Holds nothing.
    pub fn clear(output: *Output) void {
        output.len = 0;
        output.sent = 0;
    }

    /// Where the connection writes what the socket sends next.
    pub fn room(output: *Output) []u8 {
        return output.octets[output.len..];
    }

    pub fn wrote(output: *Output, written: usize) void {
        assert(written <= output.octets.len - output.len);
        output.len += written;
    }

    /// The octets no send has taken, which the socket's next send writes.
    pub fn unsent(output: *const Output) []const u8 {
        return output.octets[output.sent..output.len];
    }

    /// A send took `count` octets from the front of `unsent`. Once every octet is gone and no
    /// send is in flight, the buffer starts again at its front.
    pub fn took(output: *Output, count: usize) void {
        output.sent += count;
        assert(output.sent <= output.len);
        if (output.sent == output.len) output.clear();
    }
};

const testing = std.testing;

/// The output the test drives, outside any stack frame. Test-only.
threadlocal var test_output: Output align(@alignOf(Output)) = undefined;

test "design §8 step 79: a client's output appends after a send in flight, and empties once all went" {
    test_output.clear();
    @memcpy(test_output.room()[0..3], "abc");
    test_output.wrote(3);
    const first = test_output.unsent();
    try testing.expectEqualStrings("abc", first);
    // While the send writes "abc", the connection writes after it.
    @memcpy(test_output.room()[0..2], "de");
    test_output.wrote(2);
    test_output.took(2);
    try testing.expectEqualStrings("cde", test_output.unsent());
    try testing.expectEqual(@intFromPtr(first.ptr) + 2, @intFromPtr(test_output.unsent().ptr));
    test_output.took(3);
    try testing.expectEqual(0, test_output.unsent().len);
    try testing.expectEqual(constants.limits.socket_output_len, test_output.room().len);
}
