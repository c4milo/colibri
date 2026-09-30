//! The deadlines a server connection keeps over TCP (decision 110, design §8 step 20b), and the
//! limits behind them. colibri reads no clock (design §4.2): each deadline starts at an instant the
//! caller passed, and the caller wakes at `Connection.deadline_ns` and calls `on_instant` then.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// Which deadline ended a connection.
pub const Deadline = enum {
    /// No whole request head arrived in time after the connection opened, the TLS handshake
    /// included.
    first_request,
    /// No request began in time after the last response ended.
    idle,
    /// A request head began and did not end in time.
    head,
};

/// Each deadline's limit in nanoseconds, or null to turn it off.
pub const Deadlines = struct {
    first_request_ns: ?u64 = constants.first_request_timeout_ns,
    idle_ns: ?u64 = constants.idle_timeout_ns,
    head_ns: ?u64 = constants.head_timeout_ns,

    /// Refuses a limit of 0, which null says better, and one past `timeout_ns_max`.
    pub fn validate(deadlines: Deadlines) error{DeadlineInvalid}!void {
        inline for (std.meta.fields(Deadlines)) |field| {
            if (@field(deadlines, field.name)) |limit| {
                // RFC 9112 §9.5 leaves a server's timeout to the server, and decision 110 bounds it:
                // null turns a deadline off, and a limit stays within a day.
                if (limit == 0 or limit > constants.timeout_ns_max) return error.DeadlineInvalid;
            }
        }
    }
};

const testing = std.testing;

test "decision 110: the defaults are valid, 0 and a limit past a day are refused, and null is off" {
    try (Deadlines{}).validate();
    try (Deadlines{ .first_request_ns = null, .idle_ns = null, .head_ns = null }).validate();
    try (Deadlines{ .idle_ns = constants.timeout_ns_max }).validate();
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .head_ns = 0 }).validate());
    try testing.expectError(error.DeadlineInvalid, (Deadlines{ .first_request_ns = constants.timeout_ns_max + 1 }).validate());
}
