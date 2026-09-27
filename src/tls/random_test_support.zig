//! The source the `tls` tests pass to each session's `start` (decision 94 as amended on 2026-09-27):
//! SplitMix64 from a seed, so every run of the tests draws the same key shares and nonces, and two
//! streams from one seed draw the same octets. Nothing here is secret.
const values = @import("values.zig");

/// The seed a test uses unless it varies it.
pub const seed: u64 = 0x636f_6c69_6272_6921;

/// The stream the tests share, for sessions whose draws no test compares.
pub var stream: Stream align(@alignOf(Stream)) = .{ .state = seed };

pub const Stream = struct {
    state: u64,

    /// The source a session draws from, which points at this stream: the stream outlives the
    /// session.
    pub fn random(self: *Stream) values.Random {
        return values.Random.init(self, fill);
    }

    fn fill(self: *Stream, buffer: []u8) void {
        for (buffer) |*octet| {
            self.state +%= increment;
            var mixed = self.state;
            mixed = (mixed ^ (mixed >> shift_first)) *% multiplier_first;
            mixed = (mixed ^ (mixed >> shift_second)) *% multiplier_second;
            octet.* = @truncate(mixed ^ (mixed >> shift_third));
        }
    }
};

/// SplitMix64's increment, multipliers and shifts.
const increment: u64 = 0x9e37_79b9_7f4a_7c15;
const multiplier_first: u64 = 0xbf58_476d_1ce4_e5b9;
const multiplier_second: u64 = 0x94d0_49bb_1331_11eb;
const shift_first: u6 = 30;
const shift_second: u6 = 27;
const shift_third: u6 = 31;
