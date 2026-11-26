//! What the tests of `colibri` share: a source each test passes as the program's, which fills its
//! octets from a counter so every run draws the same octets, and the context a test makes of it,
//! with no CPU feature (decision 175). A real program draws from a cryptographic source.
//! Test-only.
const stdx = @import("stdx");

/// The type of a context's random source, `stdx.crypto.Context.random`.
const RandomSource = @FieldType(stdx.crypto.Context, "random");

pub const Counter = struct {
    next: u8 = 0,

    pub fn random(self: *Counter) RandomSource {
        return RandomSource.init(self, fill);
    }

    /// The context of a program on a CPU with no feature, which draws from this counter.
    pub fn crypto(self: *Counter) stdx.crypto.Context {
        return stdx.crypto.init(.none(), self.random());
    }

    fn fill(self: *Counter, buffer: []u8) void {
        for (buffer) |*octet| {
            octet.* = self.next;
            self.next +%= 1;
        }
    }
};

/// The counter of the contexts whose draws no test reads.
threadlocal var unread: Counter align(@alignOf(Counter)) = .{};

/// A context of no CPU feature, over a counter whose draws no test reads.
pub fn crypto() stdx.crypto.Context {
    return unread.crypto();
}
