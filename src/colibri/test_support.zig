//! What the tests of `colibri` share: a source each test passes as the program's, which fills its
//! octets from a counter so every run draws the same octets, and a CPU with no fast path. Test-only.
const tls = @import("tls");

pub const Counter = struct {
    next: u8 = 0,

    pub fn random(self: *Counter) tls.Random {
        return tls.Random.init(self, fill);
    }

    fn fill(self: *Counter, buffer: []u8) void {
        for (buffer) |*octet| {
            octet.* = self.next;
            self.next +%= 1;
        }
    }
};

pub fn cpu() tls.Cpu {
    return .{
        .probe = .{ .aes_clmul = .no, .dit = .not_known, .sha256 = .no, .sha512 = .no, .sha3 = .no, .ssse3 = .no, .sse4_1 = .no, .avx2 = .no, .vaes = .no },
        .timing = .not_stated,
    };
}
