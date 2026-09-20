//! The chapulin calls `src/testing/` links, and nothing else in the tree may
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS half.
//!
//! colibri vendors none of chapulin's C. `-Dchapulin=<checkout>` names a checkout the caller has
//! already built, the headers are read from it in place, and the object is linked as it stands.
//! Without the option `available` is false, every declaration below compiles to nothing, and the
//! TLS endpoints are absent — so a fresh clone with no chapulin still builds and still runs every
//! other check.
//!
//! **One role per object, which is why there are two.** A chapulin build carries one role and both
//! roles export `ch_read`, `ch_write` and `ch_close`, so one binary cannot hold both. The server
//! endpoint links the `ROLE=server` object and the client endpoint the client one, and the calls
//! each role alone exports are declared apart below.
//!
//! Nothing here is a protocol rule. What these calls do with a record is RFC 8446's and
//! chapulin's; colibri's side of the boundary is `tls.Provider`, which the adapter fills.
const std = @import("std");
const build_options = @import("build_options");

/// Whether `-Dchapulin=<checkout>` was given. Every entry point below is guarded on it, so a build
/// without a checkout never references a symbol the linker would have to find.
pub const available: bool = build_options.chapulin;

/// chapulin's session, whose size and layout are its own. colibri never reads a field: the struct
/// is storage the caller places, which is what decision 35 requires of every buffer here too.
/// `ch_tls_len` is taken from the header at build time rather than written down, so a chapulin
/// that grows its session does not silently overflow this.
pub const Session = if (available) @import("chapulin_session.zig").Session else struct {};

/// RFC 8446 §6: what a chapulin call answers. 0 is success and every negative value is one of
/// chapulin's `CH_E*` codes, which the adapter maps to `tls.Provider`'s errors.
pub const ok: c_int = 0;

/// The seed a `RAND=drbg` build takes, which `drbg.h` fixes at 32 octets.
pub const seed_len: usize = 32;

/// Seeds chapulin's DRBG, which a `RAND=drbg` build requires before any handshake. The endpoints
/// draw the seed from the operating system, which `src/testing/` may do and the library may not
/// (invariant 5 is scoped to the protocol path).
pub extern fn ch_drbg_seed(seed: *const [seed_len]u8) void;

/// Reads plaintext from an established session (chapulin `tls.h`). Negative is an error.
pub extern fn ch_read(session: *anyopaque, out: [*]u8, len: usize) c_int;

/// Writes plaintext to an established session. Negative is an error.
pub extern fn ch_write(session: *anyopaque, plaintext: [*]const u8, len: usize) c_int;

/// Ends a session, sending `close_notify` (RFC 8446 §6.1).
pub extern fn ch_close(session: *anyopaque) void;

/// The client role's handshake, which a `ROLE=client` object alone exports.
pub const client = struct {
    pub extern fn ch_connect(session: *anyopaque, config: *const anyopaque) c_int;
};

/// The server role's, which a `ROLE=server` object alone exports.
pub const server = struct {
    pub extern fn ch_srv_accept(session: *anyopaque, config: *const anyopaque) c_int;
    /// Refuses a configuration before a byte is sent, which is where a server without a
    /// provisioned identity fails.
    pub extern fn ch_srv_check(config: *const anyopaque) c_int;
};

/// chapulin routes every failed assertion here, and `ch_assert.h` leaves the handler to the
/// image: its failure domain is the caller's. colibri's panics, naming the condition and the
/// chapulin source line. A failed chapulin assertion is a defect in chapulin or in how colibri
/// configured it, and either way the endpoint must not carry on with a session built on it.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    // Only a build that links chapulin owes it a handler, and only that build defines one, so a
    // build without the checkout carries no symbol the linker would have to place.
    if (available) @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

const testing = std.testing;

test "the checkout the build was given is the one that is linked" {
    // With no checkout nothing above is referenced, so there is nothing to prove and nothing to
    // link. The endpoints compile to nothing and every other check still runs.
    if (!available) return error.SkipZigTest;
    // With one, calling into it proves the object linked and that colibri's declaration and
    // chapulin's definition agree well enough to run. A seed of zeros is a seed.
    const seed: [seed_len]u8 = @splat(0);
    ch_drbg_seed(&seed);
}
