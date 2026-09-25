//! The chapulin calls `src/testing/` links, and nothing else in the tree may
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS half.
//!
//! colibri vendors none of chapulin's C. `-Dchapulin-client=<checkout>` and
//! `-Dchapulin-server=<checkout>` name checkouts the caller has already built; the headers are
//! read from them in place, so every declaration here is chapulin's own and none is copied.
//! Without the options `available` is false, everything below compiles to nothing, and the TLS
//! endpoints are absent — a clone with no chapulin still builds and still runs every other check.
//!
//! **One role per object, which is why there are two options.** A chapulin build carries one role
//! and both roles export `ch_read`, `ch_write` and `ch_close`, so one binary cannot hold both.
//!
//! **The client must be built `TRUST=webpki`**, which the comptime block below enforces and
//! explains. **Both roles must be built `TRANSPORT=record`** (decisions 46 and 82): a
//! `TRANSPORT=tls` object exports none of the `ch_record_*` calls, so it does not link. Its
//! blocking handshake fails the session when a read runs dry, so the first record that carries no
//! data would end the connection (https://github.com/c4milo/colibri/issues/62). Nothing else here
//! is a protocol rule: what a record means is RFC 9846's and chapulin's, and colibri's side of the
//! boundary is `tls.Provider`.
const std = @import("std");
const build_options = @import("build_options");
const check_file = @import("check_file.zig");

/// Whether a checkout was given. Every declaration below is guarded on it, so a build without one
/// never references a symbol the linker would have to find.
pub const available: bool = build_options.chapulin;

/// chapulin's own declarations, read from its headers rather than copied into colibri. A struct
/// chapulin grows grows here with it, and a signature it changes stops this build rather than
/// passing the wrong octets.
pub const c = if (available) @cImport({
    // `tls.h` brings `cfg.h` with it, which is where the config and the ALPN fields live.
    @cInclude("tls.h");
    // The entropy a `RAND=drbg` build packages, which the endpoint seeds before any handshake.
    @cInclude("drbg.h");
    // The server's configuration and its boot-time self-test, `ch_srv_check`. It is included whatever
    // the role, because chapulin guards the whole header with `#ifdef CH_ROLE_SERVER`: in a
    // client build it expands to nothing and declares no symbol the linker would look for.
    @cInclude("srv.h");
    // The record-mode drivers: the client's in `rec.h`, the server's in `srv_rec.h`, which also
    // brings `rec.h`. chapulin guards both with `CH_TRANSPORT_RECORD`, and a server build compiles
    // the client's driver out.
    @cInclude("rec.h");
    @cInclude("srv_rec.h");
    // The record of the defines the linked object was built with, and the comparison with the
    // defines these headers were read under.
    @cInclude("build.h");
}) else struct {};

pub const BuildError = error{
    /// The linked object was built with other defines than the ones `build/modules.zig` reads
    /// the headers under, so the two disagree about struct sizes and bounds.
    ObjectMismatch,
};

/// Refuses an object built with other defines than `build/modules.zig` reads the headers under,
/// which an endpoint calls once before any other chapulin call (chapulin's `build.h`). The link
/// does not catch it when the two export the same calls: the program links and runs with the
/// wrong struct sizes.
pub fn check_build() BuildError!void {
    if (c.ch_build_matches(&c.ch_build) != 0) return;
    std.debug.print("chapulin: the linked object was built with other defines than colibri reads " ++
        "its headers under; CLAUDE.md's Commands section names the make lines.\n", .{});
    return BuildError.ObjectMismatch;
}

comptime {
    if (available) check_alpn();
}

/// RFC 9113 §3.1 selects h2 over TLS by ALPN, and colibri's `attach_tls` refuses a handshake that
/// selected anything but "h2". chapulin compiles its ALPN fields out unless the build defines
/// `CH_TRUST_WEBPKI`, `CH_TRANSPORT_QUIC` or `CH_ROLE_SERVER` (its `cfg.h`), so a `TRUST=raw` or
/// `TRUST=ca` client offers no ALPN extension at all and can never negotiate h2. Saying so here
/// costs one compile error; leaving it unsaid costs a handshake that completes and then refuses
/// every connection for a reason nothing names.
fn check_alpn() void {
    if (!@hasField(c.ch_cfg, "alpn_protocols")) {
        @compileError("this chapulin was built without ALPN, so it cannot negotiate h2 " ++
            "(RFC 9113 §3.1). Rebuild the checkout with TRUST=webpki; chapulin's cfg.h " ++
            "compiles the alpn_protocols field out for TRUST=raw and TRUST=ca.");
    }
}

/// The seed a `RAND=drbg` build takes, which chapulin's `drbg.h` fixes at 32 octets.
pub const seed_len: usize = 32;

/// Where an endpoint draws random octets from.
pub const entropy_path = "/dev/urandom";

pub const SeedError = error{
    /// The operating system gave fewer random octets than asked for.
    EntropyShort,
};

/// Seeds chapulin's generator, which a `RAND=drbg` build requires before any handshake, from the
/// operating system's entropy. An endpoint may read it; the library may not, and does not.
pub fn seed_from_entropy() !void {
    var seed: [seed_len]u8 = undefined;
    const drawn = try check_file.read_file(entropy_path, &seed);
    if (drawn.len != seed.len) return SeedError.EntropyShort;
    c.ch_drbg_seed(&seed);
}

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
    c.ch_drbg_seed(&seed);
}

test "the linked object was built with the defines colibri reads the headers under" {
    if (!available) return error.SkipZigTest;
    try check_build();
    // Both roles drive chapulin's record-mode handshake, and the object says so.
    try testing.expect(c.ch_build.axes & c.CH_BUILD_TRANSPORT_RECORD != 0);
}

test "the chapulin that is linked can negotiate h2" {
    if (!available) return error.SkipZigTest;
    // `check_alpn` has already refused a build without the field. This states the same
    // requirement where a reader of the tests will meet it, and pins the two names colibri
    // writes into the config.
    try testing.expect(@hasField(c.ch_cfg, "alpn_protocols"));
    try testing.expect(@hasField(c.ch_cfg, "alpn_count"));
    // RFC 7301 §3.1: "h2" is two octets, and chapulin's cap must admit it.
    try testing.expect(c.CH_ALPN_NAME_MAX >= "h2".len);
    try testing.expect(c.CH_ALPN_MAX >= 1);
}
