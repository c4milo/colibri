//! The chapulin calls `src/testing/` links, and nothing else in the tree may
//! ([decision 10](../../../docs/decisions.md)). Part of design §8 step 5's TLS half.
//!
//! chapulin comes from the package `build.zig.zon` pins, compiled `TRANSPORT=tcp-nonblocking
//! ROLE=both TRUST=webpki EXPORTER=on RAND=extern` (design §8 step 16a). The package translates its
//! public headers under the defines its object compiled with, and that translation is the module
//! `chapulin`, so every declaration here is chapulin's own, read under the object's own defines.
//!
//! **One object serves both roles.** `ROLE=both` compiles the client's driver and the server's into
//! one object, so the h2 server and client link the same build.
//!
//! **`TRUST=webpki`**, because chapulin compiles ALPN in only for it among the client trust modes,
//! which the comptime block below checks. **`TRANSPORT=tcp-nonblocking`** (decisions 46 and 82):
//! the handshake runs from octets the endpoint read, and a record that carries no data leaves the
//! session live (https://github.com/c4milo/colibri/issues/62). Nothing else here is a protocol
//! rule: what a record means is RFC 9846's and chapulin's, and colibri's side of the boundary is
//! `tls.Provider`.
//!
//! The image defines chapulin's two hooks: `ch_assert_fail` below, and `ch_rand_bytes` in
//! `entropy.zig`.
const std = @import("std");
const entropy = @import("../entropy.zig");

/// chapulin's own declarations, translated from its headers by its package rather than copied. A
/// struct chapulin grows grows here with it, and a signature it changes stops this build rather
/// than passing the wrong octets.
pub const c = @import("chapulin");

pub const BuildError = error{
    /// The linked object was built with other defines than the ones its headers were translated
    /// under, so the two disagree about struct sizes and bounds.
    ObjectMismatch,
};

/// Refuses an object built with other defines than its headers were translated under, which an
/// endpoint calls once before any other chapulin call (chapulin's `build.h`). The package builds
/// both from one list, so this holds by construction; the call is what proves it for the object
/// that was actually linked.
pub fn check_build() BuildError!void {
    // chapulin names the record after the object's transport, and translate-c cannot follow
    // `build.h`'s `ch_build` alias to it.
    if (c.ch_build_matches(&c.ch_build_info_tcp_nonblocking) != 0) return;
    std.debug.print("chapulin: the linked object was built with other defines than its headers " ++
        "were translated under.\n", .{});
    return BuildError.ObjectMismatch;
}

comptime {
    check_alpn();
}

/// RFC 9113 §3.1 selects h2 over TLS by ALPN, and colibri's `attach_tls` refuses a handshake that
/// selected anything but "h2". chapulin compiles its ALPN fields out unless the build defines
/// `CH_TRUST_WEBPKI`, `CH_TRANSPORT_QUIC_NONBLOCKING` or `CH_ROLE_SERVER` (its `cfg.h`), so a
/// `TRUST=raw` or `TRUST=ca` client offers no ALPN extension at all and can never negotiate h2.
/// Saying so here costs one compile error; leaving it unsaid costs a handshake that completes and
/// then refuses every connection for a reason nothing names.
fn check_alpn() void {
    if (!@hasField(c.ch_cfg, "alpn_protocols")) {
        @compileError("this chapulin was built without ALPN, so it cannot negotiate h2 " ++
            "(RFC 9113 §3.1). build/modules.zig must build it TRUST=webpki; chapulin's cfg.h " ++
            "compiles the alpn_protocols field out for TRUST=raw and TRUST=ca.");
    }
}

/// chapulin routes every failed assertion here, and `ch_assert.h` leaves the handler to the
/// image: its failure domain is the caller's. colibri's panics, naming the condition and the
/// chapulin source line. A failed chapulin assertion is a defect in chapulin or in how colibri
/// configured it, and either way the endpoint must not carry on with a session built on it.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
    // `ch_rand_bytes`, the other hook, is exported where `entropy.zig` is analysed.
    _ = entropy;
}

const testing = std.testing;

test "the linked object was built with the defines its headers were translated under" {
    try check_build();
    // Both roles drive chapulin's record-mode handshake, and the object says so.
    try testing.expect(c.ch_build_info_tcp_nonblocking.axes & c.CH_BUILD_TRANSPORT_TCP_NONBLOCKING != 0);
}

test "the chapulin that is linked can negotiate h2" {
    // `check_alpn` has already refused a build without the field. This states the same
    // requirement where a reader of the tests will meet it, and pins the two names colibri
    // writes into the config.
    try testing.expect(@hasField(c.ch_cfg, "alpn_protocols"));
    try testing.expect(@hasField(c.ch_cfg, "alpn_count"));
    // RFC 7301 §3.1: "h2" is two octets, and chapulin's cap must admit it.
    try testing.expect(c.CH_ALPN_NAME_MAX >= "h2".len);
    try testing.expect(c.CH_ALPN_MAX >= 1);
}
