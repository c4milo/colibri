//! The module graph of docs/design.md §3: one module per concern, wired in dependency order. A
//! module can `@import` only what this file gives it, so the direction is enforced by the build
//! and not by review (CLAUDE.md, Layout).
//!
//! The one edge that must never exist is `quic` importing anything of HTTP. RFC 9000 defines a
//! transport that carries streams and never interprets their payloads; decision 5 keeps it that
//! way: `quic` receives `core`, `wire`, `crypto` and `tls`, and nothing else. `src/quic/` naming
//! `http`, `h2`, `h3`, `hpack` or `qpack` does not compile, which is invariant 26 and the check of
//! design §8 step 0.
//!
//! `sim` receives `core`, `tls` and `crypto` because it implements the two caller-supplied
//! vtables (decisions 8 and 9) and passes its own null providers to the protocol modules in place
//! of a real caller's. It receives no protocol module, which stops the harness from
//! knowing anything a caller would not.
//!
//! `testing` is design §9's endpoints: it receives the protocol modules it serves and nothing
//! receives it back, so the library it drives cannot use the socket it opens.
//!
//! `sim_run` is the driver: the checks and the `zig build sim` command line, rooted at
//! `src/sim/run.zig`. It receives `sim` and the modules its checks drive, `wire` for design §8
//! step 2 and `h2` for step 4, and `sim` never receives it back, so the direction stays acyclic.
const std = @import("std");

/// Each module's root is the file named after its directory (`src/core/core.zig`), which lists
/// the module's API as `pub const` declarations and imports every file that has tests. A file
/// split off a root is imported through that root and is not named here.
pub const Modules = struct {
    /// Named limits, assertions, the bounded reader and writer, and the slot pool of decision 14.
    /// Imports nothing.
    core: *std.Build.Module,
    /// Every integer and string encoding both protocol families read: the QUIC variable-length
    /// integer (RFC 9000 §16) for framing, and the prefixed integer, string literal and Huffman
    /// code of RFC 7541 §5.1, §5.2 and Appendix B for field compression (decision 11).
    wire: *std.Build.Module,
    /// The version-independent HTTP semantics core of RFC 9110 (decision 15).
    http: *std.Build.Module,
    /// The TLS provider vtable, both modes. No production implementation (decision 8).
    tls: *std.Build.Module,
    /// The packet-protection vtable. No production implementation (decision 9).
    crypto: *std.Build.Module,
    hpack: *std.Build.Module,
    qpack: *std.Build.Module,
    /// The transport of RFC 8999, 9000, 9001 and 9002. Knows nothing about HTTP.
    quic: *std.Build.Module,
    h2: *std.Build.Module,
    h3: *std.Build.Module,
    /// The deterministic harness: clock, byte pipe, datagram network, and null providers for both
    /// vtables. Design §10.
    sim: *std.Build.Module,
    /// The driver: the checks of design §8 over `sim`, and the `zig build sim` command line.
    sim_run: *std.Build.Module,
    /// The byte-exact corpus and its manifest.
    golden: *std.Build.Module,
    /// The test-only entry points of design §9, excluded from the packaged library and the only
    /// place permitted to touch a socket. Receives the protocol modules it serves.
    testing: *std.Build.Module,
};

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Modules {
    const core = create(b, "src/core/core.zig", target, optimize);

    const wire = create(b, "src/wire/wire.zig", target, optimize);
    wire.addImport("core", core);

    const http = create(b, "src/http/http.zig", target, optimize);
    http.addImport("core", core);

    const tls = create(b, "src/tls/tls.zig", target, optimize);
    tls.addImport("core", core);

    const crypto = create(b, "src/crypto/crypto.zig", target, optimize);
    crypto.addImport("core", core);

    const hpack = create(b, "src/hpack/hpack.zig", target, optimize);
    hpack.addImport("core", core);
    hpack.addImport("wire", wire);
    hpack.addImport("http", http);

    const qpack = create(b, "src/qpack/qpack.zig", target, optimize);
    qpack.addImport("core", core);
    qpack.addImport("wire", wire);
    qpack.addImport("http", http);

    // Decision 5: no HTTP module is given to `quic`, at any point, for any reason.
    const quic = create(b, "src/quic/quic.zig", target, optimize);
    quic.addImport("core", core);
    quic.addImport("wire", wire);
    quic.addImport("crypto", crypto);
    quic.addImport("tls", tls);

    const h2 = create(b, "src/h2/h2.zig", target, optimize);
    h2.addImport("core", core);
    h2.addImport("wire", wire);
    h2.addImport("http", http);
    h2.addImport("hpack", hpack);
    h2.addImport("tls", tls);

    const h3 = create(b, "src/h3/h3.zig", target, optimize);
    h3.addImport("core", core);
    h3.addImport("wire", wire);
    h3.addImport("http", http);
    h3.addImport("qpack", qpack);
    h3.addImport("quic", quic);

    const sim = create(b, "src/sim/sim.zig", target, optimize);
    sim.addImport("core", core);
    sim.addImport("tls", tls);
    sim.addImport("crypto", crypto);

    const sim_run = create(b, "src/sim/run.zig", target, optimize);
    sim_run.addImport("core", core);
    sim_run.addImport("wire", wire);
    sim_run.addImport("sim", sim);
    sim_run.addImport("h2", h2);

    const golden = create(b, "src/golden/golden.zig", target, optimize);
    golden.addImport("core", core);
    golden.addImport("wire", wire);
    golden.addImport("hpack", hpack);

    // Design §9: the test-only endpoints. Nothing imports this module, so the library never
    // uses the socket it opens, and decision 10 links chapulin here alone when step 5 lands.
    const testing = create(b, "src/testing/testing.zig", target, optimize);
    testing.addImport("core", core);
    testing.addImport("h2", h2);

    return .{
        .core = core,
        .wire = wire,
        .http = http,
        .tls = tls,
        .crypto = crypto,
        .hpack = hpack,
        .qpack = qpack,
        .quic = quic,
        .h2 = h2,
        .h3 = h3,
        .sim = sim,
        .sim_run = sim_run,
        .golden = golden,
        .testing = testing,
    };
}

fn create(
    b: *std.Build,
    root_source_file: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = target,
        .optimize = optimize,
    });
}
