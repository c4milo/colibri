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
    /// The driver of the QUIC checks, rooted at `src/sim/run_quic.zig`: `sim`, `quic` and no HTTP
    /// module, which is the build holding decision 5's boundary.
    sim_run_quic: *std.Build.Module,
    /// The byte-exact corpus and its manifest.
    golden: *std.Build.Module,
    /// The test-only entry points of design §9, excluded from the packaged library and the only
    /// place permitted to touch a socket. Receives the protocol modules it serves.
    testing: *std.Build.Module,
    /// The test-only h2 client of design §9, rooted at `src/testing/client.zig`: the same
    /// directory as `testing` and the same imports, with a `main` of its own.
    testing_client: *std.Build.Module,
    testing_tls: *std.Build.Module,
    testing_tls_server: *std.Build.Module,
};

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    chapulin: Chapulin,
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

    // Decision 5: the QUIC checks are driven with no HTTP module in the graph, so they are not
    // in `sim_run`, which imports `h2`.
    const sim_run_quic = create(b, "src/sim/run_quic.zig", target, optimize);
    sim_run_quic.addImport("core", core);
    sim_run_quic.addImport("sim", sim);
    sim_run_quic.addImport("quic", quic);

    const golden = create(b, "src/golden/golden.zig", target, optimize);
    golden.addImport("core", core);
    golden.addImport("wire", wire);
    golden.addImport("hpack", hpack);
    // Design §3: the corpus imports what it checks, and step 7 adds the packet readers.
    golden.addImport("quic", quic);

    // Design §9: the test-only endpoints. Nothing imports this module, so the library never
    // uses the socket it opens, and decision 10 links chapulin here alone when step 5 lands.
    const testing = create(b, "src/testing/testing.zig", target, optimize);
    testing.addImport("core", core);
    testing.addImport("h2", h2);
    // Step 5's TLS half: the endpoint fills `tls.Provider` from chapulin, so it needs the vtable
    // the library declares. The library still links no TLS stack; this module is not in it.
    testing.addImport("tls", tls);
    // The endpoints call `send` and `recv` with MSG_DONTWAIT, which is libc's. The library links
    // no C at all; this module is excluded from it, and decision 10 links chapulin here too.
    testing.link_libc = true;

    const testing_client = create(b, "src/testing/client.zig", target, optimize);
    testing_client.addImport("core", core);
    testing_client.addImport("h2", h2);
    testing_client.addImport("tls", tls);
    // `socket`, `connect`, `send` and `recv` are libc's, as they are for the server above.
    testing_client.link_libc = true;

    // Decision 10, and the reason the two objects are separate: a chapulin build carries one role,
    // and both roles export `ch_read`, `ch_write` and `ch_close`, so one binary cannot hold both.
    // The server endpoint links the `ROLE=server` object and the client endpoint the client one.
    link_chapulin(b, testing, chapulin.server, "chapulin-server.o", &.{ "CH_RAND_DRBG", "CH_ROLE_SERVER", "CH_EXPORTER" });
    link_chapulin(b, testing_client, chapulin.client, "chapulin-client.o", &.{ "CH_RAND_DRBG", "CH_TRUST_WEBPKI", "CH_EXPORTER" });

    // Design §8 step 5's check runs one handshake against a server that is not colibri's. It is
    // a third root because an executable has one `main`, and the other two are the h2 server's
    // and the h2 client's.
    const testing_tls = create(b, "src/testing/tls_handshake.zig", target, optimize);
    testing_tls.addImport("core", core);
    //  sizes its buffers against h2's frame limits, and every root
    // that reads it needs the module those limits come from.
    testing_tls.addImport("h2", h2);
    testing_tls.addImport("tls", tls);
    testing_tls.link_libc = true;
    link_chapulin(b, testing_tls, chapulin.client, "chapulin-client.o", &.{ "CH_RAND_DRBG", "CH_TRUST_WEBPKI", "CH_EXPORTER" });

    // The other half of step 5's check, and a fourth root for the same reason as the third: one
    // `main` per executable, and one role per chapulin object (decision 10). This one accepts.
    const testing_tls_server = create(b, "src/testing/tls_accept.zig", target, optimize);
    testing_tls_server.addImport("core", core);
    testing_tls_server.addImport("h2", h2);
    testing_tls_server.addImport("tls", tls);
    testing_tls_server.link_libc = true;
    link_chapulin(b, testing_tls_server, chapulin.server, "chapulin-server.o", &.{ "CH_RAND_DRBG", "CH_ROLE_SERVER", "CH_EXPORTER" });

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
        .sim_run_quic = sim_run_quic,
        .golden = golden,
        .testing = testing,
        .testing_client = testing_client,
        .testing_tls = testing_tls,
        .testing_tls_server = testing_tls_server,
    };
}

/// The UDP endpoint of design §9, rooted at `src/testing/udp.zig`: the one module that imports
/// rotor (decision 58). It is made apart from `add` because rotor is a lazy package that only
/// colibri's own build requests, after a dependent project's build has stopped. `h2` is there for
/// `src/testing/constants.zig`, which every module of `src/testing/` shares.
pub fn add_testing_udp(
    b: *std.Build,
    graph: Modules,
    rotor: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = create(b, "src/testing/udp.zig", target, optimize);
    module.addImport("h2", graph.h2);
    module.addImport("rotor", rotor);
    return module;
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

/// The chapulin checkout each role's endpoint links, named apart because the two roles are two
/// builds and either can be present without the other (decision 10).
pub const Chapulin = struct {
    client: ?[]const u8 = null,
    server: ?[]const u8 = null,
};

/// Links one chapulin object into a `src/testing/` module and tells its source whether it is
/// there (decision 10). colibri vendors none of chapulin's C: the checkout is the caller's, built
/// by the two `make` lines CLAUDE.md's Commands section names, and the headers are read from it in
/// place. With no checkout the module still compiles, with `chapulin` false, and the TLS
/// endpoints compile to nothing.
fn link_chapulin(
    b: *std.Build,
    module: *std.Build.Module,
    checkout: ?[]const u8,
    object: []const u8,
    defines: []const []const u8,
) void {
    const options = b.addOptions();
    options.addOption(bool, "chapulin", checkout != null);
    module.addImport("build_options", options.createModule());
    const path = checkout orelse return;
    module.addIncludePath(.{ .cwd_relative = path });
    module.addObjectFile(.{ .cwd_relative = b.pathJoin(&.{ path, "bin", object }) });
    // chapulin's headers are compiled by the same axes that compiled its object, and they refuse
    // to parse without them. colibri names the variant it needs rather than accepting any: the
    // entropy pattern, for the client the trust mode that compiles ALPN in at all (chapulin's
    // cfg.h), and the exporter, which adds a field to `ch_tls`. A checkout built another way
    // fails here, at `check_alpn`, or at the link for want of `ch_export`, which is the point —
    // CLAUDE.md's Commands section names the two `make` lines that match.
    for (defines) |define| module.addCMacro(define, "1");
}
