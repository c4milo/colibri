//! The module graph of docs/design.md §3: one module per concern, wired in dependency order. A
//! module can `@import` only what this file gives it, so the direction is enforced by the build
//! and not by review (CLAUDE.md, Layout).
//!
//! The one edge that must never exist is `quic` importing anything of HTTP. RFC 9000 defines a
//! transport that carries streams and never interprets their payloads; decision 5 keeps it that
//! way: `quic` receives `core`, `wire`, `crypto` and `tls_provider`, and nothing else. `src/quic/` naming
//! `http`, `h2`, `h3`, `h11`, `hpack` or `qpack` does not compile, which is invariant 26 and the
//! check of design §8 step 0.
//!
//! `sim` receives `core`, `tls_provider` and `crypto` because it implements the two caller-supplied
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
    tls_provider: *std.Build.Module,
    /// The packet-protection vtable. No production implementation (decision 9).
    crypto: *std.Build.Module,
    hpack: *std.Build.Module,
    qpack: *std.Build.Module,
    /// The transport of RFC 8999, 9000, 9001 and 9002. Knows nothing about HTTP.
    quic: *std.Build.Module,
    h2: *std.Build.Module,
    h3: *std.Build.Module,
    /// HTTP/1.1 (decisions 88 and 91, design §8 step 15).
    h11: *std.Build.Module,
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
    /// The QUIC loopback check of design §8 step 9e, rooted at `src/testing/quic_loopback.zig`.
    testing_quic: *std.Build.Module,
    /// Design §9's two QPACK command-line tools, rooted at `src/testing/qif.zig`.
    testing_qif: *std.Build.Module,
};

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Modules {
    const core = library(b, "core", target, optimize);

    const wire = library(b, "wire", target, optimize);
    wire.addImport("core", core);

    const http = library(b, "http", target, optimize);
    http.addImport("core", core);

    const tls_provider = library(b, "tls_provider", target, optimize);
    tls_provider.addImport("core", core);

    const crypto = library(b, "crypto", target, optimize);
    crypto.addImport("core", core);

    const hpack = library(b, "hpack", target, optimize);
    hpack.addImport("core", core);
    hpack.addImport("wire", wire);
    hpack.addImport("http", http);

    const qpack = library(b, "qpack", target, optimize);
    qpack.addImport("core", core);
    qpack.addImport("wire", wire);
    qpack.addImport("http", http);

    // Decision 5: no HTTP module is given to `quic`, at any point, for any reason.
    const quic = library(b, "quic", target, optimize);
    quic.addImport("core", core);
    quic.addImport("wire", wire);
    quic.addImport("crypto", crypto);
    quic.addImport("tls_provider", tls_provider);

    const h2 = library(b, "h2", target, optimize);
    h2.addImport("core", core);
    h2.addImport("wire", wire);
    h2.addImport("http", http);
    h2.addImport("hpack", hpack);
    h2.addImport("tls_provider", tls_provider);

    const h3 = library(b, "h3", target, optimize);
    h3.addImport("core", core);
    h3.addImport("wire", wire);
    h3.addImport("http", http);
    h3.addImport("qpack", qpack);
    h3.addImport("quic", quic);

    const h11 = library(b, "h11", target, optimize);
    h11.addImport("core", core);
    h11.addImport("http", http);
    // Decision 88: h11 attaches to a finished handshake and checks what ALPN selected.
    h11.addImport("tls_provider", tls_provider);

    const sim = create(b, "src/sim/sim.zig", target, optimize);
    sim.addImport("core", core);
    sim.addImport("tls_provider", tls_provider);
    sim.addImport("crypto", crypto);

    const sim_run = create(b, "src/sim/run.zig", target, optimize);
    sim_run.addImport("core", core);
    sim_run.addImport("wire", wire);
    sim_run.addImport("sim", sim);
    sim_run.addImport("h2", h2);
    // The QPACK check drives the encoder and decoder, ruled by the owner on 2026-09-24.
    sim_run.addImport("qpack", qpack);
    // The h3 check drives an h3 connection over the QUIC endpoint of step 9e, ruled by the owner
    // on 2026-09-24. `quic` comes with it: the endpoint names it, and `h3` imports it already.
    sim_run.addImport("h3", h3);
    sim_run.addImport("quic", quic);
    sim_run.addImport("h11", h11);

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
    golden.addImport("http", http);
    golden.addImport("h11", h11);
    // Design §3: the corpus imports what it checks, and step 7 adds the packet readers.
    golden.addImport("quic", quic);

    // Design §9: the test-only endpoints. Nothing imports this module, so the library never
    // uses the socket it opens, and decision 10 links chapulin here alone when step 5 lands.
    const testing = create(b, "src/testing/testing.zig", target, optimize);
    testing.addImport("core", core);
    testing.addImport("h2", h2);
    testing.addImport("h11", h11);
    // Step 5's TLS half: the endpoint fills `tls_provider.Provider` from chapulin, so it needs the vtable
    // the library declares. The library still links no TLS stack; this module is not in it.
    testing.addImport("tls_provider", tls_provider);
    // The endpoints call `send` and `recv` with MSG_DONTWAIT, which is libc's. The library links
    // no C at all; this module is excluded from it, and decision 10 links chapulin here too.
    testing.link_libc = true;

    const testing_client = create(b, "src/testing/client.zig", target, optimize);
    testing_client.addImport("core", core);
    testing_client.addImport("h2", h2);
    testing_client.addImport("h11", h11);
    testing_client.addImport("tls_provider", tls_provider);
    // `socket`, `connect`, `send` and `recv` are libc's, as they are for the server above.
    testing_client.link_libc = true;

    // Design §8 step 5's check runs one handshake against a server that is not colibri's. It is
    // a third root because an executable has one `main`, and the other two are the h2 server's
    // and the h2 client's.
    const testing_tls = create(b, "src/testing/tls_handshake.zig", target, optimize);
    testing_tls.addImport("core", core);
    //  sizes its buffers against h2's frame limits, and every root
    // that reads it needs the module those limits come from.
    testing_tls.addImport("h2", h2);
    testing_tls.addImport("tls_provider", tls_provider);
    testing_tls.link_libc = true;

    // The other half of step 5's check, and a fourth root for the same reason as the third: one
    // `main` per executable, and one role per chapulin object (decision 10). This one accepts.
    const testing_tls_server = create(b, "src/testing/tls_accept.zig", target, optimize);
    testing_tls_server.addImport("core", core);
    testing_tls_server.addImport("h2", h2);
    testing_tls_server.addImport("tls_provider", tls_provider);
    testing_tls_server.link_libc = true;

    // Design §9's QIF tools, a root of their own for their `main`. They serve `qpack`, and keep
    // their limits in `src/testing/qif/constants.zig` rather than the shared file, which imports
    // `h2`. Ruled by the owner on 2026-09-24. They read and write files through libc.
    const testing_qif = create(b, "src/testing/qif.zig", target, optimize);
    testing_qif.addImport("core", core);
    testing_qif.addImport("qpack", qpack);
    testing_qif.link_libc = true;

    // Step 9e's QUIC check fills `tls_provider.QuicProvider` and `crypto.Suite` from chapulin's QUIC mode.
    // A fifth root, because its object is another build: `TRANSPORT=quic-nonblocking` exports none
    // of the record calls the other four link, and `ROLE=both` puts both roles in one object.
    // `KEYLOG=on` imports `ch_keylog`, which the check defines, so a capture of a run can be
    // decrypted.
    const testing_quic = create(b, "src/testing/quic_loopback.zig", target, optimize);
    testing_quic.addImport("h2", h2);
    testing_quic.addImport("quic", quic);
    testing_quic.link_libc = true;

    return .{
        .core = core,
        .wire = wire,
        .http = http,
        .tls_provider = tls_provider,
        .crypto = crypto,
        .hpack = hpack,
        .qpack = qpack,
        .quic = quic,
        .h2 = h2,
        .h3 = h3,
        .h11 = h11,
        .sim = sim,
        .sim_run = sim_run,
        .sim_run_quic = sim_run_quic,
        .golden = golden,
        .testing = testing,
        .testing_client = testing_client,
        .testing_tls = testing_tls,
        .testing_tls_server = testing_tls_server,
        .testing_quic = testing_quic,
        .testing_qif = testing_qif,
    };
}

/// The UDP QUIC endpoint of design §9, rooted at `src/testing/quic_udp.zig`: the one module that
/// imports rotor (decision 58). It is made apart from `add` because rotor is a lazy package that
/// only colibri's own build requests, after a dependent project's build has stopped. `h2` is
/// there for `src/testing/constants.zig`, which every module of `src/testing/` shares; `quic` is
/// the module the endpoint serves, and chapulin's QUIC object fills its two vtables (decision 10).
pub fn add_testing_udp(
    b: *std.Build,
    graph: Modules,
    rotor: *std.Build.Module,
    chapulin_quic_object: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = create(b, "src/testing/quic_udp.zig", target, optimize);
    module.addImport("h2", graph.h2);
    module.addImport("quic", graph.quic);
    // The h3 server and client of design §9, ruled by the owner on 2026-09-24.
    module.addImport("h3", graph.h3);
    module.addImport("rotor", rotor);
    module.link_libc = true;
    link_chapulin(module, chapulin_quic_object);
    return module;
}

/// One module of the packaged library, exported by name so a project that depends on colibri
/// reaches it with `dependency.module("<name>")`, carrying the imports given here. Its root is
/// `src/<name>/<name>.zig`. The simulator, the corpus and the test-only endpoints stay
/// unexported: they are not the library.
fn library(
    b: *std.Build,
    comptime name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    return b.addModule(name, .{
        .root_source_file = b.path("src/" ++ name ++ "/" ++ name ++ ".zig"),
        .target = target,
        .optimize = optimize,
    });
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

/// The trust modes chapulin's QUIC object is built with, spelled as its build spells them: `webpki`
/// for every check, and `raw-ecdsa` for the endpoint the QUIC Interop Runner runs, whose
/// certificates carry no extended key usage and so fail the Web PKI profile.
pub const QuicTrust = enum { webpki, @"raw-ecdsa" };

/// The two chapulin objects `src/testing/` links, each compiled from the pinned package with
/// `RAND=extern` (design §8 step 16a, decision 94). The package also translates the public headers
/// under the defines its object compiled with, so the declarations colibri reads always match the
/// object it links.
pub const Chapulin = struct {
    /// `TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki EXPORTER=on`: the h11 and h2 endpoints,
    /// client and server in one object. The handshake runs from octets the endpoint read, so it
    /// runs inside the endpoint's loop (decisions 46 and 82), and `TRUST=webpki` is the one client
    /// trust mode that compiles ALPN in, without which no client negotiates h2 (RFC 9113 §3.1).
    tcp: *std.Build.Dependency,
    /// `TRANSPORT=quic-nonblocking ROLE=both SUITE=aesgcm AES=hw KEYLOG=on`, with the builder's
    /// statement that the part's AES instructions run in constant time (decision 85). `KEYLOG=on`
    /// hands the checks each traffic secret, so a capture can be decrypted.
    quic: *std.Build.Dependency,
};

/// Requests both objects, the QUIC one `TRUST=webpki`, or null while the package is still being
/// fetched.
pub fn chapulin_objects(b: *std.Build, target: std.Build.ResolvedTarget) ?Chapulin {
    const tcp = b.lazyDependency("chapulin", .{
        .target = target,
        .RAND = .@"extern",
        .TRANSPORT = .@"tcp-nonblocking",
        .ROLE = .both,
        .TRUST = .webpki,
        .EXPORTER = .on,
    });
    const quic = chapulin_quic(b, target, .webpki);
    return .{ .tcp = tcp orelse return null, .quic = quic orelse return null };
}

/// The QUIC object in the trust mode `trust`, or null while the package is still being fetched.
pub fn chapulin_quic(b: *std.Build, target: std.Build.ResolvedTarget, trust: QuicTrust) ?*std.Build.Dependency {
    return b.lazyDependency("chapulin", .{
        .target = target,
        .RAND = .@"extern",
        .TRANSPORT = .@"quic-nonblocking",
        .ROLE = .both,
        .TRUST = trust,
        .SUITE = .aesgcm,
        .AES = .hw,
        .KEYLOG = .on,
        .CH_NATIVE_AES = true,
    });
}

/// Links chapulin into every `src/testing/` module that needs it: the TCP object into the h11 and
/// h2 endpoints and the TLS checks, the QUIC object into the loopback check. The UDP endpoint gets
/// the QUIC object where it is made (`add_testing_udp`).
pub fn link_chapulin_all(graph: Modules, chapulin: Chapulin) void {
    for ([_]*std.Build.Module{ graph.testing, graph.testing_client, graph.testing_tls, graph.testing_tls_server }) |module| {
        link_chapulin(module, chapulin.tcp);
    }
    link_chapulin(graph.testing_quic, chapulin.quic);
}

/// One object and the module translated from its headers, which `src/testing/` imports as
/// `chapulin`.
fn link_chapulin(module: *std.Build.Module, dependency: *std.Build.Dependency) void {
    module.addImport("chapulin", dependency.module("chapulin"));
    module.addObjectFile(dependency.namedLazyPath("chapulin.o"));
}
