//! The module graph of docs/design.md §3: one module per concern, wired in dependency order. A
//! module can `@import` only what this file gives it, so the direction is enforced by the build
//! and not by review (CLAUDE.md, Layout).
//!
//! The one edge that must never exist is `quic` importing anything of HTTP. RFC 9000 defines a
//! transport that carries streams and never interprets their payloads; decision 5 keeps it that
//! way: `quic` receives `core`, `wire`, `crypto`, `tls_provider` and `qlog`, and nothing else.
//! `src/quic/` naming `http`, `h2`, `h3`, `h11`, `hpack` or `qpack` does not compile, which is
//! invariant 26 and the check of design §8 step 0. `qlog` imports `core` alone (decision 102).
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
    /// A qlog log in the caller's buffer, and the event records `quic` and `h3` fill (decision
    /// 102). Imports `core` alone.
    qlog: *std.Build.Module,
    hpack: *std.Build.Module,
    qpack: *std.Build.Module,
    /// The transport of RFC 8999, 9000, 9001 and 9002. Knows nothing about HTTP.
    quic: *std.Build.Module,
    h2: *std.Build.Module,
    h3: *std.Build.Module,
    /// HTTP/1.1 (decisions 88 and 91, design §8 step 15).
    h11: *std.Build.Module,
    /// TLS 1.3 over chapulin (decisions 94 and 97, design §8 step 16b): colibri's values, converted
    /// once per object, and chapulin's sessions behind `tls_provider.Provider`.
    tls: *std.Build.Module,
    /// HTTP responses behind one set of calls for h11 and h2, which runs the TLS handshake itself
    /// (decision 100, design §8 step 17a).
    server: *std.Build.Module,
    /// HTTP requests behind one set of calls for h11 and h2, which runs the TLS handshake itself
    /// (decision 100, design §8 step 17c).
    client: *std.Build.Module,
    /// The TCP object `tls` links. `src/testing/`'s TCP endpoints link it too, because two objects
    /// of one transport define the same names.
    chapulin_tcp: *std.Build.Dependency,
    /// `tls` again, over the objects built `KEYLOG=on`: its tests seal records under the traffic
    /// secrets chapulin logs, such as a peer's KeyUpdate, which no chapulin session sends in record
    /// mode, and `src/testing/`'s QUIC endpoints, which write the secrets to SSLKEYLOGFILE, import
    /// it as `tls`. Test-only.
    tls_keylog: *std.Build.Module,
    /// The QUIC object `tls_keylog` links, which the QUIC endpoints' `ch_keylog` reads the hook of.
    chapulin_quic_keylog: *std.Build.Dependency,
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

    const qlog = library(b, "qlog", target, optimize);
    qlog.addImport("core", core);

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
    quic.addImport("qlog", qlog);

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
    // Decisions 90 and 91: stdx decodes the gzip and deflate transfer codings. `codec` carries
    // the streaming contract both decoders share.
    const stdx = b.dependency("stdx", .{ .target = target, .release = optimize == .ReleaseSafe });
    h11.addImport("codec", stdx.module("codec"));
    h11.addImport("gzip", stdx.module("gzip"));
    h11.addImport("zlib", stdx.module("zlib"));

    // Decision 97: `tls` fills `tls_provider.Provider` from chapulin's sessions. No HTTP module
    // imports it, so a cleartext program never links chapulin.
    const chapulin_tcp = chapulin_record_object(b, target, .off);
    const tls = library(b, "tls", target, optimize);
    tls.addImport("tls_provider", tls_provider);
    tls.addImport("crypto", crypto);
    tls.addImport("chapulin_tcp", chapulin_tcp.module("chapulin"));
    tls.addImport("chapulin_quic", chapulin_quic_object(b, target, .off).module("chapulin"));
    const chapulin_quic_keylog = chapulin_quic_object(b, target, .on);
    const tls_keylog = create(b, "src/tls/tls.zig", target, optimize);
    tls_keylog.addImport("tls_provider", tls_provider);
    tls_keylog.addImport("crypto", crypto);
    tls_keylog.addImport("chapulin_tcp", chapulin_record_object(b, target, .on).module("chapulin"));
    tls_keylog.addImport("chapulin_quic", chapulin_quic_keylog.module("chapulin"));

    // Decision 100: `server` answers requests over h11 and h2 behind one set of calls, and drives
    // `tls` itself. With `client`, it is the one module above the protocol modules.
    const server = library(b, "server", target, optimize);
    server.addImport("core", core);
    server.addImport("http", http);
    server.addImport("h11", h11);
    server.addImport("h2", h2);
    server.addImport("tls", tls);
    server.addImport("tls_provider", tls_provider);
    // Decision 100: `client` sends requests over h11 and h2 behind one set of calls, and drives
    // `tls` itself, as `server` does.
    const client = library(b, "client", target, optimize);
    client.addImport("core", core);
    client.addImport("http", http);
    client.addImport("h11", h11);
    client.addImport("h2", h2);
    client.addImport("tls", tls);
    client.addImport("tls_provider", tls_provider);
    // Design §8 step 17d: h3 over QUIC, behind the same calls.
    client.addImport("quic", quic);
    client.addImport("h3", h3);

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
    // The owner's ruling of 2026-09-26 for design §8 step 15c: the h11 coding check codes the bodies
    // it sends with stdx's encoders, because no colibri writer codes one (decision 91).
    sim_run.addImport("gzip", stdx.module("gzip"));
    sim_run.addImport("zlib", stdx.module("zlib"));

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
    // Step 5's TLS half, over the library's `tls` since step 16b: the endpoint hands a session's
    // `tls_provider.Provider` to the connection, so it names both.
    testing.addImport("tls_provider", tls_provider);
    testing.addImport("tls", tls);
    // Design §8 step 17a: the h11 and h2 server of §9 runs each connection on `server`.
    testing.addImport("server", server);
    // The endpoints call `send` and `recv` with MSG_DONTWAIT, which is libc's.
    testing.link_libc = true;

    const testing_client = create(b, "src/testing/client.zig", target, optimize);
    testing_client.addImport("core", core);
    testing_client.addImport("h2", h2);
    testing_client.addImport("h11", h11);
    testing_client.addImport("tls_provider", tls_provider);
    testing_client.addImport("tls", tls);
    // Design §8 step 17c: each connection of the client of §9 runs on `client`.
    testing_client.addImport("client", client);
    // The client session's tests run the client against §9's server, which runs on `server`.
    testing_client.addImport("server", server);
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
    testing_tls.addImport("tls", tls);
    testing_tls.link_libc = true;

    // The other half of step 5's check, and a fourth root for the same reason as the third: one
    // `main` per executable. This one accepts.
    const testing_tls_server = create(b, "src/testing/tls_accept.zig", target, optimize);
    testing_tls_server.addImport("core", core);
    testing_tls_server.addImport("h2", h2);
    testing_tls_server.addImport("tls_provider", tls_provider);
    testing_tls_server.addImport("tls", tls);
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
    // Design §8 step 16b: its sessions are `tls`'s, over the `KEYLOG=on` objects, and its
    // `ch_keylog` reads the hook through the QUIC object's module.
    testing_quic.addImport("tls", tls_keylog);
    testing_quic.addImport("chapulin", chapulin_quic_keylog.module("chapulin"));
    testing_quic.link_libc = true;

    return .{
        .core = core,
        .wire = wire,
        .http = http,
        .tls_provider = tls_provider,
        .crypto = crypto,
        .qlog = qlog,
        .hpack = hpack,
        .qpack = qpack,
        .quic = quic,
        .h2 = h2,
        .h3 = h3,
        .h11 = h11,
        .tls = tls,
        .server = server,
        .client = client,
        .chapulin_tcp = chapulin_tcp,
        .tls_keylog = tls_keylog,
        .chapulin_quic_keylog = chapulin_quic_keylog,
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
/// the module the endpoint serves, and `tls` over the `KEYLOG=on` objects fills its two vtables
/// (design §8 step 16b).
pub fn add_testing_udp(
    b: *std.Build,
    graph: Modules,
    rotor: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = create(b, "src/testing/quic_udp.zig", target, optimize);
    module.addImport("h2", graph.h2);
    module.addImport("quic", graph.quic);
    // The h3 server and client of design §9, ruled by the owner on 2026-09-24.
    module.addImport("h3", graph.h3);
    module.addImport("rotor", rotor);
    module.addImport("tls", graph.tls_keylog);
    module.addImport("chapulin", graph.chapulin_quic_keylog.module("chapulin"));
    module.link_libc = true;
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

/// chapulin's `AES`, `SUITE` and `KEYLOG` values the library's objects choose between, spelled as
/// its build spells them.
const Aes = enum { soft, hw };
const Suite = enum { chacha, aesgcm };
const Keylog = enum { on, off };

/// Decision 97's TCP object: `TRANSPORT=tcp-nonblocking ROLE=both TRUST=webpki EXPORTER=on`,
/// compiled from the pinned package with `RAND=session`, where each session draws from the source its
/// caller passes (decision 94 as amended on 2026-09-27). `SUITE=aesgcm` adds RFC 9846
/// §9.1's mandatory TLS_AES_128_GCM_SHA256, and `TX_RECORD=16384` lets a record carry TLS's largest
/// plaintext (RFC 9846 §5.1). `TRUST=webpki` is the one client trust mode that compiles ALPN in,
/// without which no client negotiates h2 (RFC 9113 §3.1). The package also translates the public
/// headers under the defines its object compiled with, so the declarations colibri reads always
/// match the object it links. The library's object is `KEYLOG=off` (decision 94); only the tests
/// of `tls_keylog` build one `on`.
fn chapulin_record_object(b: *std.Build, target: std.Build.ResolvedTarget, keylog: Keylog) *std.Build.Dependency {
    const native = aes_native(target);
    return b.dependency("chapulin", .{
        .target = target,
        .RAND = .session,
        .TRANSPORT = .@"tcp-nonblocking",
        .ROLE = .both,
        .TRUST = .webpki,
        .EXPORTER = .on,
        .SUITE = if (native) Suite.aesgcm else Suite.chacha,
        .AES = if (native) Aes.hw else Aes.soft,
        .CH_NATIVE_AES = native,
        .TX_RECORD = "16384",
        .KEYLOG = keylog,
    });
}

/// Decision 97: `AES=hw`, with the builder's statement `CH_NATIVE_AES`, on a target whose features
/// include the instructions chapulin's `aes_hw.c` runs on, and `AES=soft` on any other. Those are
/// the AES instructions and the carry-less multiply: aes and pclmul on x86, and aes on Arm, where
/// the 64-bit PMULL is part of the AES extension (chapulin's `aesTarget`). chapulin refuses
/// `SUITE=aesgcm` with `AES=soft`, whose S-box is indexed with the key (its `ct.h`, INV-26), so an
/// object with software AES carries `SUITE=chacha`, TLS_CHACHA20_POLY1305_SHA256 alone.
fn aes_native(target: std.Build.ResolvedTarget) bool {
    const cpu = target.result.cpu;
    return switch (cpu.arch) {
        .x86, .x86_64 => std.Target.x86.featureSetHasAll(cpu.features, .{ .aes, .pclmul }),
        .aarch64, .aarch64_be => std.Target.aarch64.featureSetHas(cpu.features, .aes),
        else => false,
    };
}

/// Decision 97's QUIC object: `TRANSPORT=quic-nonblocking ROLE=both TRUST=webpki SUITE=aesgcm`,
/// compiled from the pinned package with `RAND=session` (decision 94 as amended), with the AES
/// choice of the TCP object. `SUITE=aesgcm` adds RFC 9846 §9.1's mandatory TLS_AES_128_GCM_SHA256,
/// which is also the only kind of suite h3spec offers. The library's object is `KEYLOG=off`; `tls_keylog` builds
/// one `on`, which hands the tests and the endpoints each traffic secret.
fn chapulin_quic_object(b: *std.Build, target: std.Build.ResolvedTarget, keylog: Keylog) *std.Build.Dependency {
    const native = aes_native(target);
    return b.dependency("chapulin", .{
        .target = target,
        .RAND = .session,
        .TRANSPORT = .@"quic-nonblocking",
        .ROLE = .both,
        .TRUST = .webpki,
        .SUITE = if (native) Suite.aesgcm else Suite.chacha,
        .AES = if (native) Aes.hw else Aes.soft,
        .CH_NATIVE_AES = native,
        .KEYLOG = keylog,
    });
}
