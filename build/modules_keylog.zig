//! The test-only modules over chapulin's `KEYLOG=on` objects (decisions 94 and 174), split from
//! `modules.zig`, which builds the packaged graph.
//!
//! stdx asks chapulin for its one module, so the objects built `KEYLOG=on` come with a second
//! stdx, which `stdx_keylog` holds. Zig puts a file in one module of a compile alone, so an image
//! that links them reads every part of stdx from that second stdx. These are the modules that read
//! stdx, or read one that does, made again over it. Every other module is the packaged one.
const std = @import("std");
const modules = @import("modules.zig");
const modules_stdx = @import("modules_stdx.zig");

const create = modules.create;

/// The packaged modules the key-log modules import as they are: none reads stdx.
pub const Shared = struct {
    core: *std.Build.Module,
    wire: *std.Build.Module,
    http: *std.Build.Module,
    tls_provider: *std.Build.Module,
    crypto: *std.Build.Module,
    qpack: *std.Build.Module,
};

/// The modules an image over the `KEYLOG=on` objects links, each over `stdx`.
pub const Keylog = struct {
    /// stdx, whose `stdx.crypto` holds chapulin's objects built `KEYLOG=on`. They hand each
    /// traffic secret to `ch_keylog`, which the image defines.
    stdx: *std.Build.Dependency,
    qlog: *std.Build.Module,
    quic: *std.Build.Module,
    h3: *std.Build.Module,
    h11: *std.Build.Module,
    /// `tls` over these objects: its tests seal records under the traffic secrets chapulin logs,
    /// such as a peer's KeyUpdate, which no chapulin session sends in record mode, and
    /// `src/testing/`'s QUIC endpoints, which write the secrets to SSLKEYLOGFILE, import it as
    /// `tls`.
    tls: *std.Build.Module,
};

/// Makes the key-log modules, with the imports `modules.add` gives the packaged ones.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    shared: Shared,
) Keylog {
    const stdx = modules_stdx.dependency(b, target, optimize, .on);
    const qlog = create(b, "src/qlog/qlog.zig", target, optimize);
    qlog.addImport("stdx", stdx.module("stdx"));
    // Decision 5 holds here too: no HTTP module is given to `quic`.
    const quic = create(b, "src/quic/quic.zig", target, optimize);
    quic.addImport("core", shared.core);
    quic.addImport("wire", shared.wire);
    quic.addImport("crypto", shared.crypto);
    quic.addImport("tls_provider", shared.tls_provider);
    quic.addImport("qlog", qlog);
    const h3 = create(b, "src/h3/h3.zig", target, optimize);
    h3.addImport("core", shared.core);
    h3.addImport("wire", shared.wire);
    h3.addImport("http", shared.http);
    h3.addImport("qpack", shared.qpack);
    h3.addImport("quic", quic);
    h3.addImport("qlog", qlog);
    const h11 = create(b, "src/h11/h11.zig", target, optimize);
    h11.addImport("core", shared.core);
    h11.addImport("http", shared.http);
    h11.addImport("tls_provider", shared.tls_provider);
    h11.addImport("stdx", stdx.module("stdx"));
    const tls = create(b, "src/tls/tls.zig", target, optimize);
    tls.addImport("tls_provider", shared.tls_provider);
    tls.addImport("crypto", shared.crypto);
    tls.addImport("stdx", stdx.module("stdx"));
    return .{ .stdx = stdx, .qlog = qlog, .quic = quic, .h3 = h3, .h11 = h11, .tls = tls };
}
