//! The UDP QUIC endpoint's module, split off `modules.zig` because a hand-written source file
//! stays at or under 500 lines (CLAUDE.md).
const std = @import("std");
const modules = @import("modules.zig");

const Modules = modules.Modules;
const create = modules.create;

/// The UDP QUIC endpoint of design §9, rooted at `src/testing/quic_udp.zig`: the one module that
/// imports rotor (decision 58). It is made apart from `modules.add` because rotor is a lazy package that
/// only colibri's own build requests, after a dependent project's build has stopped. `h2` is
/// there for `src/testing/constants.zig`, which every module of `src/testing/` shares; `quic` is
/// the module the endpoint serves, and `tls` over the `KEYLOG=on` objects fills its two vtables
/// (design §8 step 16b).
pub fn add(
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
    // Design §8 step 17b: the h3 server runs on `server`, ruled by the owner on 2026-09-28. The
    // endpoint links `tls_keylog`'s objects, and a second chapulin object fails the link, so it
    // takes an instance of `server` over `tls_keylog`, which nothing packaged sees.
    const server_keylog = create(b, "src/server/server.zig", target, optimize);
    server_keylog.addImport("core", graph.core);
    server_keylog.addImport("http", graph.http);
    server_keylog.addImport("h11", graph.h11);
    server_keylog.addImport("h2", graph.h2);
    server_keylog.addImport("h3", graph.h3);
    server_keylog.addImport("quic", graph.quic);
    server_keylog.addImport("tls", graph.tls_keylog);
    server_keylog.addImport("tls_provider", graph.tls_provider);
    server_keylog.addImport("codec", graph.stdx.module("codec"));
    server_keylog.addImport("gzip", graph.stdx.module("gzip"));
    server_keylog.addImport("zlib", graph.stdx.module("zlib"));
    module.addImport("server", server_keylog);
    module.link_libc = true;
    return module;
}
