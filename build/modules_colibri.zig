//! The `colibri` module (decision 150): it binds the sockets and runs the loop over `server` and
//! `client`, on Rotor's own calls (ruling 6). Ruling 1 puts it above both, and decision 153 ruling
//! 8 gives it the client. It is the one library module that does I/O, and no library module
//! imports it. Split from `modules.zig`, which `zig build` reads first.
const std = @import("std");
const modules = @import("modules.zig");

/// The library modules `colibri` imports.
pub const Imports = struct {
    core: *std.Build.Module,
    http: *std.Build.Module,
    server: *std.Build.Module,
    client: *std.Build.Module,
    tls: *std.Build.Module,
};

pub fn add(
    b: *std.Build,
    imports: Imports,
    rotor: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const colibri = modules.library(b, "colibri", target, optimize);
    colibri.addImport("core", imports.core);
    colibri.addImport("http", imports.http);
    colibri.addImport("server", imports.server);
    colibri.addImport("client", imports.client);
    colibri.addImport("tls", imports.tls);
    colibri.addImport("rotor", rotor.module("rotor"));
    return colibri;
}
