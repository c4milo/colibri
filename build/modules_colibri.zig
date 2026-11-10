//! The `colibri` module (decisions 150 and 159): `colibri.Server` and `colibri.Client` over
//! `server` and `client`. Decision 150 ruling 1 puts it above both, and decision 153 ruling 8 gives
//! it the client. No library module imports it. Its `.private` kind binds the sockets and runs the
//! loop on Rotor, so the module imports Rotor only when the build has it. `build_options.rotor`
//! tells the source which build it is. Split from `modules.zig`, which `zig build` reads first.
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

/// The packaged module. `rotor` is null when the build option `rotor` is false: the module then
/// imports no Rotor, and its `.private` kind is a compile error with colibri's message.
pub fn add(
    b: *std.Build,
    imports: Imports,
    rotor: ?*std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const colibri = modules.library(b, "colibri", target, optimize);
    add_imports(b, colibri, imports, rotor);
    return colibri;
}

/// The module as a dependent that passes no `.rotor = true` gets it, which no dependent reaches by
/// name: `zig build colibri-hosted-check` compiles its fixtures against it (decision 159).
pub fn add_without_rotor(
    b: *std.Build,
    imports: Imports,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const colibri = modules.create(b, "src/colibri/colibri.zig", target, optimize);
    add_imports(b, colibri, imports, null);
    return colibri;
}

fn add_imports(b: *std.Build, colibri: *std.Build.Module, imports: Imports, rotor: ?*std.Build.Module) void {
    colibri.addImport("core", imports.core);
    colibri.addImport("http", imports.http);
    colibri.addImport("server", imports.server);
    colibri.addImport("client", imports.client);
    colibri.addImport("tls", imports.tls);
    const options = b.addOptions();
    options.addOption(bool, "rotor", rotor != null);
    colibri.addOptions("build_options", options);
    if (rotor) |held| colibri.addImport("rotor", held);
}
