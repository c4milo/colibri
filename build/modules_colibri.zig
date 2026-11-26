//! The `colibri` module (decisions 150 and 159): `colibri.Server` and `colibri.Client` over
//! `server` and `client`. Decision 150 ruling 1 puts it above both, and decision 153 ruling 8 gives
//! it the client. No library module imports it. Its `.private` kind binds the sockets and runs the
//! loop on Rotor, so the module imports Rotor only when the build has it. `build_options.rotor`
//! tells the source which build it is. Split from `modules.zig`, which `zig build` reads first.
//!
//! It is the one module that the package exports (decision 170). Its root names each of the
//! sixteen other library modules, so it imports them all, and a dependent reaches each as
//! `colibri.<name>`.
const std = @import("std");
const modules = @import("modules.zig");

/// The library modules `colibri` imports: each of the sixteen others, which its root names, and
/// stdx's one module, whose `crypto.Context` a server's configuration takes and whose
/// `crypto.init` a `.private` server calls when the program passes none (decision 175). The root
/// names nothing of stdx (decision 170).
pub const Imports = struct {
    core: *std.Build.Module,
    wire: *std.Build.Module,
    http: *std.Build.Module,
    tls_provider: *std.Build.Module,
    tls: *std.Build.Module,
    dnssec: *std.Build.Module,
    crypto: *std.Build.Module,
    qlog: *std.Build.Module,
    hpack: *std.Build.Module,
    qpack: *std.Build.Module,
    quic: *std.Build.Module,
    h2: *std.Build.Module,
    h3: *std.Build.Module,
    h11: *std.Build.Module,
    server: *std.Build.Module,
    client: *std.Build.Module,
    stdx: *std.Build.Module,
};

/// The imports of `colibri` out of the whole graph, each field by its name.
pub fn imports_of(graph: modules.Modules) Imports {
    var imports: Imports = undefined;
    inline for (@typeInfo(Imports).@"struct".fields) |field| {
        if (comptime std.mem.eql(u8, field.name, "stdx")) continue;
        @field(imports, field.name) = @field(graph, field.name);
    }
    imports.stdx = graph.stdx.module("stdx");
    return imports;
}

/// The packaged module, the one name a dependent reaches with `dependency.module("colibri")`
/// (decision 170). `rotor` is null when the build option `rotor` is false: the module then
/// imports no Rotor, and its `.private` kind is a compile error with colibri's message.
pub fn add(
    b: *std.Build,
    imports: Imports,
    rotor: ?*std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const colibri = b.addModule("colibri", .{
        .root_source_file = b.path("src/colibri/colibri.zig"),
        .target = target,
        .optimize = optimize,
    });
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
    inline for (@typeInfo(Imports).@"struct".fields) |field| {
        colibri.addImport(field.name, @field(imports, field.name));
    }
    const options = b.addOptions();
    options.addOption(bool, "rotor", rotor != null);
    colibri.addOptions("build_options", options);
    if (rotor) |held| colibri.addImport("rotor", held);
}
