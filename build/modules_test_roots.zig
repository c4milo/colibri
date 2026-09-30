//! The test identity's module and the roots the tests of `tls`, `server` and `client` compile from
//! (the owner's ruling of 2026-09-28). `testdata` is the one identity the handshake tests of every
//! module read, from `src/testing/testdata/`. `tls_keylog` and `sim_run` import it, and so does
//! each root `test_root` makes: its packaged module again, the same source with the same imports,
//! and `testdata` beside them.
//!
//! No packaged module imports `testdata`, and build.zig makes it in colibri's own build alone,
//! after a dependent's build has stopped. So a project that depends on colibri never reaches the
//! identity or its private key (docs/design.md §3).
const std = @import("std");
const assert = std.debug.assert;
const modules = @import("modules.zig");

/// The name every module that imports the test identity gives it, and no packaged module may.
const testdata_name = "testdata";

/// The test identity's module. `tls_keylog` imports it for its tests, and `sim_run` for the client
/// trace run, whose servers present it.
pub fn add_testdata(
    b: *std.Build,
    graph: modules.Modules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    assert(graph.tls_keylog.import_table.get(testdata_name) == null);
    assert(graph.sim_run.import_table.get(testdata_name) == null);
    const testdata = b.createModule(.{
        .root_source_file = b.path("src/testing/testdata/testdata.zig"),
        .target = target,
        .optimize = optimize,
    });
    graph.tls_keylog.addImport(testdata_name, testdata);
    graph.sim_run.addImport(testdata_name, testdata);
    return testdata;
}

/// The client's root: `test_root`'s, which also codes content with stdx's encoders, for the tests
/// of the client's decoding (decision 101). The packaged client encodes nothing.
pub fn client_test_root(b: *std.Build, packaged: *std.Build.Module, testdata: *std.Build.Module, stdx: *std.Build.Dependency) *std.Build.Module {
    const module = test_root(b, packaged, testdata);
    module.addImport("gzip", stdx.module("gzip"));
    module.addImport("zlib", stdx.module("zlib"));
    return module;
}

/// `packaged` again, with `testdata` beside its imports. It copies the imports `packaged` holds
/// when it is called, so build.zig calls it where it makes the tests, after the graph is built.
pub fn test_root(b: *std.Build, packaged: *std.Build.Module, testdata: *std.Build.Module) *std.Build.Module {
    assert(packaged.root_source_file != null);
    // A packaged module that imported the identity would hand its private key to every dependent.
    assert(packaged.import_table.get(testdata_name) == null);
    const module = b.createModule(.{
        .root_source_file = packaged.root_source_file,
        .target = packaged.resolved_target,
        .optimize = packaged.optimize,
    });
    for (packaged.import_table.keys(), packaged.import_table.values()) |name, imported| {
        module.addImport(name, imported);
    }
    module.addImport(testdata_name, testdata);
    return module;
}
