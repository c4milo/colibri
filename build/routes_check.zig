//! `zig build routes-check` (decision 122, design §8 step 21e.4): each table that `server.routes`
//! refuses fails to compile, with the message that names its entry and its refusal.
//!
//! The tests in `src/server/routes/routes_refusal_test.zig` call each check at compile time. They
//! do not show that `server.routes` stops the compile. This step compiles
//! `tools/fixtures/routes_refused.zig` once for each case, with the build option `case` set to
//! the name of the case. The fixture compiles that case's table alone. The step requires the
//! compile to fail with the case's message at the end of an error line.
//!
//! The case `accepted` is a control. Its table holds each kind of method and pattern that a table
//! accepts, and its compile must succeed. It shows that the fixture, its options and the `server`
//! module compile together, so each failure comes from the refusal of its case. A case with
//! no `message` is a compile that must succeed.
const std = @import("std");
const modules = @import("modules.zig");

/// One compile of the fixture: the name of its table and the error the compiler must write.
const Case = struct {
    name: []const u8,
    message: ?[]const u8,
};

/// One case for each refusal of `server.routes` and the control. The text after `server.routes:`
/// is the name of the refusal and its sentence, from `routes_pattern.zig`, `routes_method.zig`
/// and `routes_trie.zig`.
const cases = [_]Case{
    .{ .name = "accepted", .message = null },
    .{
        .name = "pattern_not_absolute",
        .message = "server.routes: route 1, \"users\": pattern_not_absolute: " ++
            "a pattern starts with \"/\" (RFC 9110 §4.1)",
    },
    .{
        .name = "segment_empty",
        .message = "server.routes: route 1, \"/a//b\": segment_empty: " ++
            "a segment of a pattern is not empty, and only the pattern \"/\" ends in \"/\"",
    },
    .{
        .name = "segment_dot",
        .message = "server.routes: route 1, \"/a/./b\": segment_dot: " ++
            "a segment of a pattern is not \".\" or \"..\" (RFC 3986 §3.3)",
    },
    .{
        .name = "segment_encoded",
        .message = "server.routes: route 1, \"/caf%C3%A9\": segment_encoded: " ++
            "a pattern holds no \"%\", because a path with one matches no route (RFC 3986 §2.1)",
    },
    .{
        .name = "octet_outside_path",
        .message = "server.routes: route 1, \"/a b\": octet_outside_path: " ++
            "each octet of a segment is a pchar other than \"%\" (RFC 3986 §3.3)",
    },
    .{
        .name = "method_unknown",
        .message = "server.routes: route 1, \"/a\": method_unknown: " ++
            "no member of http.method.Standard has this name; write a method " ++
            "outside RFC 9110's eight as its token, such as \"PATCH\"",
    },
    .{
        .name = "method_not_token",
        .message = "server.routes: route 1, \"/a\": method_not_token: " ++
            "a method is a token (RFC 9110 §9.1)",
    },
    .{
        .name = "method_standard_as_token",
        .message = "server.routes: route 1, \"/a\": method_standard_as_token: " ++
            "write a method of RFC 9110's eight as its enum literal, such as .get",
    },
    .{
        .name = "method_connect",
        .message = "server.routes: route 1, \"/a\": method_connect: " ++
            "a CONNECT request has no path (RFC 9110 §9.3.6, decision 19)",
    },
    .{
        .name = "method_type",
        .message = "server.routes: route 1, \"/a\": method_type: " ++
            "a method is an enum literal, a value of http.method.Standard, or a token",
    },
    .{
        .name = "table_empty",
        .message = "server.routes: table_empty: a table holds one route at least",
    },
    .{
        .name = "entry_shape",
        .message = "server.routes: route 1, \"\": entry_shape: " ++
            "an entry is a tuple of a method, a pattern and a value",
    },
    .{
        .name = "route_repeated",
        .message = "server.routes: route 1, \"/a\": route_repeated: " ++
            "two routes name one method and one path",
    },
};

/// Adds `zig build routes-check` and returns its step, which `zig build test` depends on.
pub fn add(
    b: *std.Build,
    graph: modules.Modules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const step = b.step("routes-check", "Require each malformed route table to fail to compile");
    for (cases) |case| {
        const options = b.addOptions();
        options.addOption([]const u8, "case", case.name);
        const module = b.createModule(.{
            .root_source_file = b.path("tools/fixtures/routes_refused.zig"),
            .target = target,
            .optimize = optimize,
        });
        module.addImport("server", graph.server);
        module.addImport("http", graph.http);
        module.addOptions("routes_case", options);
        const compile = b.addObject(.{ .name = b.fmt("routes_{s}", .{case.name}), .root_module = module });
        // Zig fails the step when the compile succeeds, or when no error line ends with the
        // message. With no message, the step fails when the compile fails.
        if (case.message) |message| compile.expect_errors = .{ .contains = message };
        step.dependOn(&compile.step);
    }
    return step;
}
