//! `zig build router-check` (decision 122, design §8 step 21e.4): each table that `server.router`
//! refuses fails to compile, with the message that names its entry and its refusal.
//!
//! The tests in `src/server/router/router_refusal_test.zig` call each check at compile time. They
//! do not show that `server.router` stops the compile. This step compiles
//! `tools/fixtures/router_refused.zig` once for each case, with the build option `case` set to
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

/// One case for each refusal of `server.router` and the control. The text after `server.router:`
/// is the name of the refusal and its sentence, from `router_pattern.zig`, `router_method.zig`
/// and `router_trie.zig`.
const cases = [_]Case{
    .{ .name = "accepted", .message = null },
    .{
        .name = "pattern_not_absolute",
        .message = "server.router: route 1, \"users\": pattern_not_absolute: " ++
            "a pattern starts with \"/\" (RFC 9110 §4.1)",
    },
    .{
        .name = "segment_empty",
        .message = "server.router: route 1, \"/a//b\": segment_empty: " ++
            "a segment of a pattern is not empty, and only the pattern \"/\" ends in \"/\"",
    },
    .{
        .name = "segment_dot",
        .message = "server.router: route 1, \"/a/./b\": segment_dot: " ++
            "a segment of a pattern is not \".\" or \"..\" (RFC 3986 §3.3)",
    },
    .{
        .name = "segment_encoded",
        .message = "server.router: route 1, \"/caf%C3%A9\": segment_encoded: " ++
            "a pattern holds no \"%\", because a path with one matches no route (RFC 3986 §2.1)",
    },
    .{
        .name = "octet_outside_path",
        .message = "server.router: route 1, \"/a b\": octet_outside_path: " ++
            "each octet of a segment is a pchar other than \"%\" (RFC 3986 §3.3)",
    },
    .{
        .name = "parameter_unnamed",
        .message = "server.router: route 1, \"/users/:\": parameter_unnamed: " ++
            "a parameter has a name after its \":\"",
    },
    .{
        .name = "parameter_name_invalid",
        .message = "server.router: route 1, \"/:user-id\": parameter_name_invalid: " ++
            "a parameter name is 1*( ALPHA / DIGIT / \"_\" ), and a parameter is a whole segment",
    },
    .{
        .name = "parameter_repeated",
        .message = "server.router: route 1, \"/:id/posts/:id\": parameter_repeated: " ++
            "each parameter of a pattern has a name of its own",
    },
    .{
        .name = "parameters_too_many",
        .message = "server.router: route 1, \"/:a/:b/:c/:d/:e/:f/:g/:h/:i\": parameters_too_many: " ++
            "a pattern holds server.constants.path_parameters_max parameters at most",
    },
    .{
        .name = "wildcard_not_last",
        .message = "server.router: route 1, \"/files/*/meta\": wildcard_not_last: " ++
            "the wildcard \"*\" is the last segment of its pattern",
    },
    .{
        .name = "method_unknown",
        .message = "server.router: route 1, \"/a\": method_unknown: " ++
            "no member of http.method.Standard has this name; write a method " ++
            "outside RFC 9110's eight as its token, such as \"PATCH\"",
    },
    .{
        .name = "method_not_token",
        .message = "server.router: route 1, \"/a\": method_not_token: " ++
            "a method is a token (RFC 9110 §9.1)",
    },
    .{
        .name = "method_standard_as_token",
        .message = "server.router: route 1, \"/a\": method_standard_as_token: " ++
            "write a method of RFC 9110's eight as its enum literal, such as .get",
    },
    .{
        .name = "method_connect",
        .message = "server.router: route 1, \"/a\": method_connect: " ++
            "a CONNECT request has no path (RFC 9110 §9.3.6, decision 19)",
    },
    .{
        .name = "method_type",
        .message = "server.router: route 1, \"/a\": method_type: " ++
            "a method is an enum literal, a value of http.method.Standard, or a token",
    },
    .{
        .name = "table_empty",
        .message = "server.router: table_empty: a table holds one route at least",
    },
    .{
        .name = "entry_shape",
        .message = "server.router: route 1, \"\": entry_shape: " ++
            "an entry is a tuple of a method, a pattern and a value",
    },
    .{
        .name = "parameter_names_differ",
        .message = "server.router: route 1, \"/users/:user\": parameter_names_differ: " ++
            "two routes with the same segments before a parameter give the parameter one name",
    },
    .{
        .name = "route_repeated",
        .message = "server.router: route 1, \"/a\": route_repeated: " ++
            "two routes name one method and one path",
    },
    .{
        .name = "allow_too_long",
        .message = "server.router: route 1, \"/a\": allow_too_long: " ++
            "the Allow value of the routes of one pattern holds " ++
            "core.constants.field_value_len_max octets at most, because a 405 sends it as a field value",
    },
    .{
        .name = "methods_too_many",
        .message = "server.router: route 10, \"/a\": methods_too_many: " ++
            "the routes of a table name server.constants.route_methods_max methods at most (decision 128)",
    },
    .{
        .name = "route_unreachable",
        .message = "server.router: route 1, \"/a/*\": route_unreachable: " ++
            "no request reaches this route, because another pattern matches each of its paths first: " ++
            "\"/a/:x\", \"/a/:x/*\"",
    },
    .{
        .name = "handler_type",
        .message = "server.router: route 1, \"/a\": handler_type: " ++
            "a route holds a function, or a struct with on_request (decision 127)",
    },
    .{
        .name = "on_request_missing",
        .message = "server.router: route 1, \"/a\": on_request_missing: " ++
            "a struct route declares pub fn on_request (decision 127)",
    },
    .{
        .name = "parameters_count",
        .message = "server.router: route 1, \"/a\": parameters_count: " ++
            "a route's function takes five parameters, and on_request six (decision 127)",
    },
    .{
        .name = "context_parameter",
        .message = "server.router: route 1, \"/a\": context_parameter: " ++
            "the first parameter is a pointer to the router's Context",
    },
    .{
        .name = "state_parameter",
        .message = "server.router: route 1, \"/a\": state_parameter: " ++
            "on_request, on_body, on_writable and on_finished take a *State after the context",
    },
    .{
        .name = "request_parameter",
        .message = "server.router: route 1, \"/a\": request_parameter: " ++
            "the request parameter is *const server.Request",
    },
    .{
        .name = "path_parameter",
        .message = "server.router: route 1, \"/a\": path_parameter: " ++
            "the path parameter is void, or a struct of []const u8 fields",
    },
    .{
        .name = "path_fields_differ",
        .message = "server.router: route 1, \"/a/:id\": path_fields_differ: " ++
            "the path struct has one field for each parameter of the pattern, and rest for its \"*\"",
    },
    .{
        .name = "query_parameter",
        .message = "server.router: route 1, \"/a\": query_parameter: " ++
            "the query parameter is void, http.QueryParameters, or a struct of []const u8 and ?[]const u8 fields",
    },
    .{
        .name = "response_parameter",
        .message = "server.router: route 1, \"/a\": response_parameter: " ++
            "the last parameter is *server.ResponseWriter",
    },
    .{
        .name = "return_type",
        .message = "server.router: route 1, \"/a\": return_type: " ++
            "a route's function returns void or an error union of void",
    },
    .{
        .name = "on_body_parameters",
        .message = "server.router: route 1, \"/a\": on_body_parameters: " ++
            "body takes the context, *State, *std.Io.Reader and *server.ResponseWriter",
    },
    .{
        .name = "on_writable_parameters",
        .message = "server.router: route 1, \"/a\": on_writable_parameters: " ++
            "writable takes the context, *State and *server.ResponseWriter",
    },
    .{
        .name = "on_finished_parameters",
        .message = "server.router: route 1, \"/a\": on_finished_parameters: " ++
            "finished takes the context, *State and server.Result, and returns void",
    },
    .{
        .name = "state_defaults",
        .message = "server.router: route 1, \"/a\": state_defaults: " ++
            "each field of State has a default value, which each request starts from",
    },
    .{
        .name = "option_unknown",
        .message = "server.router: route 1, \"/a\": option_unknown: " ++
            "a route's options are whole_body and middleware",
    },
    .{
        .name = "handler_type_not_struct",
        .message = "server.router: route 1, \"/a\": handler_type: " ++
            "a route holds a function, or a struct with on_request (decision 127)",
    },
    .{
        .name = "path_field_type",
        .message = "server.router: route 1, \"/a/:id\": path_parameter: " ++
            "the path parameter is void, or a struct of []const u8 fields",
    },
    .{
        .name = "path_field_extra",
        .message = "server.router: route 1, \"/a/:id\": path_fields_differ: " ++
            "the path struct has one field for each parameter of the pattern, and rest for its \"*\"",
    },
    .{
        .name = "finished_returns",
        .message = "server.router: route 1, \"/a\": on_finished_parameters: " ++
            "finished takes the context, *State and server.Result, and returns void",
    },
    .{
        .name = "state_not_struct",
        .message = "server.router: route 1, \"/a\": state_defaults: " ++
            "each field of State has a default value, which each request starts from",
    },
    .{
        .name = "option_not_struct",
        .message = "server.router: route 1, \"/a\": option_unknown: " ++
            "a route's options are whole_body and middleware",
    },
    .{
        .name = "whole_body_unread",
        .message = "server.router: route 1, \"/a\": whole_body_unread: " ++
            "whole_body needs a struct route with on_body",
    },
    .{
        .name = "middleware_type",
        .message = "server.router: route 1, \"/a\": middleware_type: " ++
            "middleware is a tuple of structs (decision 127 ruling 5)",
    },
    .{
        .name = "middleware_on_request",
        .message = "server.router: route 1, \"/a\": middleware_on_request: " ++
            "a middleware's on_request takes the context, *const server.Request and *server.ResponseWriter, and returns server.middleware.Next",
    },
    .{
        .name = "table_middleware_hooks",
        .message = "server.router: middleware: middleware_hooks: " ++
            "a middleware declares one or more of on_request, on_finished, wrap_body and wrap_response (decision 127 ruling 5)",
    },
    .{
        .name = "middleware_on_finished",
        .message = "server.router: route 1, \"/a\": middleware_on_finished: " ++
            "a middleware's on_finished takes the context, server.RequestId and server.Result, and returns void",
    },
    .{
        .name = "middleware_on_finished_parameters",
        .message = "server.router: route 1, \"/a\": middleware_on_finished: " ++
            "a middleware's on_finished takes the context, server.RequestId and server.Result, and returns void",
    },
    .{
        .name = "middleware_on_request_parameters",
        .message = "server.router: route 1, \"/a\": middleware_on_request: " ++
            "a middleware's on_request takes the context, *const server.Request and *server.ResponseWriter, and returns server.middleware.Next",
    },
    .{
        .name = "middleware_state_defaults",
        .message = "server.router: route 1, \"/a\": middleware_state_defaults: " ++
            "each field of a middleware's State has a default value, which each request starts from",
    },
    .{
        .name = "middleware_wrap_body",
        .message = "server.router: route 1, \"/a\": middleware_wrap_body: " ++
            "wrap_body takes the context, *State, *const server.Request and *std.Io.Reader, and returns ?*std.Io.Reader",
    },
    .{
        .name = "middleware_wrap_response",
        .message = "server.router: route 1, \"/a\": middleware_wrap_response: " ++
            "wrap_response takes the context, *State, *const server.Request, *server.ResponseWriter and *std.Io.Writer, and returns ?*std.Io.Writer",
    },
    .{
        .name = "middleware_finish_response",
        .message = "server.router: route 1, \"/a\": middleware_finish_response: " ++
            "finish_response goes with wrap_response, takes the context and *State, and returns an error union of void",
    },
    .{
        .name = "route_table_shape",
        .message = "server.router: route table: route_table_shape: " ++
            "a route table is a struct with error_handler and routes (decision 127)",
    },
    .{
        .name = "routes_missing",
        .message = "server.router: route table: routes_missing: " ++
            "a route table names routes, a tuple of route entries",
    },
    .{
        .name = "table_field_unknown",
        .message = "server.router: route table: table_field_unknown: " ++
            "a route table holds error_handler, routes and middleware alone",
    },
    .{
        .name = "error_handler_missing",
        .message = "server.router: route table: error_handler_missing: " ++
            "a route table names error_handler, which chooses the status after an error (decision 127 ruling 4)",
    },
    .{
        .name = "error_handler_type",
        .message = "server.router: route table: error_handler_type: " ++
            "error_handler takes the context, *const server.Request, anyerror and *server.ResponseWriter, and returns void",
    },
};

/// Adds `zig build router-check` and returns its step, which `zig build test` depends on.
pub fn add(
    b: *std.Build,
    graph: modules.Modules,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step {
    const step = b.step("router-check", "Require each malformed route table to fail to compile");
    for (cases) |case| {
        const options = b.addOptions();
        options.addOption([]const u8, "case", case.name);
        const module = b.createModule(.{
            .root_source_file = b.path("tools/fixtures/router_refused.zig"),
            .target = target,
            .optimize = optimize,
        });
        module.addImport("server", graph.server);
        module.addImport("http", graph.http);
        module.addOptions("router_case", options);
        const compile = b.addObject(.{ .name = b.fmt("router_{s}", .{case.name}), .root_module = module });
        // Zig fails the step when the compile succeeds, or when no error line ends with the
        // message. With no message, the step fails when the compile fails.
        if (case.message) |message| compile.expect_errors = .{ .contains = message };
        step.dependOn(&compile.step);
    }
    return step;
}

/// Adds `zig build router-hidden-check` and returns its step, which `zig build test` depends on.
/// The step runs two test binaries, apart from `zig build test-server` (the owner's rulings of
/// 2026-10-14):
///
/// - `router-hidden`, from `src/server/router_hidden_check.zig`: the cross-check of
///   `src/server/router/router_hidden_test.zig`. Its compile takes about a minute.
/// - `router-quota`, from `src/server/router_quota_check.zig`: the test of the quota on a long
///   segment, in `src/server/router/router_quota_test.zig`. Its compile also takes about a
///   minute.
///
/// The two binaries do not depend on each other, so the build compiles them in parallel. Each root
/// compiles with the imports of `server`, as the root of `test-server` does
/// (build/modules_test_roots.zig). No packaged module imports a root.
pub fn add_hidden(b: *std.Build, server: *std.Build.Module) *std.Build.Step {
    const step = b.step("router-hidden-check", "Compare the check of hidden routes with a brute force, and test its quota");
    step.dependOn(hidden_run(b, server, "router-hidden", "src/server/router_hidden_check.zig"));
    step.dependOn(hidden_run(b, server, "router-quota", "src/server/router_quota_check.zig"));
    return step;
}

/// The run of the test binary `name`, which compiles from `root` with the imports of `server`.
fn hidden_run(b: *std.Build, server: *std.Build.Module, name: []const u8, root: []const u8) *std.Build.Step {
    const module = b.createModule(.{
        .root_source_file = b.path(root),
        .target = server.resolved_target,
        .optimize = server.optimize,
    });
    for (server.import_table.keys(), server.import_table.values()) |import_name, imported| {
        module.addImport(import_name, imported);
    }
    const tests = b.addTest(.{ .name = name, .root_module = module });
    return &b.addRunArtifact(tests).step;
}
