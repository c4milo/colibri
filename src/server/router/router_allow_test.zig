//! The tests of `router_allow.zig` and of the walk that backs up for a method (decision 128).
//! Test-only.
const std = @import("std");
const router = @import("router_table.zig").table_of;
const router_trie = @import("router_trie.zig");
const router_trie_layout = @import("router_trie_layout.zig");
const router_allow = @import("router_allow.zig");
const support = @import("router_test_support.zig");
const PathParameters = @import("../path_parameters.zig").PathParameters;

const testing = std.testing;

fn layout_of(comptime table: anytype) router_trie_layout.Layout(u8, router_trie_layout.sizes_of(table, &router_trie.trie_of(table))) {
    const trie = router_trie.trie_of(table);
    return router_trie_layout.build(u8, table, &trie);
}

test "decision 128: each method has a bit in decision 122 ruling 11's order, and each leaf a mask" {
    const layout = comptime layout_of(.{
        .{ "PATCH", "/a", 0 }, .{ .delete, "/a", 1 }, .{ .get, "/b", 2 }, .{ "COPY", "/b", 3 }, .{ .post, "/a", 4 },
    });
    const A = router_allow.Allows(layout);
    // RFC 9110 §9.1's order, then the tokens by octets.
    try testing.expectEqualDeep([_][]const u8{ "GET", "POST", "DELETE", "COPY", "PATCH" }, A.order);
    try testing.expectEqual(@as(router_allow.Mask, 0b10110), A.leaf_masks[layout.nodes[layout.edges[0].child].leaf.?] | 0);
    try testing.expectEqual(@as(router_allow.Mask, 1 << 3), router_allow.bit_of(&A.order, "COPY"));
    try testing.expectEqual(@as(router_allow.Mask, 0), router_allow.bit_of(&A.order, "copy"));
}

test "decision 128: the Allow value of a mask lists its methods, with HEAD after GET" {
    const layout = comptime layout_of(.{ .{ .get, "/a", 0 }, .{ .put, "/a", 1 }, .{ "PATCH", "/a", 2 } });
    const A = router_allow.Allows(layout);
    try testing.expectEqualStrings("", A.values[0]);
    try testing.expectEqualStrings("GET, HEAD", A.values[0b001]);
    try testing.expectEqualStrings("PUT, PATCH", A.values[0b110]);
    try testing.expectEqualStrings("GET, HEAD, PUT, PATCH", A.values[0b111]);
    // A table that names HEAD lists it in its place, once.
    const with_head = comptime layout_of(.{ .{ .head, "/a", 0 }, .{ .get, "/b", 1 } });
    const H = router_allow.Allows(with_head);
    try testing.expectEqualStrings("GET, HEAD", H.values[0b11]);
    try testing.expectEqualStrings("GET, HEAD", H.values[0b01]);
    try testing.expectEqualStrings("HEAD", H.values[0b10]);
}

/// Stripe's shape: a literal action beside a resource, with other methods.
/// Each route's value, in table order, so the reference names a route by its index.
const StripeRoute = enum(u8) { search, charge, charge_post, capture, customer_delete, customer_search, files };
const stripe = router(StripeRoute, .{
    .{ .get, "/v1/charges/search", .search },
    .{ .get, "/v1/charges/:charge", .charge },
    .{ .post, "/v1/charges/:charge", .charge_post },
    .{ .post, "/v1/charges/:charge/capture", .capture },
    .{ .delete, "/v1/customers/:customer", .customer_delete },
    .{ .get, "/v1/customers/search", .customer_search },
    .{ "PATCH", "/v1/files/*", .files },
});

fn expect_value(table: anytype, expected: StripeRoute, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    const result = table.match(method, path, &parameters);
    try testing.expect(result == .found);
    try testing.expectEqual(expected, result.found);
}

test "decision 128: a method the literal lacks finds the parameter route behind it" {
    try expect_value(stripe, .search, "GET", "/v1/charges/search");
    // The literal names GET alone, so a POST backs up to the parameter.
    try expect_value(stripe, .charge_post, "POST", "/v1/charges/search");
    try expect_value(stripe, .charge, "GET", "/v1/charges/ch_1");
    try expect_value(stripe, .customer_delete, "DELETE", "/v1/customers/search");
    // RFC 9110 §9.3.2: HEAD finds the literal's GET.
    try expect_value(stripe, .search, "HEAD", "/v1/charges/search");
    // The parameter holds the literal's text.
    var parameters: PathParameters = .{};
    _ = stripe.match("POST", "/v1/charges/search", &parameters);
    try testing.expectEqualStrings("search", parameters.get("charge").?);
}

test "decision 128: 405 when no leaf the path reaches serves the method, with each leaf's methods" {
    // `/v1/charges/search` and `/v1/charges/:charge` both match: GET from one, GET and POST from
    // the other.
    try support.expect_allow(stripe, "GET, HEAD, POST", "DELETE", "/v1/charges/search");
    try support.expect_allow(stripe, "GET, HEAD, POST", "DELETE", "/v1/charges/ch_1");
    try support.expect_allow(stripe, "GET, HEAD, DELETE", "POST", "/v1/customers/search");
    try support.expect_allow(stripe, "DELETE", "POST", "/v1/customers/cus_1");
    try support.expect_allow(stripe, "POST", "GET", "/v1/charges/search/capture");
    try support.expect_allow(stripe, "PATCH", "GET", "/v1/files/a/b");
    // A path that no leaf matches is still 404, and a method no route names 501.
    try support.expect_not_found(stripe, "GET", "/v1/refunds");
    try support.expect_not_implemented(stripe, "PUT", "/v1/charges/search");
}

// The reference of decision 128, which reads no trie: each route whose pattern matches the path,
// in decision 122's order, decides. It holds the tables of the fuzz property below.

const Route = struct { method: []const u8, pattern: []const u8 };

/// Three patterns that one path can match together, each with methods of its own: a path
/// `/a/c` reaches the leaves of `/a/:q`, `/:p/c` and `/:p/:r`, in that order.
const overlap_routes = [_]Route{
    .{ .method = "GET", .pattern = "/a/:q" },   .{ .method = "PUT", .pattern = "/:p/c" },
    .{ .method = "POST", .pattern = "/:p/:r" }, .{ .method = "DELETE", .pattern = "/:p/:r" },
    .{ .method = "GET", .pattern = "/a/c/*" },  .{ .method = "PUT", .pattern = "/:p/*" },
    .{ .method = "HEAD", .pattern = "/a/:q" },
};
/// Each route's value, in the order of `overlap_routes`.
const OverlapRoute = enum(u8) { a_q, p_c, p_r_post, p_r_delete, a_c_rest, p_rest, a_q_head };
const overlap = router(OverlapRoute, .{
    .{ .get, "/a/:q", .a_q },       .{ .put, "/:p/c", .p_c },    .{ .post, "/:p/:r", .p_r_post }, .{ .delete, "/:p/:r", .p_r_delete },
    .{ .get, "/a/c/*", .a_c_rest }, .{ .put, "/:p/*", .p_rest }, .{ .head, "/a/:q", .a_q_head },
});
const stripe_routes = [_]Route{
    .{ .method = "GET", .pattern = "/v1/charges/search" },         .{ .method = "GET", .pattern = "/v1/charges/:charge" },
    .{ .method = "POST", .pattern = "/v1/charges/:charge" },       .{ .method = "POST", .pattern = "/v1/charges/:charge/capture" },
    .{ .method = "DELETE", .pattern = "/v1/customers/:customer" }, .{ .method = "GET", .pattern = "/v1/customers/search" },
    .{ .method = "PATCH", .pattern = "/v1/files/*" },
};

/// The kind of a pattern's segment, in decision 122's order: a literal first.
const Kind = enum(u8) { literal, parameter, wildcard };

fn kind_of(segment: []const u8) Kind {
    if (std.mem.eql(u8, segment, "*")) return .wildcard;
    if (segment.len > 0 and segment[0] == ':') return .parameter;
    return .literal;
}

fn segment_at(text: []const u8, index: usize) ?[]const u8 {
    var iterator = std.mem.splitScalar(u8, text[1..], '/');
    var at: usize = 0;
    // Bounded by the segments of `text`.
    while (iterator.next()) |segment| : (at += 1) {
        if (at == index) return segment;
    }
    return null;
}

fn segments_of(text: []const u8) usize {
    if (text.len == 1) return 0;
    return std.mem.count(u8, text, "/");
}

/// Whether `pattern` matches `path`.
fn pattern_matches(pattern: []const u8, path: []const u8) bool {
    const count = segments_of(pattern);
    const path_count = segments_of(path);
    for (0..count) |index| {
        const segment = segment_at(pattern, index).?;
        if (kind_of(segment) == .wildcard) return path_count > index;
        if (index >= path_count) return false;
        if (kind_of(segment) == .literal and !std.mem.eql(u8, segment, segment_at(path, index).?)) return false;
    }
    return count == path_count;
}

/// Whether `left` comes before `right` in the walk's order (claim 1 of `router_hidden.zig`).
fn before(left: []const u8, right: []const u8) bool {
    const count = @max(segments_of(left), segments_of(right));
    for (0..count) |index| {
        const a = segment_at(left, index) orelse return true;
        const b = segment_at(right, index) orelse return false;
        if (kind_of(a) != kind_of(b)) return @intFromEnum(kind_of(a)) < @intFromEnum(kind_of(b));
    }
    return false;
}

fn serves(routes: []const Route, pattern: []const u8, method: []const u8) ?usize {
    var get: ?usize = null;
    for (routes, 0..) |route, index| {
        if (!std.mem.eql(u8, route.pattern, pattern)) continue;
        if (std.mem.eql(u8, route.method, method)) return index;
        if (std.mem.eql(u8, route.method, "GET")) get = index;
    }
    return if (std.mem.eql(u8, method, "HEAD")) get else null;
}

const standard_order = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH" };

/// What the reference gives: the route found, the Allow value of a 405, or neither.
const Expected = union(enum) { found: usize, allow: [allow_len_max]u8, none, not_implemented };
const allow_len_max = 64;

fn reference(routes: []const Route, method: []const u8, path: []const u8) Expected {
    // Decision 122 ruling 2: a method that no route names gives 501 before the path is read.
    if (!named(routes, method)) return .not_implemented;
    var done: [stripe_routes.len + overlap_routes.len][]const u8 = undefined;
    var done_count: usize = 0;
    var allowed = [_]bool{false} ** standard_order.len;
    // Bounded by the routes: each pass takes the earliest pattern not taken yet.
    for (0..routes.len) |_| {
        const pattern = next_pattern(routes, path, done[0..done_count]) orelse break;
        done[done_count] = pattern;
        done_count += 1;
        if (serves(routes, pattern, method)) |index| return .{ .found = index };
        allow_pattern(routes, pattern, &allowed);
    }
    if (done_count == 0) return .none;
    return .{ .allow = allow_text(&allowed) };
}

/// Whether a route names `method`, or GET for a HEAD request (RFC 9110 §9.3.2).
fn named(routes: []const Route, method: []const u8) bool {
    for (routes) |route| {
        if (std.mem.eql(u8, route.method, method)) return true;
        if (std.mem.eql(u8, method, "HEAD") and std.mem.eql(u8, route.method, "GET")) return true;
    }
    return false;
}

/// The earliest pattern, in the walk's order, that matches `path` and is not in `done`.
fn next_pattern(routes: []const Route, path: []const u8, done: []const []const u8) ?[]const u8 {
    var best: ?[]const u8 = null;
    for (routes) |route| {
        if (!pattern_matches(route.pattern, path) or held(done, route.pattern)) continue;
        if (best == null or before(route.pattern, best.?)) best = route.pattern;
    }
    return best;
}

fn held(done: []const []const u8, pattern: []const u8) bool {
    for (done) |taken| {
        if (std.mem.eql(u8, taken, pattern)) return true;
    }
    return false;
}

/// Marks the methods of `pattern`'s routes, and HEAD beside GET.
fn allow_pattern(routes: []const Route, pattern: []const u8, allowed: *[standard_order.len]bool) void {
    for (routes) |route| {
        if (!std.mem.eql(u8, route.pattern, pattern)) continue;
        for (standard_order, 0..) |name, place| {
            if (std.mem.eql(u8, name, route.method)) allowed[place] = true;
        }
        if (std.mem.eql(u8, route.method, "GET")) allowed[1] = true;
    }
}

fn allow_text(allowed: *const [standard_order.len]bool) [allow_len_max]u8 {
    var allow: [allow_len_max]u8 = @splat(0);
    var writer = std.Io.Writer.fixed(&allow);
    var first = true;
    for (standard_order, allowed) |name, set| {
        if (!set) continue;
        if (!first) writer.writeAll(", ") catch unreachable;
        writer.writeAll(name) catch unreachable;
        first = false;
    }
    return allow;
}

fn expect_reference(table: anytype, routes: []const Route, method: []const u8, path: []const u8) !void {
    var parameters: PathParameters = .{};
    const result = table.match(method, path, &parameters);
    errdefer std.debug.print("differs: {s} {s}: {any}\n", .{ method, path, result });
    switch (reference(routes, method, path)) {
        .found => |index| {
            try testing.expect(result == .found);
            // Each table's values are the routes' indexes.
            try testing.expectEqual(index, @intFromEnum(result.found));
        },
        .allow => |allow| {
            try testing.expect(result == .method_not_allowed);
            try testing.expectEqualStrings(std.mem.sliceTo(&allow, 0), result.method_not_allowed);
        },
        .none => try testing.expect(result == .not_found),
        .not_implemented => try testing.expect(result == .not_implemented),
    }
}

/// The segments the fuzz property builds paths from: the tables' literals and one that neither
/// table names.
const pieces = [_][]const u8{ "a", "c", "v1", "charges", "customers", "files", "search", "capture", "x" };
const methods = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH" };
const fuzz_input_len_max = 8;
/// The longest piece and its "/".
const piece_len_max = 16;

fn fuzz_backs_up(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const len = smith.slice(&input);
    if (len == 0) return;
    var path_buffer: [fuzz_input_len_max * piece_len_max]u8 = undefined;
    var writer = std.Io.Writer.fixed(&path_buffer);
    for (input[1..len]) |octet| {
        writer.writeAll("/") catch unreachable;
        writer.writeAll(pieces[octet % pieces.len]) catch unreachable;
    }
    const path = if (len == 1) "/" else writer.buffered();
    const method = methods[input[0] % methods.len];
    try expect_reference(stripe, &stripe_routes, method, path);
    try expect_reference(overlap, &overlap_routes, method, path);
}

test "fuzz: the walk that backs up for a method gives what decision 128's reference gives" {
    try testing.fuzz({}, fuzz_backs_up, .{ .corpus = &.{
        @import("core").fuzz.input("\x02\x02\x03\x06"),
        @import("core").fuzz.input("\x04\x00\x01"),
        @import("core").fuzz.input("\x00\x00\x01\x08"),
    } });
    try @import("core").fuzz.sweep(fuzz_backs_up, null);
}

test "every path of up to four segments gives what decision 128's reference gives" {
    var input: [5]u8 = undefined;
    for (0..methods.len) |method| {
        for (0..5) |segments| {
            var count: usize = 1;
            for (0..segments) |_| count *= pieces.len;
            for (0..count) |number| {
                var rest = number;
                input[0] = @intCast(method);
                for (input[1 .. segments + 1]) |*octet| {
                    octet.* = @intCast(rest % pieces.len);
                    rest /= pieces.len;
                }
                var entry: [@sizeOf(u32) + 5]u8 = undefined;
                std.mem.writeInt(u32, entry[0..@sizeOf(u32)], @intCast(segments + 1), .little);
                @memcpy(entry[@sizeOf(u32)..][0 .. segments + 1], input[0 .. segments + 1]);
                var smith: testing.Smith = .{ .in = entry[0 .. @sizeOf(u32) + segments + 1] };
                try fuzz_backs_up({}, &smith);
            }
        }
    }
}
