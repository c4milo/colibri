//! The small readers every rule asks of a node it has reached: the 1-based line and column of a
//! token, the dotted text of an identifier or field-access chain such as `std.heap.page_allocator`,
//! the callee of a call node, and the segment tests the forbidden-chain rules match with.
//!
//! Split off `ast.zig` so that file holds the walk and this one holds the reads. `ast.zig`
//! re-exports every declaration here, so a rule still writes `ast.token_location`.

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;

/// The longest chain `chain_text` writes, which bounds the buffer a caller owns. A longer chain
/// is reported as no chain at all, which every caller treats as "not a match".
pub const max_chain_bytes: usize = 256;

/// 1-based line and column of a token.
pub const Location = struct {
    line: usize,
    column: usize,
};

pub fn token_location(tree: *const Ast, token: Ast.TokenIndex) Location {
    const location = tree.tokenLocation(0, token);
    return .{ .line = location.line + 1, .column = location.column + 1 };
}

/// Location of a node's main token: the `while` keyword of a loop, the literal of a number, the
/// last field name of a field access.
pub fn node_location(tree: *const Ast, node: Node.Index) Location {
    return token_location(tree, tree.nodeMainToken(node));
}

/// Location of the first token of a node, which for a field-access chain is the root identifier.
pub fn node_start_location(tree: *const Ast, node: Node.Index) Location {
    return token_location(tree, tree.firstToken(node));
}

/// Writes the dotted text of `node` into `buffer` when `node` is an identifier or a chain of
/// field accesses over one, such as `std.time.nanoTimestamp`, and returns it. Returns null for
/// any other expression, so `a().b` and `a[0].b` are not chains, and for a chain longer than the
/// buffer.
pub fn chain_text(tree: *const Ast, node: Node.Index, buffer: *[max_chain_bytes]u8) ?[]const u8 {
    var length: usize = 0;
    var current = node;
    while (tree.nodeTag(current) == .field_access) {
        const left, const name_token = tree.nodeData(current).node_and_token;
        length = prepend_segment(buffer, length, tree.tokenSlice(name_token)) orelse return null;
        current = left;
    }
    if (tree.nodeTag(current) != .identifier) return null;
    const root = tree.tokenSlice(tree.nodeMainToken(current));
    length = prepend_segment(buffer, length, root) orelse return null;
    return buffer[max_chain_bytes - length ..];
}

/// The chain is built right to left, so each segment goes in front of the ones already written,
/// at the end of the buffer, with a dot between it and them. Returns the new length, or null
/// when the segment does not fit.
fn prepend_segment(buffer: *[max_chain_bytes]u8, length: usize, segment: []const u8) ?usize {
    const with_dot = length != 0;
    const dot_bytes: usize = if (with_dot) 1 else 0;
    const new_length = length + segment.len + dot_bytes;
    if (new_length > max_chain_bytes) return null;
    const start = max_chain_bytes - new_length;
    @memcpy(buffer[start .. start + segment.len], segment);
    if (with_dot) buffer[start + segment.len] = '.';
    return new_length;
}

/// The name on the right of the last dot of a chain, or the whole chain when it has no dot.
pub fn last_segment(chain: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, chain, '.') orelse return chain;
    return chain[dot + 1 ..];
}

/// The name on the left of the first dot of a chain, or the whole chain when it has no dot.
pub fn first_segment(chain: []const u8) []const u8 {
    const dot = std.mem.indexOfScalar(u8, chain, '.') orelse return chain;
    return chain[0..dot];
}

/// Iterates the dot-separated segments of a chain, root first.
pub fn segments(chain: []const u8) std.mem.SplitIterator(u8, .scalar) {
    return std.mem.splitScalar(u8, chain, '.');
}

/// True when any segment of the chain equals `wanted`.
pub fn has_segment(chain: []const u8, wanted: []const u8) bool {
    var iterator = segments(chain);
    while (iterator.next()) |segment| {
        if (std.mem.eql(u8, segment, wanted)) return true;
    }
    return false;
}

/// True when `chain` is `prefix` or starts with `prefix` followed by a dot. The dot boundary is
/// what keeps `std.heapish` from matching `std.heap`.
pub fn has_prefix_at_dot(chain: []const u8, prefix: []const u8) bool {
    if (!std.mem.startsWith(u8, chain, prefix)) return false;
    return chain.len == prefix.len or chain[prefix.len] == '.';
}

/// True when `chain` starts at a dot boundary with any of the listed prefixes.
pub fn has_any_prefix_at_dot(chain: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix| {
        if (has_prefix_at_dot(chain, prefix)) return true;
    }
    return false;
}

pub fn is_call(tag: Node.Tag) bool {
    return switch (tag) {
        .call_one, .call_one_comma, .call, .call_comma => true,
        else => false,
    };
}

/// The function expression of a call node.
pub fn callee(tree: *const Ast, node: Node.Index) Node.Index {
    std.debug.assert(is_call(tree.nodeTag(node)));
    var buffer: [1]Node.Index = undefined;
    return tree.fullCall(&buffer, node).?.ast.fn_expr;
}

/// The quoted string of an `@import("...")` node with the quotes removed, or null for any other
/// node. A non-literal argument, `@import(module_name)`, reads as null.
pub fn imported_path(tree: *const Ast, node: Node.Index) ?[]const u8 {
    const argument = switch (tree.nodeTag(node)) {
        .builtin_call_two, .builtin_call_two_comma => tree.nodeData(node)
            .opt_node_and_opt_node[0].unwrap() orelse return null,
        .builtin_call, .builtin_call_comma => blk: {
            const arguments = tree.extraDataSlice(tree.nodeData(node).extra_range, Node.Index);
            if (arguments.len == 0) return null;
            break :blk arguments[0];
        },
        else => return null,
    };
    if (!std.mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(node)), "@import")) return null;
    if (tree.nodeTag(argument) != .string_literal) return null;
    const quoted = tree.tokenSlice(tree.nodeMainToken(argument));
    if (quoted.len < 2) return null;
    return quoted[1 .. quoted.len - 1];
}

// Tests.

const testing = std.testing;

/// Parses `const x = EXPRESSION;` and returns the chain text of the expression, copied into `out`
/// so it outlives the tree.
fn chain_of(expression: []const u8, out: *[max_chain_bytes]u8) !?[]const u8 {
    var source_buffer: [max_chain_bytes * 2]u8 = undefined;
    const source = try std.fmt.bufPrintZ(&source_buffer, "const x = {s};", .{expression});
    var tree = try Ast.parse(testing.allocator, source, .zig);
    defer tree.deinit(testing.allocator);
    const declaration = tree.rootDecls()[0];
    const value = tree.nodeData(declaration).opt_node_and_opt_node[1].unwrap().?;
    var buffer: [max_chain_bytes]u8 = undefined;
    const chain = chain_text(&tree, value, &buffer) orelse return null;
    @memcpy(out[0..chain.len], chain);
    return out[0..chain.len];
}

test "chain_text joins an identifier and its field accesses" {
    var out: [max_chain_bytes]u8 = undefined;
    try testing.expectEqualStrings("std", (try chain_of("std", &out)).?);
    try testing.expectEqualStrings("std.heap.page_allocator", (try chain_of("std.heap.page_allocator", &out)).?);
}

test "chain_text returns null for a call, an index, or a literal in the chain" {
    var out: [max_chain_bytes]u8 = undefined;
    try testing.expectEqual(null, try chain_of("a().b", &out));
    try testing.expectEqual(null, try chain_of("a[0].b", &out));
    try testing.expectEqual(null, try chain_of("1", &out));
}

test "chain_text returns null for a chain longer than the buffer" {
    const long_name = "a" ** (max_chain_bytes + 1);
    var out: [max_chain_bytes]u8 = undefined;
    try testing.expectEqual(null, try chain_of(long_name, &out));
}

test "last_segment and first_segment split a chain at its dots" {
    try testing.expectEqualStrings("nanoTimestamp", last_segment("std.time.nanoTimestamp"));
    try testing.expectEqualStrings("std", first_segment("std.time.nanoTimestamp"));
    try testing.expectEqualStrings("alone", last_segment("alone"));
    try testing.expectEqualStrings("alone", first_segment("alone"));
}

test "has_segment looks at every segment" {
    try testing.expect(has_segment("std.mem.Allocator", "Allocator"));
    try testing.expect(has_segment("Allocator", "Allocator"));
    try testing.expect(!has_segment("std.mem.Allocators", "Allocator"));
}

test "has_prefix_at_dot stops at a dot boundary" {
    try testing.expect(has_prefix_at_dot("std.heap", "std.heap"));
    try testing.expect(has_prefix_at_dot("std.heap.page_allocator", "std.heap"));
    try testing.expect(!has_prefix_at_dot("std.heapish", "std.heap"));
    try testing.expect(!has_prefix_at_dot("std", "std.heap"));
    try testing.expect(has_any_prefix_at_dot("std.posix.socket", &.{ "std.fs", "std.posix" }));
    try testing.expect(!has_any_prefix_at_dot("std.posix.socket", &.{"std.fs"}));
}

test "token_location is 1-based" {
    var tree = try Ast.parse(testing.allocator, "const a = 1;\nconst b = 2;", .zig);
    defer tree.deinit(testing.allocator);
    const second = tree.rootDecls()[1];
    const location = node_location(&tree, second);
    try testing.expectEqual(2, location.line);
    try testing.expectEqual(1, location.column);
}

/// Returns the imported path of the first root declaration's value.
fn import_of(source: [:0]const u8, out: *[max_chain_bytes]u8) !?[]const u8 {
    var tree = try Ast.parse(testing.allocator, source, .zig);
    defer tree.deinit(testing.allocator);
    const declaration = tree.rootDecls()[0];
    const value = tree.nodeData(declaration).opt_node_and_opt_node[1].unwrap().?;
    const path = imported_path(&tree, value) orelse return null;
    @memcpy(out[0..path.len], path);
    return out[0..path.len];
}

test "imported_path reads the literal of @import and nothing else" {
    var out: [max_chain_bytes]u8 = undefined;
    try testing.expectEqualStrings("core", (try import_of("const a = @import(\"core\");", &out)).?);
    try testing.expectEqual(null, try import_of("const a = @embedFile(\"x.bin\");", &out));
    try testing.expectEqual(null, try import_of("const a = @import(module_name);", &out));
    try testing.expectEqual(null, try import_of("const a = @as(u32, 1);", &out));
}
