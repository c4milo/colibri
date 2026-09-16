//! Scores one parsed Zig file against SonarSource's Cognitive Complexity
//! definition. `cognitive_complexity.zig` states the mapping from that
//! definition onto Zig syntax; this file is the walk that applies it.
//!
//! Two walks run over each file. `Collector` records every `fn` declaration
//! with a body and every `test` block, at any container depth. `Scorer` then
//! walks one body and adds one increment per construct, carrying the nesting
//! level down the recursion so that no rule looks back up the tree.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const Node = Ast.Node;
const ast = @import("lint/ast.zig");
const for_each_child = ast.for_each_child;
const max_tree_depth = ast.max_tree_depth;

/// Functions and test blocks recorded per file. A file holding more is
/// reported as an error rather than scored in part.
const max_functions_per_file: usize = 4096;

/// One scored function or test block. `path` and `name` are owned by the
/// arena passed to `score_source`, so a result outlives the parsed tree.
pub const FunctionScore = struct {
    path: []const u8,
    /// 1-based line of the name token.
    line: usize,
    name: []const u8,
    score: u32,
};

pub const ScoreError = error{ ParseFailed, TooManyFunctions, NestingTooDeep } || Allocator.Error;

fn is_block(tag: Node.Tag) bool {
    return tag == .block or tag == .block_semicolon or
        tag == .block_two or tag == .block_two_semicolon;
}

/// Walks a whole tree and records every declaration that carries a body.
const Collector = struct {
    tree: *const Ast,
    declarations: *std.ArrayList(Node.Index),
    depth: u32 = 0,
    truncated: bool = false,
    too_deep: bool = false,

    pub fn child(self: *Collector, node: Node.Index) void {
        if (self.depth >= max_tree_depth) {
            self.too_deep = true;
            return;
        }
        self.depth += 1;
        defer self.depth -= 1;
        const tag = self.tree.nodeTag(node);
        if (tag == .fn_decl or tag == .test_decl) self.record(node);
        for_each_child(self.tree, node, self);
    }

    fn record(self: *Collector, node: Node.Index) void {
        if (self.declarations.items.len >= max_functions_per_file) {
            self.truncated = true;
            return;
        }
        self.declarations.appendAssumeCapacity(node);
    }
};

/// Scores one body. `nesting` travels down the recursion as an argument;
/// `score`, `depth` and `too_deep` are the only mutable state.
const Scorer = struct {
    tree: *const Ast,
    function_name: []const u8,
    score: u32 = 0,
    depth: u32 = 0,
    too_deep: bool = false,

    /// Adapter `for_each_child` calls: every child of a node that carries no
    /// increment keeps its parent's nesting level.
    const ChildVisitor = struct {
        scorer: *Scorer,
        nesting: u32,

        pub fn child(self: ChildVisitor, node: Node.Index) void {
            self.scorer.visit(node, self.nesting);
        }
    };

    /// An `if` written after an `else` adds 1 in total rather than 2, and its
    /// body sits at the level of the first `if`'s body.
    const IfKind = enum { fresh, else_if };

    fn visit(self: *Scorer, node: Node.Index, nesting: u32) void {
        if (self.depth >= max_tree_depth) {
            self.too_deep = true;
            return;
        }
        self.depth += 1;
        defer self.depth -= 1;
        switch (self.tree.nodeTag(node)) {
            .if_simple, .@"if" => self.visit_if(node, nesting, .fresh),
            .while_simple, .while_cont, .@"while" => self.visit_while(node, nesting),
            .for_simple, .@"for" => self.visit_for(node, nesting),
            .@"switch", .switch_comma => self.visit_switch(node, nesting),
            .@"catch" => self.visit_catch(node, nesting),
            .@"orelse" => self.visit_orelse(node, nesting),
            .bool_and, .bool_or => self.visit_logical_sequence(node, nesting),
            .@"break", .@"continue" => self.visit_jump(node, nesting),
            .call_one, .call_one_comma, .call, .call_comma => self.visit_call(node, nesting),
            .fn_decl => self.visit_nested_function(node, nesting),
            else => self.visit_children(node, nesting),
        }
    }

    fn visit_children(self: *Scorer, node: Node.Index, nesting: u32) void {
        for_each_child(self.tree, node, ChildVisitor{ .scorer = self, .nesting = nesting });
    }

    fn visit_if(self: *Scorer, node: Node.Index, nesting: u32, kind: IfKind) void {
        const full_if = self.tree.fullIf(node).?;
        self.score += if (kind == .else_if) 1 else 1 + nesting;
        self.visit(full_if.ast.cond_expr, nesting);
        self.visit_branches(full_if.ast.then_expr, full_if.ast.else_expr, nesting);
    }

    /// The body of a structural construct sits one level deeper. An `else`
    /// adds 1 and raises no level; an `else if` is scored as `.else_if`.
    fn visit_branches(self: *Scorer, then_expr: Node.Index, else_expr: Node.OptionalIndex, nesting: u32) void {
        self.visit(then_expr, nesting + 1);
        const else_node = else_expr.unwrap() orelse return;
        switch (self.tree.nodeTag(else_node)) {
            .if_simple, .@"if" => self.visit_if(else_node, nesting, .else_if),
            else => {
                self.score += 1;
                self.visit(else_node, nesting + 1);
            },
        }
    }

    fn visit_while(self: *Scorer, node: Node.Index, nesting: u32) void {
        const full_while = self.tree.fullWhile(node).?;
        self.score += 1 + nesting;
        self.visit(full_while.ast.cond_expr, nesting);
        if (full_while.ast.cont_expr.unwrap()) |cont_expr| self.visit(cont_expr, nesting + 1);
        self.visit_branches(full_while.ast.then_expr, full_while.ast.else_expr, nesting);
    }

    fn visit_for(self: *Scorer, node: Node.Index, nesting: u32) void {
        const full_for = self.tree.fullFor(node).?;
        self.score += 1 + nesting;
        for (full_for.ast.inputs) |input| self.visit(input, nesting);
        self.visit_branches(full_for.ast.then_expr, full_for.ast.else_expr, nesting);
    }

    /// One increment for the whole switch, never one per prong. Prong bodies
    /// sit one level deeper; prongs add no level of their own.
    fn visit_switch(self: *Scorer, node: Node.Index, nesting: u32) void {
        const full_switch = self.tree.fullSwitch(node).?;
        self.score += 1 + nesting;
        self.visit(full_switch.ast.condition, nesting);
        for (full_switch.ast.cases) |case_node| {
            const case = self.tree.fullSwitchCase(case_node).?;
            for (case.ast.values) |value| self.visit(value, nesting + 1);
            self.visit(case.ast.target_expr, nesting + 1);
        }
    }

    fn visit_catch(self: *Scorer, node: Node.Index, nesting: u32) void {
        const lhs, const rhs = self.tree.nodeData(node).node_and_node;
        self.score += 1 + nesting;
        self.visit(lhs, nesting);
        self.visit(rhs, nesting + 1);
    }

    /// `orelse` whose operand is a block is structural and raises the level.
    /// `orelse return` and the like add 1 and raise no level.
    fn visit_orelse(self: *Scorer, node: Node.Index, nesting: u32) void {
        const lhs, const rhs = self.tree.nodeData(node).node_and_node;
        const structural = is_block(self.tree.nodeTag(rhs));
        self.score += if (structural) 1 + nesting else 1;
        self.visit(lhs, nesting);
        self.visit(rhs, if (structural) nesting + 1 else nesting);
    }

    /// One increment for a whole run of like operators. An operand joined by
    /// the same operator continues the run; any other operand starts a new
    /// expression, and a run inside it is counted on its own.
    fn visit_logical_sequence(self: *Scorer, node: Node.Index, nesting: u32) void {
        self.score += 1;
        self.visit_logical_operands(node, self.tree.nodeTag(node), nesting);
    }

    fn visit_logical_operands(self: *Scorer, node: Node.Index, operator: Node.Tag, nesting: u32) void {
        const lhs, const rhs = self.tree.nodeData(node).node_and_node;
        for ([_]Node.Index{ lhs, rhs }) |operand| {
            if (self.tree.nodeTag(operand) == operator) {
                self.visit_logical_operands(operand, operator, nesting);
            } else {
                self.visit(operand, nesting);
            }
        }
    }

    /// A `break` or `continue` that names a label adds 1. An unlabelled one
    /// adds nothing.
    fn visit_jump(self: *Scorer, node: Node.Index, nesting: u32) void {
        const label, const target = self.tree.nodeData(node).opt_token_and_opt_node;
        if (label != .none) self.score += 1;
        if (target.unwrap()) |target_node| self.visit(target_node, nesting);
    }

    fn visit_call(self: *Scorer, node: Node.Index, nesting: u32) void {
        var buffer: [1]Node.Index = undefined;
        const call = self.tree.fullCall(&buffer, node).?;
        if (self.is_recursive_callee(call.ast.fn_expr)) self.score += 1;
        self.visit(call.ast.fn_expr, nesting);
        for (call.ast.params) |param| self.visit(param, nesting);
    }

    /// A call through a field access (`self.name()`) adds nothing: the tool
    /// has no type information and cannot tell which function that names.
    fn is_recursive_callee(self: *const Scorer, callee: Node.Index) bool {
        if (self.tree.nodeTag(callee) != .identifier) return false;
        const callee_name = self.tree.tokenSlice(self.tree.nodeMainToken(callee));
        return std.mem.eql(u8, callee_name, self.function_name);
    }

    /// A function declared inside a body is scored twice: on its own, by the
    /// collector, and here as part of the enclosing body one level deeper.
    fn visit_nested_function(self: *Scorer, node: Node.Index, nesting: u32) void {
        const proto, const body = self.tree.nodeData(node).node_and_node;
        self.visit_children(proto, nesting);
        self.visit(body, nesting + 1);
    }
};

/// The name token and the body of one declaration. A `test` block with no name
/// is named by its own keyword.
fn name_and_body(tree: *const Ast, node: Node.Index) ?struct { Ast.TokenIndex, Node.Index } {
    if (tree.nodeTag(node) == .test_decl) {
        const name, const body = tree.nodeData(node).opt_token_and_node;
        return .{ name.unwrap() orelse tree.nodeMainToken(node), body };
    }
    var buffer: [1]Node.Index = undefined;
    const proto = tree.fullFnProto(&buffer, node).?;
    _, const body = tree.nodeData(node).node_and_node;
    return .{ proto.name_token orelse return null, body };
}

/// Scores one `fn_decl` or `test_decl` node, and sets `too_deep` when the body
/// nests past `max_tree_depth`. Returns null for a function declaration with no
/// name token, which the parser produces only for a prototype, and a prototype
/// has no body to score.
fn score_declaration(tree: *const Ast, node: Node.Index, too_deep: *bool) ?FunctionScore {
    const name_token, const body = name_and_body(tree, node) orelse return null;
    const name = tree.tokenSlice(name_token);
    var scorer: Scorer = .{ .tree = tree, .function_name = name };
    scorer.visit(body, 0);
    if (scorer.too_deep) too_deep.* = true;
    return .{
        .path = "",
        .line = tree.tokenLocation(0, name_token).line + 1,
        .name = name,
        .score = scorer.score,
    };
}

/// Parses `source` and scores every function and test block in it. `path` and
/// each name are copied into `arena`, so the results outlive `source`.
pub fn score_source(arena: Allocator, path: []const u8, source: [:0]const u8) ScoreError![]FunctionScore {
    var tree = try Ast.parse(arena, source, .zig);
    defer tree.deinit(arena);
    if (tree.errors.len != 0) return error.ParseFailed;

    var declarations: std.ArrayList(Node.Index) = .empty;
    defer declarations.deinit(arena);
    try declarations.ensureTotalCapacity(arena, max_functions_per_file);
    var collector: Collector = .{ .tree = &tree, .declarations = &declarations };
    for (tree.rootDecls()) |declaration| collector.child(declaration);
    if (collector.truncated) return error.TooManyFunctions;
    if (collector.too_deep) return error.NestingTooDeep;

    const owned_path = try arena.dupe(u8, path);
    var too_deep = false;
    var results: std.ArrayList(FunctionScore) = .empty;
    try results.ensureTotalCapacity(arena, declarations.items.len);
    for (declarations.items) |declaration| {
        var result = score_declaration(&tree, declaration, &too_deep) orelse continue;
        result.path = owned_path;
        result.name = try arena.dupe(u8, result.name);
        results.appendAssumeCapacity(result);
    }
    if (too_deep) return error.NestingTooDeep;
    return results.items;
}

const testing = std.testing;

/// Scores `source` and returns the score of the one declaration in it.
fn score_of(source: [:0]const u8) !u32 {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const scores = try score_source(arena_state.allocator(), "test.zig", source);
    try testing.expectEqual(@as(usize, 1), scores.len);
    return scores[0].score;
}

test "a function with no branches scores zero" {
    try testing.expectEqual(0, try score_of(
        \\fn add(a: u32, b: u32) u32 {
        \\    const sum = a + b;
        \\    return sum;
        \\}
    ));
}

test "nesting adds the level to each structural increment" {
    // for 1, the if inside it 1+1, the if inside that 1+2: 6.
    try testing.expectEqual(6, try score_of(
        \\fn scan(items: []const u8, flag: bool) void {
        \\    for (items) |item| {
        \\        if (item == 0) {
        \\            if (flag) unreachable;
        \\        }
        \\    }
        \\}
    ));
    // A `while` continue expression sits one level deeper too: while 1, the
    // `if` in the continue expression 1+1, its `else` 1: 4.
    try testing.expectEqual(4, try score_of(
        \\fn count(limit: u32, flag: bool) void {
        \\    var index: u32 = 0;
        \\    while (index < limit) : (index += if (flag) 1 else 2) {}
        \\}
    ));
}

test "else adds one and else if adds one in total" {
    // if 1, else-if 1, else 1: 3.
    try testing.expectEqual(3, try score_of(
        \\fn pick(n: u32) u32 {
        \\    if (n == 0) {
        \\        return 1;
        \\    } else if (n == 1) {
        \\        return 2;
        \\    } else {
        \\        return 3;
        \\    }
        \\}
    ));
    // The same chain one level deep: for 1, if 1+1, else-if 1, else 1 = 5.
    // Scoring the `else if` as a fresh `if` would make it 1+1 and the total 6,
    // which is what tells the two readings apart.
    try testing.expectEqual(5, try score_of(
        \\fn pick(items: []const u8, n: u32) u32 {
        \\    for (items) |_| {
        \\        if (n == 0) {
        \\            return 1;
        \\        } else if (n == 1) {
        \\            return 2;
        \\        } else {
        \\            return 3;
        \\        }
        \\    }
        \\    return 0;
        \\}
    ));
}

test "orelse and catch score by whether the operand is a block" {
    // `orelse return` 1, `catch` 1: 2.
    try testing.expectEqual(2, try score_of(
        \\fn read(value: ?u32, fallible: anytype) !u32 {
        \\    const unwrapped = value orelse return error.Missing;
        \\    const caught = fallible.call() catch 0;
        \\    return unwrapped + caught;
        \\}
    ));
    // `orelse` with a block operand is structural, so it is 1 + nesting, and
    // the `if` inside the block sits one level deeper: 1 + (1 + 1) = 3.
    try testing.expectEqual(3, try score_of(
        \\fn read(value: ?u32, flag: bool) u32 {
        \\    return value orelse {
        \\        if (flag) return 1;
        \\        return 0;
        \\    };
        \\}
    ));
    // Every `catch` is structural, so its operand nests the same way: 3.
    try testing.expectEqual(3, try score_of(
        \\fn read(fallible: anytype, flag: bool) u32 {
        \\    return fallible.call() catch {
        \\        if (flag) return 1;
        \\        return 0;
        \\    };
        \\}
    ));
}

/// Scores `expression` as the whole body of a function taking four booleans.
fn score_boolean(comptime expression: []const u8) !u32 {
    return score_of("fn all(a: bool, b: bool, c: bool, d: bool) bool { return " ++ expression ++ "; }");
}

test "a sequence of like boolean operators adds one" {
    try testing.expectEqual(1, try score_boolean("a and b and c"));
    // The operator changes once, so there are two sequences.
    try testing.expectEqual(2, try score_boolean("a and b or c"));
    // Parentheses start a new expression, so this is two sequences as well.
    try testing.expectEqual(2, try score_boolean("a and (b and c)"));
    // Read by precedence this is one `or` run holding one `and` run, so 2.
    // Read token by token the operator changes twice and it would be 3.
    try testing.expectEqual(2, try score_boolean("a or b and c or d"));
}

test "a labelled break adds one and an unlabelled break adds nothing" {
    // while 1, if 1+1, labelled break 1, unlabelled break 0: 4.
    try testing.expectEqual(4, try score_of(
        \\fn search(items: []const u8) void {
        \\    outer: while (true) {
        \\        if (items.len == 0) break :outer;
        \\        break;
        \\    }
        \\}
    ));
}

test "a switch scores once and its prongs sit one level deeper" {
    // switch 1, the if in a prong 1+1: 3.
    try testing.expectEqual(3, try score_of(
        \\fn classify(tag: u8, flag: bool) u8 {
        \\    switch (tag) {
        \\        0 => return 1,
        \\        1 => if (flag) return 2,
        \\        else => return 3,
        \\    }
        \\}
    ));
}

test "a call to the enclosing function adds one" {
    // if 1, the recursive call 1: 2.
    try testing.expectEqual(2, try score_of(
        \\fn factorial(n: u32) u32 {
        \\    if (n == 0) return 1;
        \\    return n * factorial(n - 1);
        \\}
    ));
}

test "a test block is scored under the same rules as a function" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const scores = try score_source(arena_state.allocator(), "test.zig",
        \\test "counts its branches" {
        \\    if (true) { if (true) {} }
        \\}
    );
    try testing.expectEqual(@as(usize, 1), scores.len);
    try testing.expectEqualStrings("\"counts its branches\"", scores[0].name);
    try testing.expectEqual(@as(u32, 3), scores[0].score);
    try testing.expectEqual(@as(usize, 1), scores[0].line);
}

test "a function inside a container inside a function is scored on its own" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const scores = try score_source(arena_state.allocator(), "test.zig",
        \\fn outer(flag: bool) void {
        \\    const Helper = struct {
        \\        fn inner(f: bool) void {
        \\            if (f) {}
        \\        }
        \\    };
        \\    if (flag) Helper.inner(flag);
        \\}
    );
    try testing.expectEqual(@as(usize, 2), scores.len);
    // `outer`: its own `if` 1, plus `inner`'s `if` one level deeper 1+1 = 3.
    try testing.expectEqualStrings("outer", scores[0].name);
    try testing.expectEqual(@as(u32, 3), scores[0].score);
    try testing.expectEqualStrings("inner", scores[1].name);
    try testing.expectEqual(@as(u32, 1), scores[1].score);
}

test "a source the parser rejects is reported rather than scored" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.ParseFailed, score_source(
        arena_state.allocator(),
        "test.zig",
        "fn broken( {",
    ));
}
