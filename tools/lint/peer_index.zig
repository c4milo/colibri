//! peer-index: colibri never slices or indexes with a value the peer chose, outside the reader and
//! writer (invariant 3). All parsing goes through `core.Reader` and all output through
//! `core.Writer`, which check every bound. The violation invariant 3 names is a parser that reads
//! a length, then slices with it, and checks the length afterwards.
//!
//! Over every `.zig` file under `src/`, but for `src/core/reader.zig` and `src/core/writer.zig`,
//! the rule reads each function on its own and follows the values a `Reader` produced:
//!
//! 1. A value is peer-derived when it is a parameter whose type names `Reader`, or a local whose
//!    type names `Reader` or whose value calls `Reader.init`.
//! 2. A name declared, assigned or captured from an expression that reads a peer-derived name is
//!    peer-derived too: `const len = try reader.read_int(u16);`, `total += len;`,
//!    `if (reader.peek()) |octet|`. A `for` capture follows its own input, so in
//!    `for (octets, 0..) |octet, index|` the octet is peer-derived and the index is not.
//! 3. A `[...]` index, or a slice's start, end or sentinel, that reads a peer-derived name is a
//!    finding.
//!
//! `name.len` does not read `name`. A slice the reader returned is bounded by the memory it covers,
//! so its length is not a value the peer chose. `test` blocks are not read.
//!
//! What the rule cannot see. It follows names within one function, so a peer-derived value passed
//! to another function as an argument arrives there clean. It does not follow scopes, so a name
//! reused in a later block stays peer-derived. It reads names, not types, so a value derived from
//! a `Reader` held in a struct field is invisible. The fuzzing of every parser, and the assertion
//! at every reader and writer entry, cover what a name-based reading cannot.
//!
//! This rule is colibri's own, written against pepegrillo's readers (decision 36).

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const ast = lint.ast;
const report = lint.report;
const Scope = lint.Scope;

pub const name = "peer-index";

/// The files the rule reads.
pub const scope: Scope = .{
    .extensions = &.{lint.paths.zig_extension},
    .include_directories = &.{"src"},
    .exclude_paths = &.{ "src/core/reader.zig", "src/core/writer.zig" },
};

/// The type whose values the rule follows, and the call that makes one.
const reader_type = "Reader";
const reader_constructor = "init";

/// The field whose read does not read the value it belongs to.
const length_field = "len";

/// Most peer-derived names one function holds. A function past it stops the run with an error
/// rather than being read wrong.
const names_max: usize = 128;

pub fn check(context: *report.Context, file: report.File) !void {
    if (!scope.applies(file.path)) return;
    const tree = file.tree orelse return;
    var visitor: Visitor = .{ .tree = tree, .findings = &context.findings, .path = file.path };
    for (tree.rootDecls()) |declaration| visitor.child(declaration);
    if (visitor.failure) |failure| return failure;
}

const Visitor = struct {
    tree: *const Ast,
    findings: *report.Findings,
    path: []const u8,
    names: [names_max][]const u8 = undefined,
    count: usize = 0,
    depth: u32 = 0,
    failure: ?anyerror = null,

    pub fn child(self: *Visitor, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        self.visit(node) catch |failure| {
            self.failure = failure;
        };
    }

    fn visit(self: *Visitor, node: Node.Index) !void {
        switch (self.tree.nodeTag(node)) {
            .test_decl => return,
            .fn_decl => return self.visit_function(node),
            .array_access => try self.check_index(node, self.tree.nodeData(node).node_and_node[1]),
            .slice_open, .slice, .slice_sentinel => try self.check_slice(node),
            else => try self.follow(node),
        }
        ast.for_each_child(self.tree, node, self);
    }

    /// Reads one function with no peer-derived name but its own.
    fn visit_function(self: *Visitor, node: Node.Index) !void {
        const saved = self.count;
        defer self.count = saved;
        self.count = 0;
        var buffer: [1]Node.Index = undefined;
        const prototype_node = self.tree.nodeData(node).node_and_node[0];
        const prototype = self.tree.fullFnProto(&buffer, prototype_node).?;
        var parameters = prototype.iterate(self.tree);
        while (parameters.next()) |parameter| {
            const type_expression = parameter.type_expr orelse continue;
            const name_token = parameter.name_token orelse continue;
            if (self.names_reader(type_expression)) try self.add(name_token);
        }
        self.child(self.tree.nodeData(node).node_and_node[1]);
    }

    /// Marks the names a declaration, an assignment or a capture takes from a peer-derived value.
    fn follow(self: *Visitor, node: Node.Index) !void {
        if (self.tree.fullVarDecl(node)) |declaration| return self.follow_declaration(declaration);
        if (is_assignment(self.tree.nodeTag(node))) return self.follow_assignment(node);
        if (self.tree.fullFor(node)) |full_for| return self.follow_for(full_for);
        const condition, const payload = self.condition_and_payload(node) orelse return;
        if (self.reads_peer(condition)) try self.add_payload(payload);
    }

    /// Marks each capture of a `for` whose own input is peer-derived: the n-th name captures the
    /// n-th input.
    fn follow_for(self: *Visitor, full_for: Ast.full.For) !void {
        const inputs = full_for.ast.inputs;
        var token = full_for.payload_token;
        var input_index: usize = 0;
        while (token < self.tree.tokens.len and input_index < inputs.len) : (token += 1) {
            switch (self.tree.tokenTag(token)) {
                .identifier => {
                    if (self.reads_peer(inputs[input_index])) try self.add(token);
                    input_index += 1;
                },
                .comma, .asterisk => {},
                else => return,
            }
        }
    }

    fn follow_declaration(self: *Visitor, declaration: Ast.full.VarDecl) !void {
        const name_token = declaration.ast.mut_token + 1;
        if (declaration.ast.type_node.unwrap()) |type_node| {
            if (self.names_reader(type_node)) return self.add(name_token);
        }
        const value = declaration.ast.init_node.unwrap() orelse return;
        if (self.reads_peer(value)) try self.add(name_token);
    }

    fn follow_assignment(self: *Visitor, node: Node.Index) !void {
        const target, const value = self.tree.nodeData(node).node_and_node;
        if (self.tree.nodeTag(target) != .identifier) return;
        if (self.reads_peer(value)) try self.add(self.tree.nodeMainToken(target));
    }

    /// The condition and the first payload token of an `if` or a `while` that captures one.
    fn condition_and_payload(self: *Visitor, node: Node.Index) ?ConditionAndPayload {
        if (self.tree.fullIf(node)) |full_if| {
            return .{ full_if.ast.cond_expr, full_if.payload_token orelse return null };
        }
        if (self.tree.fullWhile(node)) |full_while| {
            return .{ full_while.ast.cond_expr, full_while.payload_token orelse return null };
        }
        return null;
    }

    fn check_slice(self: *Visitor, node: Node.Index) !void {
        const slice = self.tree.fullSlice(node).?;
        try self.check_index(node, slice.ast.start);
        if (slice.ast.end.unwrap()) |end| try self.check_index(node, end);
        if (slice.ast.sentinel.unwrap()) |sentinel| try self.check_index(node, sentinel);
    }

    fn check_index(self: *Visitor, node: Node.Index, index: Node.Index) !void {
        var reads: Reads = .{ .visitor = self };
        reads.child(index);
        const found = reads.found orelse return;
        const location = ast.node_location(self.tree, node);
        try self.findings.add(
            name,
            self.path,
            location.line,
            location.column,
            "index reads {s}, which a Reader produced; take the octets through core.Reader," ++
                " which checks the bound (invariant 3)",
            .{found},
        );
    }

    fn reads_peer(self: *Visitor, node: Node.Index) bool {
        var reads: Reads = .{ .visitor = self };
        reads.child(node);
        return reads.found != null;
    }

    /// True when the type expression names `Reader` in any of its tokens: `Reader`, `*Reader`,
    /// `*core.Reader`.
    fn names_reader(self: *Visitor, type_expression: Node.Index) bool {
        const first = self.tree.firstToken(type_expression);
        const last = self.tree.lastToken(type_expression);
        for (first..last + 1) |token| {
            if (std.mem.eql(u8, self.tree.tokenSlice(@intCast(token)), reader_type)) return true;
        }
        return false;
    }

    /// Marks every name in an `if` or `while` capture: `|octet|`, `|*octet|`.
    fn add_payload(self: *Visitor, payload_token: Ast.TokenIndex) !void {
        var token = payload_token;
        while (token < self.tree.tokens.len) : (token += 1) {
            switch (self.tree.tokenTag(token)) {
                .identifier => try self.add(token),
                .comma, .asterisk => {},
                else => return,
            }
        }
    }

    fn add(self: *Visitor, name_token: Ast.TokenIndex) !void {
        const token_name = self.tree.tokenSlice(name_token);
        if (self.holds(token_name)) return;
        if (self.count == names_max) return error.PeerNamesOverflow;
        self.names[self.count] = token_name;
        self.count += 1;
    }

    fn holds(self: *const Visitor, candidate: []const u8) bool {
        for (self.names[0..self.count]) |held| {
            if (std.mem.eql(u8, held, candidate)) return true;
        }
        return false;
    }
};

/// Walks an expression for the first name it reads that is peer-derived, or a `Reader.init` call.
const Reads = struct {
    visitor: *const Visitor,
    found: ?[]const u8 = null,
    depth: u32 = 0,

    pub fn child(self: *Reads, node: Node.Index) void {
        if (self.found != null) return;
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        const tree = self.visitor.tree;
        switch (tree.nodeTag(node)) {
            .identifier => {
                const identifier = tree.tokenSlice(tree.nodeMainToken(node));
                if (self.visitor.holds(identifier)) self.found = identifier;
                return;
            },
            .field_access => if (self.reads_field(node)) return,
            else => {},
        }
        ast.for_each_child(tree, node, self);
    }

    /// Handles a field access and returns true when it reads nothing more: `name.len`, or
    /// `Reader.init`, which it records.
    fn reads_field(self: *Reads, node: Node.Index) bool {
        const tree = self.visitor.tree;
        const object, const field_token = tree.nodeData(node).node_and_token;
        const field = tree.tokenSlice(field_token);
        if (std.mem.eql(u8, field, length_field)) return true;
        if (!std.mem.eql(u8, field, reader_constructor)) return false;
        const object_name = tree.tokenSlice(tree.lastToken(object));
        if (!std.mem.eql(u8, object_name, reader_type)) return false;
        self.found = reader_type ++ "." ++ reader_constructor;
        return true;
    }
};

const ConditionAndPayload = struct { Node.Index, Ast.TokenIndex };

fn is_assignment(tag: Node.Tag) bool {
    return switch (tag) {
        .assign,
        .assign_add,
        .assign_add_wrap,
        .assign_add_sat,
        .assign_sub,
        .assign_sub_wrap,
        .assign_sub_sat,
        .assign_mul,
        .assign_mul_wrap,
        .assign_mul_sat,
        .assign_div,
        .assign_mod,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_or,
        .assign_bit_xor,
        => true,
        else => false,
    };
}

test {
    _ = @import("peer_index_test.zig");
}
