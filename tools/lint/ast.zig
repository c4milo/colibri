//! Generic child visitor over `std.zig.Ast`, shared by every rule that walks a parsed Zig file.
//!
//! `for_each_child` hands every child of one node to `visitor.child`, and the visitor decides
//! whether to descend. Sub-expressions it does not hand over: pointer type qualifiers (`align`,
//! sentinel, address space), a function prototype's `align`, `addrspace`, `linksection` and
//! `callconv` expressions, the variables on the left of a destructuring assignment, and `asm`
//! operands. Every other child of every node is handed over.
//!
//! A function prototype's parameter types are handed over. The `io` and `determinism` rules read
//! parameter types — `fn send(socket: std.posix.socket_t) void` names a forbidden type there and
//! nowhere else — so the walk descends into them.
//!
//! The readers of `ast_read.zig` are re-exported at the bottom, so a rule imports this file alone.

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const ast_read = @import("ast_read.zig");

/// Deepest AST node a visitor recurses into. Recursion depth is bounded by the source's
/// syntactic nesting, and this is the ceiling on that.
pub const max_tree_depth: u32 = 512;

/// Every scanned node passes through `for_each_child`, which hands each child node to
/// `visitor.child`. The visitor decides whether to descend further.
pub fn for_each_child(tree: *const Ast, node: Node.Index, visitor: anytype) void {
    const data = tree.nodeData(node);
    switch (tree.nodeTag(node)) {
        .root,
        .identifier,
        .number_literal,
        .string_literal,
        .multiline_string_literal,
        .char_literal,
        .enum_literal,
        .error_value,
        .error_set_decl,
        .anyframe_literal,
        .unreachable_literal,
        => {},

        .@"defer",
        .@"comptime",
        .@"nosuspend",
        .@"suspend",
        .@"resume",
        .deref,
        .bool_not,
        .negation,
        .negation_wrap,
        .bit_not,
        .address_of,
        .@"try",
        .optional_type,
        => visitor.child(data.node),

        .@"return" => visit_optional(visitor, data.opt_node),

        .@"catch",
        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_add,
        .assign_sub,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_xor,
        .assign_bit_or,
        .assign_mul_wrap,
        .assign_add_wrap,
        .assign_sub_wrap,
        .assign_mul_sat,
        .assign_add_sat,
        .assign_sub_sat,
        .assign,
        .merge_error_sets,
        .mul,
        .div,
        .mod,
        .array_mult,
        .mul_wrap,
        .mul_sat,
        .add,
        .sub,
        .array_cat,
        .add_wrap,
        .sub_wrap,
        .add_sat,
        .sub_sat,
        .shl,
        .shl_sat,
        .shr,
        .bit_and,
        .bit_xor,
        .bit_or,
        .@"orelse",
        .bool_and,
        .bool_or,
        .error_union,
        .array_type,
        .array_access,
        .array_init_one,
        .array_init_one_comma,
        .slice_open,
        .switch_range,
        .container_field_align,
        .if_simple,
        .while_simple,
        .for_simple,
        .fn_decl,
        => visit_pair(visitor, data.node_and_node),

        .for_range,
        .call_one,
        .call_one_comma,
        .struct_init_one,
        .struct_init_one_comma,
        .container_field_init,
        .aligned_var_decl,
        => {
            visitor.child(data.node_and_opt_node[0]);
            visit_optional(visitor, data.node_and_opt_node[1]);
        },

        .switch_case_one,
        .switch_case_inline_one,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        => {
            visit_optional(visitor, data.opt_node_and_node[0]);
            visitor.child(data.opt_node_and_node[1]);
        },

        .simple_var_decl,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        .block_two,
        .block_two_semicolon,
        .container_decl_two,
        .container_decl_two_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        => {
            visit_optional(visitor, data.opt_node_and_opt_node[0]);
            visit_optional(visitor, data.opt_node_and_opt_node[1]);
        },

        .fn_proto_simple,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto,
        => {
            var buffer: [1]Node.Index = undefined;
            const prototype = tree.fullFnProto(&buffer, node).?;
            visit_slice(visitor, prototype.ast.params);
            visit_optional(visitor, prototype.ast.return_type);
        },

        .field_access,
        .unwrap_optional,
        .grouped_expression,
        .asm_simple,
        .asm_input,
        => visitor.child(data.node_and_token[0]),

        .asm_output => visit_optional(visitor, data.opt_node_and_token[0]),
        .test_decl, .@"errdefer" => visitor.child(data.opt_token_and_node[1]),
        .anyframe_type => visitor.child(data.token_and_node[1]),
        .@"break", .@"continue" => visit_optional(visitor, data.opt_token_and_opt_node[1]),

        .array_init_dot,
        .array_init_dot_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .builtin_call,
        .builtin_call_comma,
        .block,
        .block_semicolon,
        .container_decl,
        .container_decl_trailing,
        .tagged_union,
        .tagged_union_trailing,
        => visit_slice(visitor, tree.extraDataSlice(data.extra_range, Node.Index)),

        .array_init,
        .array_init_comma,
        .struct_init,
        .struct_init_comma,
        .call,
        .call_comma,
        .@"switch",
        .switch_comma,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => {
            visitor.child(data.node_and_extra[0]);
            const range = tree.extraData(data.node_and_extra[1], Node.SubRange);
            visit_slice(visitor, tree.extraDataSlice(range, Node.Index));
        },

        .slice => {
            const extra = tree.extraData(data.node_and_extra[1], Node.Slice);
            visitor.child(data.node_and_extra[0]);
            visitor.child(extra.start);
            visitor.child(extra.end);
        },
        .slice_sentinel => {
            const extra = tree.extraData(data.node_and_extra[1], Node.SliceSentinel);
            visitor.child(data.node_and_extra[0]);
            visitor.child(extra.start);
            visit_optional(visitor, extra.end);
            visitor.child(extra.sentinel);
        },
        .array_type_sentinel => {
            const extra = tree.extraData(data.node_and_extra[1], Node.ArrayTypeSentinel);
            visitor.child(data.node_and_extra[0]);
            visitor.child(extra.sentinel);
            visitor.child(extra.elem_type);
        },
        .container_field => {
            const extra = tree.extraData(data.node_and_extra[1], Node.ContainerField);
            visitor.child(data.node_and_extra[0]);
            visitor.child(extra.align_expr);
            visitor.child(extra.value_expr);
        },
        .@"asm" => visitor.child(data.node_and_extra[0]),

        .switch_case, .switch_case_inline => {
            const range = tree.extraData(data.extra_and_node[0], Node.SubRange);
            visit_slice(visitor, tree.extraDataSlice(range, Node.Index));
            visitor.child(data.extra_and_node[1]);
        },
        .assign_destructure,
        .ptr_type,
        .ptr_type_bit_range,
        => visitor.child(data.extra_and_node[1]),

        .global_var_decl => {
            const extra = tree.extraData(data.extra_and_opt_node[0], Node.GlobalVarDecl);
            visit_optional(visitor, extra.type_node);
            visit_optional(visitor, data.extra_and_opt_node[1]);
        },
        .local_var_decl => {
            const extra = tree.extraData(data.extra_and_opt_node[0], Node.LocalVarDecl);
            visitor.child(extra.type_node);
            visit_optional(visitor, data.extra_and_opt_node[1]);
        },
        .while_cont => {
            const extra = tree.extraData(data.node_and_extra[1], Node.WhileCont);
            visitor.child(data.node_and_extra[0]);
            visitor.child(extra.cont_expr);
            visitor.child(extra.then_expr);
        },
        .@"while" => {
            const extra = tree.extraData(data.node_and_extra[1], Node.While);
            visitor.child(data.node_and_extra[0]);
            visit_optional(visitor, extra.cont_expr);
            visitor.child(extra.then_expr);
            visitor.child(extra.else_expr);
        },
        .@"if" => {
            const extra = tree.extraData(data.node_and_extra[1], Node.If);
            visitor.child(data.node_and_extra[0]);
            visitor.child(extra.then_expr);
            visitor.child(extra.else_expr);
        },
        .@"for" => {
            const full_for = tree.forFull(node);
            visit_slice(visitor, full_for.ast.inputs);
            visitor.child(full_for.ast.then_expr);
            visit_optional(visitor, full_for.ast.else_expr);
        },
    }
}

pub fn visit_optional(visitor: anytype, node: Node.OptionalIndex) void {
    const index = node.unwrap() orelse return;
    visitor.child(index);
}

pub fn visit_pair(visitor: anytype, pair: struct { Node.Index, Node.Index }) void {
    visitor.child(pair[0]);
    visitor.child(pair[1]);
}

pub fn visit_slice(visitor: anytype, nodes: []const Node.Index) void {
    for (nodes) |node| visitor.child(node);
}

pub fn is_while(tag: Node.Tag) bool {
    return switch (tag) {
        .while_simple, .while_cont, .@"while" => true,
        else => false,
    };
}

// The readers of `ast_read.zig`, re-exported so a rule reaches the whole surface through this
// file: it is the entry point every rule imports.

pub const max_chain_bytes = ast_read.max_chain_bytes;
pub const Location = ast_read.Location;
pub const token_location = ast_read.token_location;
pub const node_location = ast_read.node_location;
pub const node_start_location = ast_read.node_start_location;
pub const chain_text = ast_read.chain_text;
pub const last_segment = ast_read.last_segment;
pub const first_segment = ast_read.first_segment;
pub const segments = ast_read.segments;
pub const has_segment = ast_read.has_segment;
pub const has_prefix_at_dot = ast_read.has_prefix_at_dot;
pub const has_any_prefix_at_dot = ast_read.has_any_prefix_at_dot;
pub const is_call = ast_read.is_call;
pub const callee = ast_read.callee;
pub const imported_path = ast_read.imported_path;

// Tests.

const testing = std.testing;

/// Counts every node under the root declarations of `source`.
fn count_nodes(source: [:0]const u8) !usize {
    var tree = try Ast.parse(testing.allocator, source, .zig);
    defer tree.deinit(testing.allocator);
    const Counter = struct {
        tree: *const Ast,
        count: usize = 0,
        fn child(self: *@This(), node: Node.Index) void {
            self.count += 1;
            for_each_child(self.tree, node, self);
        }
    };
    var counter: Counter = .{ .tree = &tree };
    for (tree.rootDecls()) |declaration| counter.child(declaration);
    return counter.count;
}

test "for_each_child reaches every node of a declaration, parameter types included" {
    // fn_decl, fn_proto_multi, the two parameter type identifiers, the return type identifier,
    // block, the return, the add, and its two operands: 10 nodes.
    try testing.expectEqual(10, count_nodes(
        \\fn add(a: u32, b: u32) u32 {
        \\    return a + b;
        \\}
    ));
}

test "is_while names the three while shapes" {
    try testing.expect(is_while(.while_simple));
    try testing.expect(is_while(.while_cont));
    try testing.expect(is_while(.@"while"));
    try testing.expect(!is_while(.for_simple));
    try testing.expect(!is_while(.if_simple));
}

test {
    _ = ast_read;
}
