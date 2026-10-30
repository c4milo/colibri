//! The methods of a route table as bits, and the Allow value of each set of them (decision 128,
//! design §8 step 13h). A walk joins the masks of the leaves it reaches, and when none of them
//! serves the method, its 405 carries the Allow value of the joined mask (RFC 9110 §15.5.6).
//! Everything here but `bit_of`, `wanted_of` and the lookup of a value is built at compile time.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const router_method = @import("router_method.zig");

/// A set of the table's methods: bit `i` is the method at place `i` of `Allows.order`.
pub const Mask = u16;

/// The separator between the methods of an Allow value: RFC 9110 §10.2.1 makes Allow a list, and
/// RFC 9110 §5.6.1.1 writes a list as `element *( OWS "," OWS element )`.
const separator = ", ";

/// The bits of `layout`'s methods, each leaf's mask, and the Allow value of each mask. A table
/// that names more than `route_methods_max` methods does not reach this: `methods_too_many`.
/// Comptime-only.
pub fn Allows(comptime layout: anytype) type {
    const count = layout.methods.len;
    assert(count > 0 and count <= constants.limits.route_methods_max);
    return struct {
        /// The table's method tokens in decision 122 ruling 11's order: RFC 9110 §9.1's methods in
        /// its order, then each token by octets.
        pub const order: [count][]const u8 = order_of(layout);
        /// The methods of each leaf.
        pub const leaf_masks: [layout.leaves.len]Mask = leaf_masks_of(layout, &order);
        /// The Allow value of each mask.
        pub const values: [1 << count][]const u8 = values_of(&order);
        /// The bit of GET, or 0 when no route names GET: GET serves HEAD (RFC 9110 §9.3.2).
        pub const get_bit: Mask = bit_of_token(&order, router_method.get_token);
    };
}

/// The bit of `method` in `order`, or 0 when no route names it.
pub fn bit_of(order: []const []const u8, method: []const u8) Mask {
    for (order, 0..) |token, index| {
        // RFC 9110 §9.1: the method token is case-sensitive.
        if (std.mem.eql(u8, token, method)) return @as(Mask, 1) << @intCast(index);
    }
    return 0;
}

fn bit_of_token(comptime order: []const []const u8, comptime token: []const u8) Mask {
    @setEvalBranchQuota(order_quota);
    return bit_of(order, token);
}

/// The methods whose leaf serves a request of `method`: the method itself, and GET for a HEAD
/// request (RFC 9110 §9.1, §9.3.2). 0 when no route names it.
pub fn wanted_of(comptime layout: anytype, method: []const u8) Mask {
    const A = Allows(layout);
    const bit = bit_of(&A.order, method);
    if (std.mem.eql(u8, method, router_method.head_token)) return bit | A.get_bit;
    return bit;
}

fn rank_of(token: []const u8) usize {
    const standard = http.method.standard(token) orelse return @typeInfo(http.method.Standard).@"enum".fields.len;
    return @intFromEnum(standard);
}

fn token_less(_: void, left: []const u8, right: []const u8) bool {
    if (rank_of(left) != rank_of(right)) return rank_of(left) < rank_of(right);
    return std.mem.lessThan(u8, left, right);
}

fn order_of(comptime layout: anytype) [layout.methods.len][]const u8 {
    @setEvalBranchQuota(order_quota);
    var order: [layout.methods.len][]const u8 = undefined;
    for (layout.methods, 0..) |range, index| order[index] = layout.text[range.offset..][0..range.len];
    std.mem.sort([]const u8, &order, {}, token_less);
    return order;
}

fn leaf_masks_of(comptime layout: anytype, comptime order: []const []const u8) [layout.leaves.len]Mask {
    @setEvalBranchQuota(order_quota * layout.leaves.len);
    var masks: [layout.leaves.len]Mask = undefined;
    for (layout.leaves, &masks) |leaf, *mask| {
        mask.* = 0;
        for (layout.entries[leaf.entries_first..][0..leaf.entries_count]) |entry| {
            mask.* |= bit_of(order, layout.text[entry.method.offset..][0..entry.method.len]);
        }
    }
    return masks;
}

/// The Allow value of each mask: its methods in `order`, with HEAD after GET when the mask holds
/// GET and no HEAD (decision 122 ruling 1).
fn values_of(comptime order: []const []const u8) [1 << order.len][]const u8 {
    @setEvalBranchQuota(allow_quota_per_value << order.len);
    var values: [1 << order.len][]const u8 = undefined;
    const head = bit_of(order, router_method.head_token);
    for (&values, 0..) |*value, mask| {
        var text: []const u8 = "";
        for (order, 0..) |token, index| {
            if ((mask >> index) & 1 == 0) continue;
            text = if (text.len == 0) token else text ++ separator ++ token;
            const is_get = std.mem.eql(u8, token, router_method.get_token);
            if (is_get and mask & head == 0) text = text ++ separator ++ router_method.head_token;
        }
        value.* = text;
    }
    return values;
}

/// The comptime branches of sorting a table's methods, at most `route_methods_max` of them.
const order_quota = 100_000;

/// The comptime branches that writing one Allow value takes, at most.
const allow_quota_per_value = 400;

test {
    _ = @import("router_allow_test.zig");
}
