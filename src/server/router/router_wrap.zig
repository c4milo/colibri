//! A middleware's state and its wrappers of the request body's reader and of the response body's
//! writer (decision 127 ruling 5, design §8 step 25.6). The root exports none of it.
//!
//! Each request's entry holds one `State` for each middleware of its chain, one after the other.
//! `wrap_body` and `wrap_response` run at the head, after the middleware's `on_request` returns
//! `.next`, and each wraps what the middleware before it gave. When the program ends a wrapped
//! response, the router calls each `finish_response` from the route's side outward, and then ends
//! it.
const std = @import("std");
const event = @import("../event.zig");
const ResponseWriter = @import("../response_writer/response_writer.zig").ResponseWriter;
const router_call = @import("router_call.zig");

/// The state a middleware keeps in a request's entry, or `void` for one with none. Comptime-only.
pub fn StateOf(comptime Middleware: type) type {
    if (@hasDecl(Middleware, "State")) return Middleware.State;
    return void;
}

/// The pointer type a middleware's hooks take for its state: `*void` for one with none.
/// Comptime-only.
pub fn StatePointer(comptime Middleware: type) type {
    return *StateOf(Middleware);
}

/// Whether a middleware wraps the request body's reader or the response body's writer.
/// Comptime-only.
pub fn wraps(comptime Middleware: type) bool {
    return @hasDecl(Middleware, "wrap_body") or @hasDecl(Middleware, "wrap_response");
}

/// The comptime branches of `layout_of`: a base, and a share for each route.
const branch_quota_base = 1000;
const branch_quota_per_route = 100;

/// The size, the alignment and the longest chain of every route's middleware states. Comptime-only.
pub const Layout = struct { size: usize, alignment: usize, chain_max: usize };

pub fn layout_of(comptime table: anytype) Layout {
    // The loop walks each route's chain, and the GitHub API's 203 routes pass the default budget
    // of 1,000 (`src/testing/server/server_routes.zig`).
    @setEvalBranchQuota(branch_quota_base + branch_quota_per_route * table.routes.len);
    var layout: Layout = .{ .size = 0, .alignment = 1, .chain_max = 0 };
    for (0..table.routes.len) |index| {
        const chain = router_call.table_chain(table) ++ router_call.entry_chain(table.routes[index]);
        const offsets = offsets_of(chain);
        layout.size = @max(layout.size, offsets[chain.len]);
        layout.chain_max = @max(layout.chain_max, chain.len);
        for (0..chain.len) |place| layout.alignment = @max(layout.alignment, @alignOf(StateOf(chain[place])));
    }
    return layout;
}

/// The offset of each middleware's state in an entry, and the size of them all last.
/// Comptime-only.
fn offsets_of(comptime chain: anytype) [chain.len + 1]usize {
    var offsets: [chain.len + 1]usize = undefined;
    var offset: usize = 0;
    for (0..chain.len) |index| {
        const State = StateOf(chain[index]);
        offset = std.mem.alignForward(usize, offset, @alignOf(State));
        offsets[index] = offset;
        offset += @sizeOf(State);
    }
    offsets[chain.len] = offset;
    return offsets;
}

/// What a request's wrappers gave the router: the writer each middleware's `wrap_response`
/// returned, by its place in the chain, and the reader the route's `on_body` reads.
pub fn Held(comptime chain_max: usize) type {
    return struct {
        writers: [chain_max]?*std.Io.Writer = @splat(null),
        reader: *std.Io.Reader = undefined,
    };
}

/// The state of the middleware at `index` of `chain`, in the entry's `states`.
pub fn state_at(comptime chain: anytype, comptime index: usize, states: [*]u8) StatePointer(chain[index]) {
    const offset = comptime offsets_of(chain)[index];
    return @ptrCast(@alignCast(states + offset));
}

/// Gives each middleware of `chain` the state its fields' defaults hold.
pub fn reset(comptime chain: anytype, states: [*]u8) void {
    inline for (0..chain.len) |index| {
        if (comptime StateOf(chain[index]) != void) state_at(chain, index, states).* = .{};
    }
}

/// Calls the wrappers of the middleware at `index`, after its `on_request` returned `.next`.
pub fn wrap(
    comptime chain: anytype,
    comptime index: usize,
    context: anytype,
    states: [*]u8,
    held: anytype,
    request: *const event.Request,
    response: *ResponseWriter,
) void {
    const Middleware = chain[index];
    const state = state_at(chain, index, states);
    if (comptime @hasDecl(Middleware, "wrap_body")) {
        if (Middleware.wrap_body(context, state, request, held.reader)) |reader| held.reader = reader;
    }
    if (comptime @hasDecl(Middleware, "wrap_response")) {
        const inner = response.wrapped orelse &response.writer;
        if (Middleware.wrap_response(context, state, request, response, inner)) |writer| {
            response.wrapped = writer;
            held.writers[index] = writer;
        }
    }
}

/// Lets each wrapper of the response write what it owes, from the route's side outward: its
/// middleware's `finish_response`, or a flush of its writer when it declares none.
pub fn finish(comptime chain: anytype, context: anytype, states: [*]u8, held: anytype) anyerror!void {
    inline for (0..chain.len) |reverse| {
        const index = chain.len - 1 - reverse;
        const Middleware = chain[index];
        if (comptime @hasDecl(Middleware, "wrap_response")) {
            if (held.writers[index]) |writer| {
                if (comptime @hasDecl(Middleware, "finish_response")) {
                    try Middleware.finish_response(context, state_at(chain, index, states));
                } else {
                    try writer.flush();
                }
            }
        }
    }
}
