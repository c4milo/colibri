//! The program's router and handler, which `init` takes (decision 156 ruling 5, decision 159).
//! colibri keeps each one as an `*anyopaque` and a function that comptime makes for the program's
//! type, so the type of a `colibri.Server` or a `colibri.Client` does not name the program's
//! types. The root exports none of these names.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const client = @import("client");

/// The router and the context of a server whose engine is `Engine`.
pub fn Router(comptime Engine: type) type {
    return struct {
        const Self = @This();

        router: *anyopaque,
        context: *anyopaque,
        handle_fn: *const fn (router: *anyopaque, context: *anyopaque, engine: *Engine, reported: server.Event) server.Handled,

        /// Keeps `router`, a pointer to the program's `server.Router`, and `context`, a pointer to
        /// the context that the router's functions take.
        pub fn of(router: anytype, context: anytype) Self {
            const RouterType = @typeInfo(@TypeOf(router)).pointer.child;
            const Context = @typeInfo(@TypeOf(context)).pointer.child;
            const Calls = struct {
                fn handle(erased_router: *anyopaque, erased_context: *anyopaque, engine: *Engine, reported: server.Event) server.Handled {
                    const typed: *RouterType = @ptrCast(@alignCast(erased_router));
                    const typed_context: *Context = @ptrCast(@alignCast(erased_context));
                    return typed.handle(typed_context, engine, reported);
                }
            };
            return .{ .router = @ptrCast(router), .context = @ptrCast(context), .handle_fn = Calls.handle };
        }

        /// Hands one event to the router, which writes the response or hands the event back.
        pub fn handle(self: Self, engine: *Engine, reported: server.Event) server.Handled {
            return self.handle_fn(self.router, self.context, engine, reported);
        }
    };
}

/// The handler of a client of type `Client`: a pointer to the program's struct, or none for a
/// client that only fetches. The struct declares `on_finished` and may declare `on_connected`.
pub fn Handler(comptime Client: type) type {
    return struct {
        const Self = @This();

        handler: ?*anyopaque,
        finished_fn: ?*const fn (handler: *anyopaque, running: *Client, finished: client.Finished) void,
        connected_fn: ?*const fn (handler: *anyopaque, running: *Client, connected: client.Connected) void,

        pub const none: Self = .{ .handler = null, .finished_fn = null, .connected_fn = null };

        /// Keeps `handler`, a pointer to the program's struct, or null.
        pub fn of(handler: anytype) Self {
            if (@TypeOf(handler) == @TypeOf(null)) return none;
            const Program = @typeInfo(@TypeOf(handler)).pointer.child;
            if (!@hasDecl(Program, "on_finished")) {
                @compileError("colibri: a client's handler declares on_finished (decision 156 ruling 5)");
            }
            const Calls = struct {
                fn finished(erased_handler: *anyopaque, running: *Client, ended: client.Finished) void {
                    const typed: *Program = @ptrCast(@alignCast(erased_handler));
                    typed.on_finished(running, ended);
                }
                fn connected(erased_handler: *anyopaque, running: *Client, taken: client.Connected) void {
                    const typed: *Program = @ptrCast(@alignCast(erased_handler));
                    typed.on_connected(running, taken);
                }
            };
            const connected_fn = if (@hasDecl(Program, "on_connected")) &Calls.connected else null;
            return .{ .handler = @ptrCast(handler), .finished_fn = Calls.finished, .connected_fn = connected_fn };
        }

        /// Hands the program an exchange that ended. A client with no handler drops it.
        pub fn on_finished(self: Self, running: *Client, ended: client.Finished) void {
            const call = self.finished_fn orelse return;
            call(self.handler.?, running, ended);
        }

        /// Hands the program the connection that takes the exchanges, when its struct declares
        /// `on_connected`.
        pub fn on_connected(self: Self, running: *Client, taken: client.Connected) void {
            const call = self.connected_fn orelse return;
            assert(self.finished_fn != null);
            call(self.handler.?, running, taken);
        }
    };
}
