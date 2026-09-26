//! Example: an h11 client fetches a resource and uploads another, and an h11 server answers both.
//!
//! The client pipelines two requests: a GET, then a PUT whose body it sends from its own buffer
//! with `count_body`, so colibri copies none of it (decision 95). The server reads one request at
//! a time and answers each before it reads the next (decision 92). Both run over `link.zig`, which
//! stands where a program's sockets would be.
//!
//! Run it with `zig build example-h11_exchange`, or every example with `zig build examples`.
const std = @import("std");
const h11 = @import("h11");
const link_module = @import("link.zig");

const Connection = h11.connection.Connection;
const Link = link_module.Link;

/// The octets one side writes before it sends them, at most.
const output_len = 4096;

/// The requests the client sends, and so the responses it waits for.
const exchanges = 2;

/// Calls to `receive` either side makes before the example gives up.
const receive_calls_max = 64;

const host = "example.test";
const greeting = "hello from colibri\n";
const upload = "an upload the client sends from its own buffer\n";

/// The resources the server knows. A request's target points into the octets the server read,
/// which move once it consumes them, so the server keeps which resource it is answering instead.
const Resource = enum { greeting, upload, unknown };

// The connections and the link hold kilobytes each, so they live outside the stack.
var link: Link = undefined;
var client: Connection = undefined;
var server: Connection = undefined;
var output: [output_len]u8 = undefined;

pub fn main() !void {
    try link.init();
    defer link.deinit();
    client.init(.client, .{});
    server.init(.server, .{});

    try send_requests();
    try serve();
    try read_responses();
}

fn send_requests() !void {
    const get_len = try client.write_request(&output, "GET", "/greeting", &.{
        .{ .name = "Host", .value = host },
    });
    try link.send(.client, output[0..get_len]);

    // GET is idempotent, so the client sends the PUT before the GET's response arrives (decision
    // 88). The PUT's body goes out from `upload` itself: `count_body` counts it against the
    // Content-Length and writes nothing.
    const put_len = try client.write_request(&output, "PUT", "/upload", &.{
        .{ .name = "Host", .value = host },
        .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{upload.len}) },
    });
    try link.send(.client, output[0..put_len]);
    try client.count_body(upload.len);
    try link.send(.client, upload);
    _ = try client.write_end(&output, &.{});
}

fn serve() !void {
    var answered: usize = 0;
    var resource: Resource = .unknown;
    var body_len: usize = 0;
    for (0..receive_calls_max) |_| {
        if (answered == exchanges) return;
        const input = try link.receive(.server);
        const received = try server.receive(input);
        if (received.event) |event| switch (event) {
            .request => |request| {
                std.debug.print("server: {s} {s}\n", .{ request.line.method, request.line.target });
                resource = resource_of(request.line.target);
                body_len = 0;
                // A request without a body ends with its head, and no `end` event follows.
                if (ends_with_head(request.body)) {
                    try respond(resource, body_len);
                    answered += 1;
                }
            },
            .data => |data| body_len += data.len,
            .end => {
                try respond(resource, body_len);
                answered += 1;
            },
            else => {},
        };
        // The event's slices point into the queue, so it is consumed only once they are used.
        link.consume(.server, received.consumed);
    }
    return error.ExchangeUnfinished;
}

/// Whether a message has no body, so its head is all of it and no `end` event follows.
fn ends_with_head(body: h11.message.Body) bool {
    return switch (body.length) {
        .none => true,
        .fixed => |octets| octets == 0,
        else => false,
    };
}

fn resource_of(target: []const u8) Resource {
    if (std.mem.eql(u8, target, "/greeting")) return .greeting;
    if (std.mem.eql(u8, target, "/upload")) return .upload;
    return .unknown;
}

/// Writes the response to the request the server just read, and sends it.
fn respond(resource: Resource, body_len: usize) !void {
    switch (resource) {
        .greeting => {
            const head_len = try server.write_response(&output, 200, "OK", &.{
                .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{greeting.len}) },
            });
            const written = head_len + try server.write_body(output[head_len..], greeting);
            _ = try server.write_end(output[written..], &.{});
            try link.send(.server, output[0..written]);
        },
        .upload => {
            std.debug.print("server: stored {d} octets\n", .{body_len});
            // A response with no content ends with its head, so it has no `write_end`.
            const head_len = try server.write_response(&output, 201, "Created", &.{
                .{ .name = "Content-Length", .value = "0" },
            });
            try link.send(.server, output[0..head_len]);
        },
        .unknown => {
            const head_len = try server.write_response(&output, 404, "Not Found", &.{
                .{ .name = "Content-Length", .value = "0" },
            });
            try link.send(.server, output[0..head_len]);
        },
    }
}

fn read_responses() !void {
    var ended: usize = 0;
    for (0..receive_calls_max) |_| {
        if (ended == exchanges) return;
        const input = try link.receive(.client);
        const received = try client.receive(input);
        if (received.event) |event| switch (event) {
            .response => |response| {
                std.debug.print("client: {d}\n", .{response.line.status.code});
                if (ends_with_head(response.body)) ended += 1;
            },
            .data => |data| std.debug.print("client: body {s}", .{data}),
            .end => ended += 1,
            else => {},
        };
        link.consume(.client, received.consumed);
    }
    return error.ExchangeUnfinished;
}
