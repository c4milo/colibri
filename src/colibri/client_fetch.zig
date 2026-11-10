//! `Client.fetch` of a `.private` `colibri.Client` (decision 156 ruling 12, design §8 step 44h):
//! one exchange, which runs on colibri's own loop until it ends. The first `fetch` or `run` makes
//! the loop, and it stays made between fetches (`client_loop.begin`). `deinit` stops it. The
//! handler gets each exchange that ends, except the exchange of the fetch.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const client_loop = @import("client_loop.zig");

/// One exchange that `fetch` runs, in the shape of `std.http.Client.fetch` with no heap and with
/// decision 126's words. An empty buffer drops its part of the response.
pub const FetchOptions = struct {
    /// The request method (RFC 9110 §9). Null sends POST with a request body, and GET without.
    method: ?[]const u8 = null,
    /// The target's path and query in origin form (RFC 9112 §3.2.1).
    path: []const u8,
    /// The request's own headers, as `client.Request.headers` holds them.
    headers: []const client.Header = &.{},
    /// The path and the headers that go out as never-indexed literals (RFC 7541 §6.2.3, RFC 9204
    /// §4.5.4).
    never_indexed: @FieldType(client.Request, "never_indexed") = .{},
    /// The request's body, sent whole. Empty for none.
    request_body: []const u8 = "",
    /// Where the response's body, its header section and its trailer section are copied.
    response_body: []u8 = &.{},
    response_headers: []u8 = &.{},
    response_trailers: []u8 = &.{},
};

/// How the exchange of a `fetch` ended. A protocol failure is a `result`, not an error (decision
/// 126).
pub const FetchResult = struct {
    result: client.Result,
    /// The final response's status code (RFC 9110 §15), as `client.Response.status` holds it. An
    /// exchange that ended before its final head has none, so a program reads `result` first
    /// (decision 158 ruling 5).
    status: client.Status,
    headers: client.Headers,
    trailers: client.Trailers,
    /// Bytes of `FetchOptions.response_body` the response body filled.
    body_len: usize,
};

/// The method of `options`: its own, or POST with a request body and GET without (RFC 9110
/// §9.3.1, §9.3.3).
pub fn method_of(options: *const FetchOptions) []const u8 {
    if (options.method) |method| return method;
    return if (options.request_body.len > 0) "POST" else "GET";
}

/// Runs the exchange of `options` on the client `state` names. See `Client.fetch`.
pub fn fetch(state: anytype, options: *const FetchOptions) !FetchResult {
    assert(state.fetching == null);
    state.fetch_request = .{
        .method = method_of(options),
        .path = options.path,
        .headers = options.headers,
        .never_indexed = options.never_indexed,
        .body = options.request_body,
    };
    state.fetch_response = .{
        .headers = .{ .buffer = options.response_headers },
        .trailers = .{ .buffer = options.response_trailers },
        .body = options.response_body,
    };
    const id = try state.request(&state.fetch_request, &state.fetch_response);
    state.fetching = id;
    state.fetched = false;
    try run_until_fetched(state, id, private_loop);
    assert(state.fetching == null);
    const response = &state.fetch_response;
    return .{
        .result = response.result,
        .status = response.status,
        .headers = response.headers,
        .trailers = response.trailers,
        .body_len = response.body_len,
    };
}

/// The loop of a `.private` client, as `run_until_fetched` runs it.
const private_loop = struct {
    fn begin(state: anytype) !void {
        return client_loop.begin(state);
    }

    fn pass(state: anytype) !void {
        // The pool reports each exchange's `finished` before its `closed`, so the run cannot end
        // before the fetch does.
        assert(!client_loop.finished(state));
        return state.host.pass(state, client_loop);
    }
};

/// Makes `loop` when no `fetch` did, and passes it until the exchange `id` of a fetch has ended.
/// When the loop fails, the pool drops the exchange. The memory that `FetchOptions` names is then
/// the program's again, and no later pass of the loop writes it.
fn run_until_fetched(state: anytype, id: client.RequestId, comptime loop: type) !void {
    assert(state.fetching.? == id);
    errdefer abandon(state, id);
    try loop.begin(state);
    while (!state.fetched) try loop.pass(state);
}

/// Ends the exchange `id` of a fetch whose loop failed. The pool reports nothing for it.
fn abandon(state: anytype, id: client.RequestId) void {
    state.pool.cancel(id, state.latest_ns);
    state.fetching = null;
}

const testing = std.testing;

/// The fields that `run_until_fetched` reads, with nothing else of a client. Test-only.
const TestClient = struct {
    fetching: ?client.RequestId = test_id,
    fetched: bool = false,
    latest_ns: u64 = 0,
    pool: TestPool = .{},
    passes: u32 = 0,
};
const TestPool = struct {
    cancelled: ?client.RequestId = null,

    pub fn cancel(pool: *TestPool, id: client.RequestId, _: u64) void {
        pool.cancelled = id;
    }
};
/// The id of the test's exchange, as a pool numbers one. Test-only.
const test_number: u64 = 7;
const test_id: client.RequestId = @enumFromInt(test_number);
/// The pass at which a test loop ends the fetch or fails. Test-only.
const test_last_pass = 2;

/// A loop that cannot be made, one whose second pass fails, and one whose second pass ends the
/// fetch as `client_loop.zig` ends it. Test-only.
const UnmadeLoop = struct {
    fn begin(_: *TestClient) !void {
        return error.SystemResources;
    }

    fn pass(_: *TestClient) !void {
        unreachable;
    }
};
const FailedLoop = struct {
    fn begin(_: *TestClient) !void {}

    fn pass(state: *TestClient) !void {
        state.passes += 1;
        if (state.passes == test_last_pass) return error.Unexpected;
    }
};
const EndedLoop = struct {
    fn begin(_: *TestClient) !void {}

    fn pass(state: *TestClient) !void {
        state.passes += 1;
        if (state.passes < test_last_pass) return;
        state.fetching = null;
        state.fetched = true;
    }
};

test "decision 156 ruling 12: a fetch whose loop fails ends its exchange in the pool" {
    var unmade: TestClient = .{};
    try testing.expectError(error.SystemResources, run_until_fetched(&unmade, test_id, UnmadeLoop));
    // The pool holds no pointer into the program's memory after the error.
    try testing.expectEqual(@as(?client.RequestId, test_id), unmade.pool.cancelled);
    try testing.expectEqual(null, unmade.fetching);
    var failed: TestClient = .{};
    try testing.expectError(error.Unexpected, run_until_fetched(&failed, test_id, FailedLoop));
    try testing.expectEqual(@as(?client.RequestId, test_id), failed.pool.cancelled);
    try testing.expectEqual(null, failed.fetching);
}

test "decision 156 ruling 12: a fetch passes its loop until its exchange has ended, and no longer" {
    var ended: TestClient = .{};
    try run_until_fetched(&ended, test_id, EndedLoop);
    try testing.expectEqual(test_last_pass, ended.passes);
    // The exchange ended itself, so the pool gets no cancel.
    try testing.expectEqual(null, ended.pool.cancelled);
}

test "RFC 9110 §9.3: a fetch with no method sends POST with a request body, and GET without" {
    try testing.expectEqualStrings("GET", method_of(&.{ .path = "/" }));
    try testing.expectEqualStrings("POST", method_of(&.{ .path = "/", .request_body = "note" }));
    // A method that the program names goes out as it is (RFC 9110 §9.3.4).
    try testing.expectEqualStrings("PUT", method_of(&.{ .path = "/", .method = "PUT", .request_body = "note" }));
    try testing.expectEqualStrings("HEAD", method_of(&.{ .path = "/", .method = "HEAD" }));
}
