//! The agreement of a connection's head writes with the writes they replaced (design §8 step 17).
//! Before `message.Checked.add`, `write_response` and `write_request` scanned the field lines for
//! each rule. `reference` keeps that code, test-only, over the head writers of
//! `message_write_test.zig`. The tests require the same octets or error from both, and the same
//! state of the connection after each.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const connection = @import("connection.zig");
const connection_body = @import("connection_body.zig");
const connection_server = @import("connection_server.zig");
const message_write_test = @import("../message/message_write_test.zig");

const testing = std.testing;
const Connection = connection.Connection;
const SendError = connection.SendError;
const Field = http.Field;
const Code = http.status.Code;
const message_reference = message_write_test.reference;
const atoms = message_write_test.atoms;
const atom = message_write_test.atom;
const list_len_max = message_write_test.list_len_max;
const lists_len = message_write_test.lists_len;
const list_at = message_write_test.list_at;

/// A connection's head writes as they were before the pass, each rule with its own scan.
const reference = struct {
    const close_field: Field = .{ .name = "Connection", .value = "close" };
    const switching_protocols: u16 = @intFromEnum(http.status.Code.switching_protocols);

    fn write_response(target: *Connection, output: []u8, status: u16, reason: []const u8, fields: []const Field) SendError!usize {
        // RFC 9112 §9.6: a server that closes the connection sends nothing after its last response.
        if (target.phase == .closed or target.failure != null) return error.ConnectionClosed;
        // RFC 9112 §9.2: each response answers the request read last, and one final response does.
        if (target.phase == .head or target.phase == .tunnel or target.answered) return error.NoRequest;
        // RFC 9110 §15.2.2: 101 switches to the protocol Upgrade names.
        if (status == switching_protocols) return error.UpgradeUnsupported;
        // RFC 9110 §15: a status code is three digits from 100 to 599.
        const code = http.Status.from_code(status) catch return error.StatusInvalid;
        if (code.is_interim()) return message_reference.write_response_head(output, status, reason, fields);
        if (target.asked == .connect) try answer_connect(target, code, fields);
        const writer = try response_body(target, code, fields);
        const close_after = target.close_after or writer.kind == .close_delimited or fields_ask_close(fields);
        const written = try write_final_head(close_after, output, status, reason, fields);
        target.close_after = close_after;
        target.answered = true;
        target.writer = writer;
        if (writer.kind == .tunnel) target.phase = .tunnel;
        if (!writer.open()) connection_server.finish_response(target);
        return written;
    }

    fn answer_connect(target: *Connection, code: http.Status, fields: []const Field) SendError!void {
        if (code.class() != .successful) {
            target.close_after = true;
            return;
        }
        const framed = message_reference.find(fields, "Content-Length") != null or message_reference.find(fields, "Transfer-Encoding") != null;
        // RFC 9110 §8.6 and RFC 9112 §6.1: no Content-Length or Transfer-Encoding in a 2xx to CONNECT.
        if (framed) return error.FramingInvalid;
    }

    fn response_body(target: *const Connection, code: http.Status, fields: []const Field) error{FramingInvalid}!connection_body.Writer {
        if (target.asked == .connect and code.class() == .successful) return .{ .kind = .tunnel };
        const no_content = code.code == @intFromEnum(http.status.Code.no_content) or code.code == @intFromEnum(http.status.Code.not_modified);
        if (target.asked == .head or no_content) return .{ .kind = .none };
        return declared(fields, .close_delimited);
    }

    fn write_final_head(close_after: bool, output: []u8, status: u16, reason: []const u8, fields: []const Field) SendError!usize {
        if (!close_after or fields_ask_close(fields)) {
            return message_reference.write_response_head(output, status, reason, fields);
        }
        var with_close: [core.constants.field_count_max]Field = undefined;
        // RFC 9110 §5.4: no predefined limit on a section, so colibri's applies to what it sends.
        if (fields.len >= with_close.len) return error.TooManyFields;
        @memcpy(with_close[0..fields.len], fields);
        with_close[fields.len] = close_field;
        return message_reference.write_response_head(output, status, reason, with_close[0 .. fields.len + 1]);
    }

    fn write_request(target: *Connection, output: []u8, method: []const u8, target_uri: []const u8, fields: []const Field) SendError!usize {
        // RFC 9110 §7.8: Upgrade invites the server to switch protocols, which h11 cannot follow.
        if (message_reference.find(fields, "Upgrade") != null) return error.UpgradeUnsupported;
        const written = try message_reference.write_request_head(output, method, target_uri, fields);
        target.writer = declared(fields, .none) catch unreachable;
        target.close_sent = fields_ask_close(fields);
        return written;
    }

    fn declared(fields: []const Field, otherwise: connection_body.Writer.Kind) error{FramingInvalid}!connection_body.Writer {
        if (message_reference.find(fields, "Transfer-Encoding") != null) return .{ .kind = .chunked };
        const value = message_reference.find(fields, "Content-Length") orelse return .{ .kind = otherwise };
        // RFC 9110 §8.6: Content-Length = 1*DIGIT, and colibri counts a length a u64 holds.
        const octets = std.fmt.parseUnsigned(u64, value, http.constants.content_length_radix) catch return error.FramingInvalid;
        return .{ .kind = if (octets == 0) .none else .fixed, .remaining = octets };
    }

    fn fields_ask_close(fields: []const Field) bool {
        for (fields) |line| {
            if (!http.field.names_equal(line.name, "Connection")) continue;
            var options = std.mem.splitScalar(u8, line.value, ',');
            for (0..line.value.len + 1) |_| {
                const option = options.next() orelse break;
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, option, " \t"), "close")) return true;
            }
        }
        return false;
    }
};

/// The two connections and buffers of each case, placed outside any stack frame.
var test_new: Connection align(@alignOf(Connection)) = undefined;
var test_old: Connection align(@alignOf(Connection)) = undefined;
var test_output_new: [test_output_len]u8 = undefined;
var test_output_old: [test_output_len]u8 = undefined;
const test_output_len = 8192;

/// The requests a response answers: each `asked`, the close option, and a body not read.
const requests = [_][]const u8{
    "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
    "HEAD / HTTP/1.1\r\nHost: h\r\n\r\n",
    "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\n",
};
/// A status below 100.
const status_below_min: u16 = 99;
const statuses = [_]u16{
    status_below_min,              @intFromEnum(Code.@"continue"),  @intFromEnum(Code.ok),
    @intFromEnum(Code.no_content), @intFromEnum(Code.not_modified), @intFromEnum(Code.not_found),
};
const reasons = [_][]const u8{ "OK", "O\r\nK" };

/// The lines of the lists of three: the faults that a connection's rules read before the head
/// writer does, and the lines those rules read.
const connection_atoms = [_]Field{
    atom.plain,   atom.content_length, atom.content_length_letter, atom.content_length_underscore,
    atom.chunked, atom.close,          atom.name_invalid,          atom.value_invalid,
};

fn expect_same_state(new: *const Connection, old: *const Connection) !void {
    try testing.expectEqual(old.phase, new.phase);
    try testing.expectEqual(old.close_after, new.close_after);
    try testing.expectEqual(old.close_sent, new.close_sent);
    try testing.expectEqual(old.answered, new.answered);
    try testing.expectEqual(old.responded, new.responded);
    try testing.expectEqual(old.writer, new.writer);
}

fn expect_same_response(request: []const u8, status: u16, reason: []const u8, fields: []const Field) !void {
    errdefer std.debug.print("request \"{s}\", status {d}, reason \"{s}\", fields {any}\n", .{ request, status, reason, fields });
    for ([_]*Connection{ &test_new, &test_old }) |target| {
        target.init(.server, .{});
        _ = try target.receive(request, &.{});
    }
    const new = test_new.write_response(&test_output_new, status, reason, fields);
    const old = reference.write_response(&test_old, &test_output_old, status, reason, fields);
    try message_write_test.expect_same(new, &test_output_new, old, &test_output_old);
    try expect_same_state(&test_new, &test_old);
}

fn expect_same_responses(set: []const Field, len_max: usize) !void {
    var lines: [list_len_max]Field = undefined;
    for (0..lists_len(set.len, len_max)) |index| {
        const fields = list_at(set, index, &lines);
        for (requests) |request| {
            for (statuses) |status| {
                for (reasons) |reason| try expect_same_response(request, status, reason, fields);
            }
        }
    }
}

test "every final response of up to two lines, and of three from the connection's faults, is written as the scans wrote it" {
    try expect_same_responses(&atoms, 2);
    try expect_same_responses(&connection_atoms, list_len_max);
}

/// A section as long as `with_close` holds, and one line shorter, each with a fault.
var test_many: [core.constants.field_count_max]Field align(@alignOf(Field)) = undefined;

test "a section too long for the close option is refused as the scans refused it, whatever its faults" {
    for ([_]Field{ atom.plain, atom.content_length_letter, atom.name_invalid }) |fault| {
        @memset(&test_many, atom.plain);
        test_many[test_many.len / 2] = fault;
        for ([_]usize{ test_many.len - 1, test_many.len }) |len| {
            try expect_same_response(requests[3], 200, "OK", test_many[0..len]);
            try expect_same_response(requests[0], 200, "OK", test_many[0..len]);
        }
    }
}

const methods = [_][]const u8{ "GET", "POST", "CONNECT" };
const targets = [_][]const u8{ "/", "a:1" };

/// The lines of the requests of three lines: a Host, and the lines the client's rules read.
const client_atoms = [_]Field{
    atom.host,    atom.host_port, atom.content_length, atom.content_length_letter,
    atom.chunked, atom.close,     atom.name_invalid,   atom.upgrade,
};

fn expect_same_request(method: []const u8, target: []const u8, fields: []const Field) !void {
    errdefer std.debug.print("method \"{s}\", target \"{s}\", fields {any}\n", .{ method, target, fields });
    test_new.init(.client, .{});
    test_old.init(.client, .{});
    const new = test_new.write_request(&test_output_new, method, target, fields);
    const old = reference.write_request(&test_old, &test_output_old, method, target, fields);
    try message_write_test.expect_same(new, &test_output_new, old, &test_output_old);
    try testing.expectEqual(test_old.writer, test_new.writer);
    try testing.expectEqual(test_old.close_sent, test_new.close_sent);
}

fn expect_same_requests(set: []const Field, len_max: usize) !void {
    var lines: [list_len_max]Field = undefined;
    for (0..lists_len(set.len, len_max)) |index| {
        const fields = list_at(set, index, &lines);
        for (methods) |method| {
            for (targets) |target| try expect_same_request(method, target, fields);
        }
    }
}

test "every request of up to two lines, and of three from a Host and the client's faults, is written as the scans wrote it" {
    try expect_same_requests(&atoms, 2);
    try expect_same_requests(&client_atoms, list_len_max);
}
