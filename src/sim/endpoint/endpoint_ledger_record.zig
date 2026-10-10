//! The record each event adds to the endpoint check's CRC of the events (`endpoint_ledger.zig`):
//! its kind, a detail, its slot and generation, the request's number, its word, a length and the
//! instant, each integer big-endian, so the CRC is the same on every host. Split off
//! `endpoint_ledger.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");

const Handle = server.ConnectionHandle;

/// Octets of one event's record in the CRC of the events: its kind, a detail, its slot and
/// generation, the request's number, its word, a length, and the instant.
const record_len: usize = 40;

/// `reported` as a record of fixed length, its integers big-endian, so the CRC is the same on
/// every host.
pub fn encode(reported: server.Event, now_ms: u64) [record_len]u8 {
    var record: [record_len]u8 = @splat(0);
    const fields = fields_of(reported);
    var at: usize = 0;
    put(&record, &at, u8, @intFromEnum(std.meta.activeTag(reported)));
    put(&record, &at, u8, fields.detail);
    put(&record, &at, u16, @intCast(fields.handle.slot));
    put(&record, &at, u32, fields.handle.generation);
    put(&record, &at, u64, fields.number);
    put(&record, &at, u64, fields.word);
    put(&record, &at, u64, fields.length);
    put(&record, &at, u64, now_ms);
    assert(at == record_len);
    return record;
}

fn put(record: *[record_len]u8, at: *usize, comptime T: type, value: T) void {
    std.mem.writeInt(T, record[at.*..][0..@sizeOf(T)], value, .big);
    at.* += @sizeOf(T);
}

/// What an event's record holds beside its kind and its instant.
const Fields = struct {
    detail: u8 = 0,
    handle: Handle = .{ .slot = 0, .generation = 0 },
    number: u64 = 0,
    word: u64 = 0,
    length: u64 = 0,
};

fn fields_of(reported: server.Event) Fields {
    return switch (reported) {
        .request => |request| .{ .handle = request.id.connection, .number = request.id.number, .detail = @intFromBool(request.end), .length = request.version.major },
        .body => |body| .{ .handle = body.id.connection, .number = body.id.number, .word = body.user_data, .detail = @intFromBool(body.end), .length = body.octets.len },
        .trailers => |trailers| .{ .handle = trailers.id.connection, .number = trailers.id.number, .word = trailers.user_data, .length = trailers.fields.len() },
        .cancelled => |cancelled| .{ .handle = cancelled.id.connection, .number = cancelled.id.number, .word = cancelled.user_data, .detail = @intFromEnum(cancelled.reason), .length = reason_detail(cancelled.reason) },
        .done => |done| .{ .handle = done.id.connection, .number = done.id.number, .word = done.user_data },
        .writable => |writable| .{ .handle = writable.id.connection, .number = writable.id.number, .word = writable.user_data },
        .send => |handle| .{ .handle = handle },
        .close => |handle| .{ .handle = handle },
        .ended => |over| .{ .handle = over.connection, .detail = @intFromBool(over.failed), .length = close_detail(over.reason) },
        .closed => .{},
    };
}

/// The deadline that cancelled a request, plus one, or 0.
fn reason_detail(reason: server.CancelReason) u64 {
    return switch (reason) {
        .deadline => |passed| @as(u64, @intFromEnum(passed)) + 1,
        else => 0,
    };
}

/// Why colibri closed a connection, as a number: 0 for no reason, then each deadline, then each
/// limit.
fn close_detail(reason: ?server.CloseReason) u64 {
    const held = reason orelse return 0;
    const deadlines: u64 = std.meta.fields(server.Deadline).len;
    return switch (held) {
        .deadline => |passed| @as(u64, @intFromEnum(passed)) + 1,
        .limit => |passed| deadlines + @intFromEnum(passed) + 1,
    };
}
