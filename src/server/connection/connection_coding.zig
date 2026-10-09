//! Content codings on a server connection over TCP (decision 101, design §8 step 17e). With
//! `Config.codings` and `Config.encoders` set, the connection keeps what each request's
//! Accept-Encoding accepts as the request arrives, and writes each final response the caller marks
//! `codable` as `coding_rules.plan` says: its fields rewritten, and its content coded through an
//! encoder of the pool. h11 and h2 copy the coded octets out of the encoder's ring as they copy the
//! caller's, and `send` copies what the ring still holds after the caller's last call, then ends
//! the content once the encoder has finished.
//!
//! Every response passes through here: `respond`, `write_body` and `write_trailers` hand one that
//! is not coded to the protocol unchanged.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const coding_rules = @import("../coding/coding_rules.zig");
const coding_fields = @import("../coding/coding_fields.zig");
const coding_response = @import("../coding/coding_response.zig");
const connection_module = @import("connection.zig");
const connection_h11 = @import("connection_h11.zig");
const connection_h2 = @import("connection_h2.zig");

const Connection = connection_module.Connection;
const SendError = connection_module.SendError;
const Field = http.Field;
const Number = event.Number;
const Coded = coding_response.Coded;

/// What the connection keeps of one request while its response may be coded.
pub const Entry = struct {
    /// The request's id, or 0 for an entry not in use.
    id: Number,
    asked: coding_rules.Asked,
    /// The coded response, once its head went out coded.
    coded: ?Coded,
};

/// The requests whose responses may be coded: one entry each, from the request's head until its
/// response is uncoded, ends, or is cancelled.
pub const Table = struct {
    entries: [constants.coding_requests_max]Entry,
    /// Entries in use.
    used: usize,

    pub fn init(table: *Table) void {
        for (&table.entries) |*entry| entry.id = 0;
        table.used = 0;
    }

    fn find(table: *Table, id: Number) ?*Entry {
        if (table.used == 0 or id == 0) return null;
        for (&table.entries) |*entry| {
            if (entry.id == id) return entry;
        }
        return null;
    }

    fn add(table: *Table, id: Number, asked: coding_rules.Asked) void {
        assert(id != 0 and table.find(id) == null);
        for (&table.entries) |*entry| {
            if (entry.id != 0) continue;
            entry.* = .{ .id = id, .asked = asked, .coded = null };
            table.used += 1;
            return;
        }
        // h2 refuses a stream past `concurrent_streams_max` (RFC 9113 §5.1.2), each entry's
        // request holds a stream until the entry goes, and h11 holds one request at a time.
        unreachable;
    }
};

/// Keeps what `request` asks, when the connection codes content.
pub fn on_request(connection: *Connection, request: event.Request) void {
    if (connection.config.encoders == null) return;
    connection.coding.add(request.id.number, coding_rules.asked(connection.config.codings, request));
}

/// Forgets request `id`, which ended before its response did, and gives back its encoder.
pub fn forget(connection: *Connection, id: Number) void {
    const entry = connection.coding.find(id) orelse return;
    release(connection, entry);
}

/// Forgets every request and gives back every encoder: nothing more is written.
pub fn forget_all(connection: *Connection) void {
    if (connection.config.encoders == null) return;
    for (&connection.coding.entries) |*entry| {
        if (entry.id != 0) release(connection, entry);
    }
    assert(connection.coding.used == 0);
}

fn release(connection: *Connection, entry: *Entry) void {
    assert(entry.id != 0);
    if (entry.coded) |coded| connection.config.encoders.?.give_back(coded.slot);
    entry.id = 0;
    connection.coding.used -= 1;
}

/// Writes the head of the response to request `id`, rewritten as its plan says when it is the
/// final one, and takes an encoder when its content is to be coded.
pub fn respond(connection: *Connection, id: Number, response: event.Response) SendError!void {
    const entry = connection.coding.find(id) orelse return write_head(connection, id, response.status, response.fields, response.end);
    // RFC 9110 §15.2: an interim response leaves the coding to the final one.
    if (is_interim(response.status)) return write_head(connection, id, response.status, response.fields, response.end);
    const encoders = connection.config.encoders.?;
    var rewritten: coding_fields.Rewritten = undefined;
    const head = try coding_response.plan_head(encoders, entry.asked, response, &rewritten);
    errdefer if (head.slot) |index| encoders.give_back(index);
    try write_head(connection, id, response.status, head.fields, response.end);
    if (head.slot) |index| {
        entry.coded = .{ .slot = index };
    } else {
        release(connection, entry);
    }
}

/// Writes content of the response to request `id`: the caller's octets, or for a coded response
/// as many as the encoder's ring takes, coded. Returns the octets taken.
pub fn write_body(connection: *Connection, id: Number, content: event.Content) SendError!usize {
    const entry = connection.coding.find(id) orelse return write_content(connection, id, content.octets, content.end);
    const coded = if (entry.coded) |*coded| coded else return write_content(connection, id, content.octets, content.end);
    // RFC 9110 §6.4.1: the content ended, and nothing follows it.
    if (coded.finishing) return error.SectionOutOfOrder;
    const encoders = connection.config.encoders.?;
    // What the ring holds goes out first, which leaves the encoder room.
    _ = try copy_out(connection, entry);
    const consumed = coded.code(encoders, content.octets);
    if (content.end and consumed == content.octets.len) coded.finishing = true;
    try advance(connection, entry);
    // RFC 9113 §6.9, RFC 9112 §7.1: the ring is full, and neither h2's window nor the room for
    // a chunk takes what it holds.
    if (consumed == 0 and content.octets.len > 0) return error.Blocked;
    return consumed;
}

/// Ends the response to request `id` with a trailer section, after every coded octet.
pub fn write_trailers(connection: *Connection, id: Number, fields: []const Field) SendError!void {
    const entry = connection.coding.find(id) orelse return write_trailer_section(connection, id, fields);
    const coded = if (entry.coded) |*coded| coded else return write_trailer_section(connection, id, fields);
    // RFC 9110 §6.5: a trailer section follows the content, and one that ended has none.
    if (coded.finishing and !coded.trailers) return error.SectionOutOfOrder;
    coded.finishing = true;
    coded.trailers = true;
    try advance(connection, entry);
    // RFC 9110 §6.5: the trailer section follows the content, so it waits for the coded octets
    // the ring still holds: `send`, `receive`, then call again.
    if (!coded.finished or coded.ring.held() > 0) return error.Blocked;
    try write_trailer_section(connection, id, fields);
    release(connection, entry);
}

/// Moves each coded response on, as `send` calls it: what each ring holds goes into the output,
/// and a response whose content ended is finished and ended. The responses go in the order their
/// requests took entries.
pub fn drain(connection: *Connection) void {
    const table = &connection.coding;
    // RFC 9113 §5.4.1, RFC 9112 §9.6: a connection that failed or was stopped sends no more
    // content.
    if (table.used == 0 or connection.stopped) return;
    for (&table.entries) |*entry| {
        if (entry.id == 0 or entry.coded == null) continue;
        // The protocol refused the response's content: its stream ended, so nothing reads it.
        advance(connection, entry) catch release(connection, entry);
    }
}

/// Copies what the ring holds into the output, finishes the encoder once the content ended, and
/// gives the encoder back once the response's end is written.
fn advance(connection: *Connection, entry: *Entry) SendError!void {
    const coded = &entry.coded.?;
    if (try copy_out(connection, entry)) return release(connection, entry);
    if (!coded.finishing or coded.finished) return;
    coded.finish(connection.config.encoders.?);
    if (try copy_out(connection, entry)) return release(connection, entry);
}

/// Copies what the ring holds into the output, as h11 and h2 frame content, and ends the content
/// once the encoder has finished and the ring is empty. Returns whether it wrote the end.
fn copy_out(connection: *Connection, entry: *Entry) SendError!bool {
    const coded = &entry.coded.?;
    const octets = connection.config.encoders.?.ring(coded.slot);
    // What the ring holds runs to its end, then on from its start.
    for (0..coding_response.steps_max) |_| {
        const held = coded.ring.oldest(octets);
        if (held.len == 0) break;
        const last = ends_with(coded, held.len);
        const taken = write_content(connection, entry.id, held, last) catch |failure| return blocked(failure);
        coded.ring.free(taken);
        if (taken < held.len) return false;
        if (last) return true;
    }
    // gzip and zlib end with a trailer (RFC 1952 §2.3, RFC 1950 §2.2), which the encoder writes in
    // the call that finishes, so the end always goes out with the last octets the ring held.
    assert(!ends_with(coded, 0));
    return false;
}

/// Whether the response's end goes out with `len` octets that are all the ring holds.
fn ends_with(coded: *const Coded, len: usize) bool {
    return coded.finished and !coded.trailers and len == coded.ring.held();
}

/// No room, or h2's window is closed: the rest waits for the next `send`.
fn blocked(failure: SendError) SendError!bool {
    if (failure == error.Blocked) return false;
    return failure;
}

fn is_interim(status: u16) bool {
    return status < @intFromEnum(http.status.Code.ok);
}

fn write_head(connection: *Connection, id: Number, status: u16, fields: []const Field, end: bool) SendError!void {
    switch (connection.session) {
        .h2 => try connection_h2.respond(connection, id, status, fields, end),
        .h11 => try connection_h11.respond(connection, id, status, fields, end),
        // RFC 9110 §3.4: a response answers a request, and none arrives before the handshake
        // completes.
        .none => return error.RequestUnknown,
    }
}

fn write_content(connection: *Connection, id: Number, octets: []const u8, end: bool) SendError!usize {
    return switch (connection.session) {
        .h2 => connection_h2.write_body(connection, id, octets, end),
        .h11 => connection_h11.write_body(connection, id, octets, end),
        // RFC 9110 §3.4: no request arrives before the handshake completes.
        .none => error.RequestUnknown,
    };
}

fn write_trailer_section(connection: *Connection, id: Number, fields: []const Field) SendError!void {
    switch (connection.session) {
        .h2 => try connection_h2.write_trailers(connection, id, fields),
        .h11 => try connection_h11.write_trailers(connection, id, fields),
        // RFC 9110 §3.4: no request arrives before the handshake completes.
        .none => return error.RequestUnknown,
    }
}
