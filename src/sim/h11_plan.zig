//! One seed's HTTP/1.1 stream for the h11 split check (design §8 step 15a): up to
//! `h11_split_messages_max` messages of one role, pipelined, written by h11's own writers. A
//! request may carry no body, a fixed body or a chunked one with trailers; a response carries a
//! Content-Length or chunked, except a 204 and a 304, because a response with neither would run
//! until close and end the pipeline (RFC 9112 §6.3 rule 8).
//!
//! One seed in `h11_split_defect_one_in` plants a defect in one message, a shape RFC 9112 §11.2
//! ties to request smuggling or §2.2 refuses. The writers refuse to write any of them, so the plan
//! edits the octets the writers wrote. The messages before the defect must be read whole, and the
//! defect refused with the error `Defect.expected` names.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h11 = @import("h11");
const http = h11.http;
const sim = @import("sim");

const Random = sim.Random;
const Field = http.field.Field;
const constants = sim.constants;

pub const Role = h11.message.Role;

pub const BodyKind = enum { none, fixed, chunked };

/// What a message holds, which the check's reading of it must match.
pub const Message = struct {
    body_kind: BodyKind = .none,
    body_len: u32 = 0,
    body_crc32: u32 = 0,
    /// Field lines in its head.
    fields: u32 = 0,
    /// Field lines in its trailer section.
    trailers: u32 = 0,
};

pub const Defect = enum {
    none,
    /// The start line ends in a lone LF (RFC 9112 §2.2).
    lone_line_feed,
    /// The start line's LF is replaced, leaving a bare CR (RFC 9112 §2.2).
    bare_carriage_return,
    /// An SP between the first field name and its colon (RFC 9112 §5.1).
    space_before_colon,
    /// The first field value folded onto a second line, in a request (RFC 9112 §5.2).
    obs_fold,
    /// Content-Length beside chunked (RFC 9112 §6.1).
    length_and_chunked,
    /// The first chunk-size starts with an octet that is no hex digit (RFC 9112 §7.1).
    chunk_size_not_hex,

    /// The error reading the defective message must return.
    pub fn expected(defect: Defect) ?anyerror {
        return switch (defect) {
            .none => null,
            .lone_line_feed => error.BareLineFeed,
            .bare_carriage_return => error.BareCarriageReturn,
            .space_before_colon => error.WhitespaceBeforeColon,
            .obs_fold => error.ObsFold,
            .length_and_chunked => error.TransferEncodingWithContentLength,
            .chunk_size_not_hex => error.ChunkSizeInvalid,
        };
    }

    fn needs_chunked(defect: Defect) bool {
        return defect == .length_and_chunked or defect == .chunk_size_not_hex;
    }
};

const methods = [_][]const u8{ "GET", "POST", "PUT", "DELETE" };
const targets = [_][]const u8{ "/", "/a", "/b/c", "/d?e=f" };
const field_names = [_][]const u8{ "Accept", "User-Agent", "X-Request", "Cookie", "Cache-Control" };
const field_values = [_][]const u8{ "*/*", "sim/1", "abc", "k=v", "no-cache", "v" };
const trailer_names = [_][]const u8{ "Checksum", "X-Tail" };
const statuses = [_]u16{
    @intFromEnum(http.status.Code.ok),
    @intFromEnum(http.status.Code.created),
    @intFromEnum(http.status.Code.no_content),
    @intFromEnum(http.status.Code.not_modified),
    @intFromEnum(http.status.Code.not_found),
    @intFromEnum(http.status.Code.internal_server_error),
};
const reasons = [_][]const u8{ "", "OK", "Reason Phrase" };

/// The request's Host, which every request carries first (RFC 9112 §3.2).
const host_value = "a.example";

/// Field lines one head carries at most: Host, the extra lines and the framing line.
const head_fields_max = constants.h11_split_extra_fields_max + host_fields + framing_fields;
const host_fields = 1;
const framing_fields = 1;

/// The two roles a plan draws between.
const roles = [_]Role{ .request, .response };

/// The octets of a decimal Content-Length.
const length_digits_max = 20;

/// The octets a head's lines end with, and the empty line that ends it (RFC 9112 §2.1).
const line_end = "\r\n";
const head_end_octets = "\r\n\r\n";
const carriage_return_len = 1;
const colon_len = 1;

pub const Plan = struct {
    role: Role,
    messages: [constants.h11_split_messages_max]Message,
    count: u32,
    defect: Defect,
    /// The message the defect is in, when there is one.
    defect_index: u32,
    stream: [constants.h11_split_stream_len_max]u8,
    stream_len: u32,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.role = roles[random.below(roles.len)];
        plan.count = @intCast(random.between(1, constants.h11_split_messages_max));
        plan.defect = .none;
        plan.defect_index = 0;
        if (random.below(constants.h11_split_defect_one_in) == 0) {
            plan.defect = draw_defect(random, plan.role);
            plan.defect_index = @intCast(random.below(plan.count));
        }
        plan.stream_len = 0;
        for (0..plan.count) |index| {
            const defect: Defect = if (index == plan.defect_index) plan.defect else .none;
            const start = plan.stream_len;
            plan.messages[index] = plan.write_message(random, defect);
            if (defect != .none) plan.plant(defect, start);
        }
        assert(plan.stream_len <= plan.stream.len);
    }

    pub fn written(plan: *const Plan) []const u8 {
        return plan.stream[0..plan.stream_len];
    }

    fn write_message(plan: *Plan, random: *Random, defect: Defect) Message {
        var message: Message = .{};
        var fields: [head_fields_max]Field = undefined;
        var count: usize = 0;
        if (plan.role == .request) {
            fields[count] = .{ .name = "Host", .value = host_value };
            count += 1;
        }
        const extra = random.between(@intFromBool(plan.role == .response), constants.h11_split_extra_fields_max);
        for (0..extra) |_| {
            fields[count] = .{ .name = pick(random, &field_names), .value = pick(random, &field_values) };
            count += 1;
        }
        const status = if (plan.role == .response) draw_status(random, defect) else 0;
        const bodiless = is_bodiless(status);
        message.body_kind = if (bodiless) .none else draw_body_kind(random, plan.role, defect);
        var body: [constants.h11_split_body_len_max]u8 = undefined;
        var digits: [length_digits_max]u8 = undefined;
        if (message.body_kind == .fixed) {
            message.body_len = @intCast(random.below(body.len + 1));
            for (body[0..message.body_len]) |*octet| octet.* = @truncate(random.next());
            const text = std.fmt.bufPrint(&digits, "{d}", .{message.body_len}) catch unreachable;
            fields[count] = .{ .name = "Content-Length", .value = text };
            count += 1;
        }
        if (message.body_kind == .chunked) {
            fields[count] = .{ .name = "Transfer-Encoding", .value = "chunked" };
            count += 1;
        }
        message.fields = @intCast(count);
        plan.write_head(random, status, fields[0..count]);
        switch (message.body_kind) {
            .none => {},
            .fixed => {
                message.body_crc32 = std.hash.Crc32.hash(body[0..message.body_len]);
                plan.append(body[0..message.body_len]);
            },
            .chunked => plan.write_chunked(random, &message),
        }
        return message;
    }

    fn write_head(plan: *Plan, random: *Random, status: u16, fields: []const Field) void {
        const output = plan.stream[plan.stream_len..];
        const len = switch (plan.role) {
            .request => h11.message.write_request_head(output, pick(random, &methods), pick(random, &targets), fields),
            .response => h11.message.write_response_head(output, status, pick(random, &reasons), fields),
        } catch unreachable;
        plan.stream_len += @intCast(len);
    }

    fn write_chunked(plan: *Plan, random: *Random, message: *Message) void {
        var crc: std.hash.Crc32 = .init();
        var chunk: [constants.h11_split_chunk_len_max]u8 = undefined;
        const chunks = random.between(1, constants.h11_split_chunks_max);
        for (0..chunks) |_| {
            const len = random.between(1, chunk.len);
            for (chunk[0..len]) |*octet| octet.* = @truncate(random.next());
            crc.update(chunk[0..len]);
            message.body_len += @intCast(len);
            plan.stream_len += @intCast(h11.chunked.write_chunk(plan.stream[plan.stream_len..], chunk[0..len]) catch unreachable);
        }
        message.body_crc32 = crc.final();
        var trailers: [constants.h11_split_trailers_max]Field = undefined;
        const count = random.below(trailers.len + 1);
        for (trailers[0..count]) |*line| line.* = .{ .name = pick(random, &trailer_names), .value = pick(random, &field_values) };
        message.trailers = @intCast(count);
        plan.stream_len += @intCast(h11.chunked.write_last_chunk(plan.stream[plan.stream_len..], trailers[0..count]) catch unreachable);
    }

    fn append(plan: *Plan, octets: []const u8) void {
        @memcpy(plan.stream[plan.stream_len..][0..octets.len], octets);
        plan.stream_len += @intCast(octets.len);
    }

    /// Edits the message that starts at `start` so it carries `defect`.
    fn plant(plan: *Plan, defect: Defect, start: u32) void {
        const message = plan.stream[start..plan.stream_len];
        const start_line_end = start + @as(u32, @intCast(std.mem.indexOf(u8, message, line_end).?));
        const after_start_line = plan.stream[start_line_end..plan.stream_len];
        const first_colon = start_line_end + @as(u32, @intCast(std.mem.indexOfScalar(u8, after_start_line, ':').?));
        switch (defect) {
            .none => unreachable,
            // The CR of the start line's CRLF, removed.
            .lone_line_feed => plan.remove(start_line_end),
            // The LF of the start line's CRLF, replaced.
            .bare_carriage_return => plan.stream[start_line_end + carriage_return_len] = 'x',
            .space_before_colon => plan.insert(first_colon, " "),
            .obs_fold => plan.insert(first_colon + colon_len, "\r\n "),
            .length_and_chunked => plan.insert(start_line_end + @as(u32, line_end.len), "Content-Length: 1\r\n"),
            .chunk_size_not_hex => {
                const head_end = start + std.mem.indexOf(u8, message, head_end_octets).? + head_end_octets.len;
                plan.stream[head_end] = 'g';
            },
        }
    }

    fn insert(plan: *Plan, at: u32, octets: []const u8) void {
        assert(plan.stream_len + octets.len <= plan.stream.len);
        const tail = plan.stream[at..plan.stream_len];
        std.mem.copyBackwards(u8, plan.stream[at + octets.len ..][0..tail.len], tail);
        @memcpy(plan.stream[at..][0..octets.len], octets);
        plan.stream_len += @intCast(octets.len);
    }

    fn remove(plan: *Plan, at: u32) void {
        std.mem.copyForwards(u8, plan.stream[at .. plan.stream_len - 1], plan.stream[at + 1 .. plan.stream_len]);
        plan.stream_len -= 1;
    }
};

fn draw_defect(random: *Random, role: Role) Defect {
    const all = [_]Defect{ .lone_line_feed, .bare_carriage_return, .space_before_colon, .obs_fold, .length_and_chunked, .chunk_size_not_hex };
    const defect = all[random.below(all.len)];
    // A client joins obs-fold in a response (RFC 9112 §5.2), so it is a defect in a request only.
    if (role == .response and defect == .obs_fold) return .chunk_size_not_hex;
    return defect;
}

/// A response status. A defect that needs a chunked body needs a status that allows a body.
fn draw_status(random: *Random, defect: Defect) u16 {
    const status = statuses[random.below(statuses.len)];
    if (defect.needs_chunked() and is_bodiless(status)) return @intFromEnum(http.status.Code.ok);
    return status;
}

/// A 204 or 304 carries no body (RFC 9112 §6.3 rule 1).
fn is_bodiless(status: u16) bool {
    return status == @intFromEnum(http.status.Code.no_content) or status == @intFromEnum(http.status.Code.not_modified);
}

fn draw_body_kind(random: *Random, role: Role, defect: Defect) BodyKind {
    if (defect.needs_chunked()) return .chunked;
    // A request with neither framing field has no body (RFC 9112 §6.3 rule 7); a response would
    // run until close, so it carries a Content-Length of 0 instead.
    const kinds = [_]BodyKind{ .none, .fixed, .chunked };
    const kind = kinds[random.below(kinds.len)];
    if (role == .response and kind == .none) return .fixed;
    return kind;
}

fn pick(random: *Random, choices: []const []const u8) []const u8 {
    return choices[random.below(choices.len)];
}
