//! One seed's messages for the h11 coding check (design §8 step 15c), and the octets a peer sends
//! for them. No colibri writer codes a body (decision 91), so the plan writes each message itself:
//! a head naming `gzip, chunked`, `deflate, chunked` or `chunked`, the body coded by stdx's
//! encoders in chunks of seeded lengths, and the last chunk (RFC 9112 §7.1).
//!
//! A seed's messages are requests to a colibri server or responses to a colibri client. Its last
//! message may carry a defect, and the plan says which refusal decision 91 gives it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const gzip = @import("gzip");
const zlib = @import("zlib");
const h11 = @import("h11");
const sim = @import("sim");

const Writer = core.Writer;
const Random = sim.Random;
const limits = sim.constants.h11_coding;
const Features = h11.coding.Features;
const Code = h11.http.status.Code;

pub const Coding = h11.message.Coding;
pub const GzipEncoder = gzip.Encoder(.{ .level = 1 });
pub const ZlibEncoder = zlib.Encoder(.{ .level = 1 });

comptime {
    assert(GzipEncoder.encoded_len_max(limits.body_len_max) <= limits.coded_len_max);
    assert(ZlibEncoder.encoded_len_max(limits.body_len_max) <= limits.coded_len_max);
}

/// Whose messages the seed sends: requests to a server, or responses to a client.
pub const Role = enum { server, client };

/// A defect the last message may carry, each met by a refusal of decision 91.
pub const Defect = enum {
    none,
    /// The stream's checksum one bit off (RFC 1950 §2.2, RFC 1952 §2.3.1): corrupt.
    checksum,
    /// The last coded octet left out, so the body ends inside the stream: corrupt.
    truncated,
    /// An octet after a zlib stream, inside the body.
    trailing,
    /// A zlib preset dictionary (RFC 1950 §2.2), which stdx refuses.
    dictionary,
    /// Every decoder taken before the message arrives (RFC 9110 §15.6.4).
    exhausted,
};

/// A zlib header with FDICT set and a valid FCHECK, and a dictionary identifier (RFC 1950 §2.2).
const dictionary_stream = "\x78\xbb\x00\x00\x00\x01";

/// RFC 1952 §2.3: a gzip member ends with CRC32 and ISIZE, four octets each. RFC 1950 §2.2: a
/// zlib stream ends with ADLER32, four octets.
const gzip_checksum_from_end = 8;
const zlib_checksum_from_end = 4;

/// Two members code a body's two halves.
const member_halves = 2;

/// The octets a copy repeats at least, DEFLATE's shortest match (RFC 1951 §3.2.5).
const copy_len_min = 3;
/// One pass in this many copies a run rather than writing a letter.
const copy_one_in = 2;
/// The letters a body is written in.
const letters = "abcdefghijklmnopqrstuvwxyz";

/// The digits of a chunk size, in hex (RFC 9112 §7.1).
const chunk_size_radix = 16;
const chunk_size_digits_max = 4;

pub const Message = struct {
    coding: Coding,
    body_len: u32,
    /// Whether a gzip body is written as two members (RFC 1952 §2.2).
    two_members: bool,
};

pub const Plan = struct {
    role: Role,
    count: u32,
    defect: Defect,
    messages: [limits.messages_max]Message,
    bodies: [limits.messages_max][limits.body_len_max]u8,

    pub fn draw(plan: *Plan, random: *Random) void {
        const roles = [_]Role{ .server, .client };
        plan.role = roles[random.below(roles.len)];
        plan.count = @intCast(random.between(1, limits.messages_max));
        plan.defect = if (random.below(limits.defect_one_in) == 0) draw_defect(random) else .none;
        for (plan.messages[0..plan.count], 0..) |*message, index| {
            message.* = .{ .coding = draw_coding(random), .body_len = 0, .two_members = false };
            message.body_len = fill(random, &plan.bodies[index]);
            message.two_members = message.coding == .gzip and random.below(limits.two_members_one_in) == 0;
        }
        plan.fit_defect();
    }

    /// Makes the last message one the defect applies to.
    fn fit_defect(plan: *Plan) void {
        const last = &plan.messages[plan.count - 1];
        switch (plan.defect) {
            .none => {},
            .checksum, .truncated => if (last.coding == .none) {
                last.coding = .gzip;
            },
            .trailing, .dictionary => last.coding = .deflate,
            .exhausted => {
                // The only decoder is taken from the start, so the messages before are uncoded.
                for (plan.messages[0 .. plan.count - 1]) |*message| message.coding = .none;
                if (last.coding == .none) last.coding = .gzip;
            },
        }
        if (last.coding != .gzip) last.two_members = false;
    }

    /// The status a server answers the defect with (decision 91).
    pub fn expected_status(plan: *const Plan) u16 {
        return switch (plan.defect) {
            .none => unreachable,
            .checksum, .truncated, .trailing => @intFromEnum(Code.bad_request),
            .dictionary => @intFromEnum(Code.not_implemented),
            .exhausted => @intFromEnum(Code.service_unavailable),
        };
    }

    /// Why a client fails on the defect (decision 91).
    pub fn expected_failure(plan: *const Plan) anyerror {
        return switch (plan.defect) {
            .none => unreachable,
            .checksum, .truncated => error.CodingCorrupt,
            .trailing => error.CodingTrailing,
            .dictionary => error.CodingFeatureRefused,
            .exhausted => error.DecodersExhausted,
        };
    }

    /// Messages a run must read whole before the defect, or all of them.
    pub fn whole_expected(plan: *const Plan) u32 {
        return if (plan.defect == .none) plan.count else plan.count - 1;
    }
};

fn draw_defect(random: *Random) Defect {
    const defects = [_]Defect{ .checksum, .truncated, .trailing, .dictionary, .exhausted };
    return defects[random.below(defects.len)];
}

fn draw_coding(random: *Random) Coding {
    const codings = [_]Coding{ .none, .gzip, .deflate };
    return codings[random.below(codings.len)];
}

/// A body of letters, with runs copied from earlier in it, so DEFLATE finds matches.
fn fill(random: *Random, octets: []u8) u32 {
    const len: usize = @intCast(random.between(1, octets.len));
    var index: usize = 0;
    // Every pass writes at least one octet.
    for (0..len) |_| {
        if (index == len) break;
        const room = len - index;
        if (index >= copy_len_min and room >= copy_len_min and random.below(copy_one_in) == 0) {
            const distance: usize = @intCast(random.between(1, @min(index, limits.copy_distance_max)));
            const run: usize = @intCast(random.between(copy_len_min, @min(room, limits.copy_len_max)));
            for (0..run) |offset| octets[index + offset] = octets[index + offset - distance];
            index += run;
        } else {
            octets[index] = letters[random.below(letters.len)];
            index += 1;
        }
    }
    return @intCast(len);
}

/// The encoders the stream is coded with, in storage the caller places.
pub const Encoders = struct {
    gzip: GzipEncoder,
    zlib: ZlibEncoder,
};

/// Writes every message of the plan into `output`, with chunk lengths drawn from `random`.
pub fn write_stream(plan: *const Plan, random: *Random, encoders: *Encoders, output: *Writer) !void {
    for (plan.messages[0..plan.count], 0..) |message, index| {
        try write_head(plan.role, message.coding, output);
        var coded_storage: [limits.coded_len_max + 1]u8 = undefined;
        var coded = try code(message, plan.bodies[index][0..message.body_len], encoders, &coded_storage);
        if (index + 1 == plan.count) coded = apply_defect(plan.defect, message.coding, coded, &coded_storage);
        try write_chunks(random, coded, output);
    }
}

fn write_head(role: Role, coding: Coding, output: *Writer) !void {
    const start = switch (role) {
        .server => "POST /m HTTP/1.1\r\nHost: a.example\r\n",
        .client => "HTTP/1.1 200 OK\r\n",
    };
    const framing = switch (coding) {
        .none => "Transfer-Encoding: chunked\r\n\r\n",
        .gzip => "Transfer-Encoding: gzip, chunked\r\n\r\n",
        .deflate => "Transfer-Encoding: deflate, chunked\r\n\r\n",
    };
    try output.write_bytes(start);
    try output.write_bytes(framing);
}

/// The body coded as the message says, into `storage`.
fn code(message: Message, body: []const u8, encoders: *Encoders, storage: []u8) ![]u8 {
    switch (message.coding) {
        .none => {
            @memcpy(storage[0..body.len], body);
            return storage[0..body.len];
        },
        .deflate => {
            encoders.zlib.init(Features.none());
            return storage[0..try encoders.zlib.encode_all(body, storage)];
        },
        .gzip => {
            // RFC 1952 §2.2: a gzip body may be a series of members, each coding part of it.
            const split = if (message.two_members) body.len / member_halves else body.len;
            encoders.gzip.init(Features.none());
            const first = try encoders.gzip.encode_all(body[0..split], storage);
            if (!message.two_members) return storage[0..first];
            encoders.gzip.init(Features.none());
            const second = try encoders.gzip.encode_all(body[split..], storage[first..]);
            return storage[0 .. first + second];
        },
    }
}

/// The coded octets as the defect leaves them.
fn apply_defect(defect: Defect, coding: Coding, coded: []u8, storage: []u8) []u8 {
    switch (defect) {
        .none, .exhausted => return coded,
        .checksum => {
            const from_end: usize = if (coding == .gzip) gzip_checksum_from_end else zlib_checksum_from_end;
            coded[coded.len - from_end] ^= 1;
            return coded;
        },
        .truncated => return coded[0 .. coded.len - 1],
        .trailing => {
            storage[coded.len] = 'x';
            return storage[0 .. coded.len + 1];
        },
        .dictionary => {
            @memcpy(storage[0..dictionary_stream.len], dictionary_stream);
            return storage[0..dictionary_stream.len];
        },
    }
}

/// `coded` in chunks of lengths drawn from `random`, then the last chunk (RFC 9112 §7.1).
fn write_chunks(random: *Random, coded: []const u8, output: *Writer) !void {
    var offset: usize = 0;
    // Every pass writes at least one octet of the body.
    for (0..coded.len) |_| {
        if (offset == coded.len) break;
        const len: usize = @intCast(random.between(1, @min(coded.len - offset, limits.chunk_len_max)));
        var digits: [chunk_size_digits_max]u8 = undefined;
        try output.write_bytes(try std.fmt.bufPrint(&digits, "{x}", .{len}));
        try output.write_bytes("\r\n");
        try output.write_bytes(coded[offset..][0..len]);
        try output.write_bytes("\r\n");
        offset += len;
    }
    try output.write_bytes("0\r\n\r\n");
}

comptime {
    assert(limits.chunk_len_max < std.math.pow(u64, chunk_size_radix, chunk_size_digits_max));
}
