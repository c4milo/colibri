//! A `tls.Provider` that performs no cryptography (decisions 8 and 10, design §8 step 5). It is
//! test-only, lives in `src/sim/` and is never packaged: colibri's library carries no
//! implementation of either vtable and never will (CLAUDE.md non-negotiable 2).
//!
//! What it is for is the shape, not the secrecy. It frames records exactly as RFC 8446 §5.1 sizes
//! them — a five-octet header, the body, and a tag of the length an AEAD would add — so record
//! boundaries fall in different places from h2 frame boundaries and a check sees colibri reassemble
//! across them. The body is copied, not protected.
//!
//! Everything it answers is set by the test before the run: how many handshake flights it owes,
//! which protocol it reports, which version and suite, and what each record holds. It reads no
//! clock, draws no random number and allocates nothing, so one seed replays byte for byte
//! (invariants 4, 5 and 6).
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const constants = @import("constants.zig");

/// RFC 8446 §5.1: the ContentType of a record.
pub const ContentType = enum(u8) {
    alert = 21,
    handshake = 22,
    application_data = 23,
};

/// RFC 8446 §4: the HandshakeType of the messages a check scripts after the handshake.
pub const HandshakeType = enum(u8) {
    new_session_ticket = 4,
    certificate_request = 13,
    key_update = 24,
};

/// What one endpoint of the null provider answers. A test fills it before the run and never during
/// one.
pub const NullProvider = struct {
    /// Handshake flights still owed before the handshake completes. A flight is one record.
    flights_owed: u8 = 0,
    /// Flights the peer still owes, counted down as `handshake_read` consumes them.
    flights_expected: u8 = 0,
    /// What `negotiated_alpn` reports. Null reports no selection at all.
    alpn: ?[]const u8 = &tls.constants.alpn_h2,
    /// What `negotiated_parameters` reports.
    parameters: ?tls.Negotiated = .{
        .version = tls.constants.version_tls_1_3,
        .cipher_suite = tls.constants.cipher_suite_aes_128_gcm_sha256,
    },
    /// The alert held for the next `take_alert`, which the call clears (RFC 8446 §6).
    alert_held: ?tls.AlertReport = null,
    /// Whether `send_close_notify` has already written its record (RFC 8446 §6.1).
    close_sent: bool = false,

    /// The vtable, filled once and shared. Every connection in a run uses the same one, which is
    /// what `Provider.vtable` being read-only is for.
    var table: tls.VTable = undefined;

    /// Fills the shared vtable. Called once before any provider is handed out.
    pub fn install() void {
        table = .{
            .handshake_read = handshake_read,
            .handshake_write = handshake_write,
            .encrypt_record = encrypt_record,
            .decrypt_record = decrypt_record,
            .negotiated_alpn = negotiated_alpn,
            .handshake_complete = handshake_complete,
            .negotiated_parameters = negotiated_parameters,
            .take_alert = take_alert,
            .send_close_notify = send_close_notify,
            .initiate_key_update = initiate_key_update,
            .export_keying_material = export_keying_material,
        };
    }

    /// The vtable-shaped view colibri holds.
    pub fn provider(self: *NullProvider) tls.Provider {
        return .{ .context = @ptrCast(self), .vtable = &table };
    }

    fn of(context: *anyopaque) *NullProvider {
        return @ptrCast(@alignCast(context));
    }

    fn of_const(context: *const anyopaque) *const NullProvider {
        return @ptrCast(@alignCast(context));
    }

    fn handshake_read(context: *anyopaque, input: []const u8, now_ns: u64) tls.provider.HandshakeReadError!usize {
        // The instant is a parameter because a provider that checked a certificate would need one;
        // this one reads no clock and needs nothing (CLAUDE.md non-negotiable 3).
        _ = now_ns;
        const self = of(context);
        if (self.flights_expected == 0) return 0;
        const record = read_record(input) orelse return 0;
        self.flights_expected -= 1;
        return record.total_len;
    }

    fn handshake_write(context: *anyopaque, output: []u8, now_ns: u64) tls.provider.HandshakeWriteError!usize {
        _ = now_ns;
        const self = of(context);
        if (self.flights_owed == 0) return 0;
        const written = write_record(output, .handshake, &.{}) catch return error.NoSpaceLeft;
        self.flights_owed -= 1;
        return written;
    }

    fn encrypt_record(context: *anyopaque, plaintext: []const u8, output: []u8) tls.provider.SealError!tls.provider.Sealed {
        _ = context;
        // RFC 8446 §5.1: one record carries at most 2^14 octets of plaintext.
        const body_len = @min(plaintext.len, tls.constants.record_plaintext_len_max);
        const written = write_record(output, .application_data, plaintext[0..body_len]) catch
            return error.NoSpaceLeft;
        return .{ .consumed = body_len, .written = written };
    }

    fn decrypt_record(context: *anyopaque, input: []const u8, plaintext: []u8) tls.provider.OpenError!tls.provider.Opened {
        _ = context;
        const record = read_record(input) orelse
            return .{ .consumed = 0, .plaintext_len = 0, .content = .incomplete };
        const body = input[header_len .. header_len + record.body_len];
        if (body.len > plaintext.len) return error.NoSpaceLeft;
        @memcpy(plaintext[0..body.len], body);
        return .{
            .consumed = record.total_len,
            .plaintext_len = body.len,
            .content = classify(record.content, body),
        };
    }

    fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
        const self = of_const(context);
        // RFC 7301 §3.1: the selected protocol is known only once the handshake has chosen it.
        if (self.flights_owed != 0 or self.flights_expected != 0) return null;
        return self.alpn;
    }

    fn handshake_complete(context: *const anyopaque) bool {
        const self = of_const(context);
        return self.flights_owed == 0 and self.flights_expected == 0;
    }

    fn negotiated_parameters(context: *const anyopaque) ?tls.Negotiated {
        const self = of_const(context);
        if (!handshake_complete(context)) return null;
        return self.parameters;
    }

    fn take_alert(context: *anyopaque) ?tls.AlertReport {
        const self = of(context);
        defer self.alert_held = null;
        return self.alert_held;
    }

    fn send_close_notify(context: *anyopaque, output: []u8) tls.provider.CloseError!usize {
        const self = of(context);
        // RFC 8446 §6.1: each party sends it before closing its write side, and once is enough.
        if (self.close_sent) return 0;
        const written = write_record(output, .alert, &.{@intFromEnum(tls.Alert.close_notify)}) catch
            return error.NoSpaceLeft;
        self.close_sent = true;
        return written;
    }

    fn initiate_key_update(
        context: *anyopaque,
        request: tls.provider.KeyUpdateRequest,
        output: []u8,
    ) tls.provider.KeyUpdateError!usize {
        _ = context;
        // RFC 8446 §4.6.3: the KeyUpdate message carries the request as its one octet.
        const body = [_]u8{ @intFromEnum(HandshakeType.key_update), @intFromEnum(request) };
        return write_record(output, .handshake, &body) catch error.NoSpaceLeft;
    }

    fn export_keying_material(
        context: *anyopaque,
        label: []const u8,
        context_value: ?[]const u8,
        output: []u8,
    ) tls.provider.ExportError!void {
        _ = context;
        _ = label;
        _ = context_value;
        // The null provider derives nothing: it holds no secret, so there is nothing to export.
        // A provider without an exporter answers this, which is what the member is for.
        _ = output;
        return error.Unsupported;
    }
};

/// The ContentType, the legacy version and the length (RFC 8446 §5.1).
const header_len: usize = tls.constants.record_header_len;

/// What `read_record` found.
const Record = struct {
    content: ContentType,
    body_len: usize,
    total_len: usize,
};

/// The ContentType an octet names, or null when RFC 8446 §5.1 gives it none.
fn content_type_of(octet: u8) ?ContentType {
    return switch (octet) {
        @intFromEnum(ContentType.alert) => .alert,
        @intFromEnum(ContentType.handshake) => .handshake,
        @intFromEnum(ContentType.application_data) => .application_data,
        else => null,
    };
}

/// Reads one record's header, or null when `input` holds no whole record.
fn read_record(input: []const u8) ?Record {
    if (input.len < header_len) return null;
    const content = content_type_of(input[constants.record_content_type_offset]) orelse return null;
    // RFC 8446 §5.1: the length is the two octets after the version, in network byte order.
    const high: usize = input[constants.record_length_offset];
    const low: usize = input[constants.record_length_offset + 1];
    const declared: usize = (high << @bitSizeOf(u8)) | low;
    if (declared < constants.record_tag_len) return null;
    const total = header_len + declared;
    if (input.len < total) return null;
    return .{ .content = content, .body_len = declared - constants.record_tag_len, .total_len = total };
}

/// Writes one record: the header RFC 8446 §5.1 sizes, the body, and the tag an AEAD would add.
fn write_record(output: []u8, content: ContentType, body: []const u8) error{NoSpaceLeft}!usize {
    const declared = body.len + constants.record_tag_len;
    const total = header_len + declared;
    if (output.len < total or declared > tls.constants.record_ciphertext_len_max) return error.NoSpaceLeft;
    output[constants.record_content_type_offset] = @intFromEnum(content);
    // RFC 8446 §5.1: legacy_record_version is 0x0303 on every record after the first flight.
    output[constants.record_version_offset] = constants.record_legacy_version_octet;
    output[constants.record_version_offset + 1] = constants.record_legacy_version_octet;
    output[constants.record_length_offset] = @intCast(declared >> @bitSizeOf(u8));
    output[constants.record_length_offset + 1] = @truncate(declared);
    @memcpy(output[header_len .. header_len + body.len], body);
    @memset(output[header_len + body.len .. total], 0);
    return total;
}

/// What a record holds, in the terms colibri's vtable reports (RFC 8446 §5.1, §4).
fn classify(content: ContentType, body: []const u8) tls.Content {
    return switch (content) {
        .application_data => .application_data,
        .alert => .alert,
        .handshake => classify_handshake(body),
    };
}

/// The handshake message a post-handshake record holds (RFC 8446 §4).
fn classify_handshake(body: []const u8) tls.Content {
    if (body.len == 0) return .new_session_ticket;
    // RFC 9113 §9.2.3 names the three a post-handshake record may hold, and CertificateRequest is
    // the one an HTTP/2 client must refuse.
    return switch (body[0]) {
        @intFromEnum(HandshakeType.key_update) => .key_update,
        @intFromEnum(HandshakeType.certificate_request) => .certificate_request,
        else => .new_session_ticket,
    };
}

const testing = std.testing;

test "a record carries the sizes RFC 8446 §5.1 gives it, and round-trips its body" {
    NullProvider.install();
    var endpoint: NullProvider = .{};
    var output: [64]u8 = undefined;
    const sealed = try NullProvider.encrypt_record(@ptrCast(&endpoint), "hello", &output);
    try testing.expectEqual(5, sealed.consumed);
    // Five octets of header, five of body, sixteen of tag.
    try testing.expectEqual(header_len + 5 + constants.record_tag_len, sealed.written);
    var plaintext: [64]u8 = undefined;
    const opened = try NullProvider.decrypt_record(@ptrCast(&endpoint), output[0..sealed.written], &plaintext);
    try testing.expectEqual(sealed.written, opened.consumed);
    try testing.expectEqualStrings("hello", plaintext[0..opened.plaintext_len]);
    try testing.expectEqual(tls.Content.application_data, opened.content);
}

test "a record that is not whole yet is incomplete, not an error" {
    NullProvider.install();
    var endpoint: NullProvider = .{};
    var output: [64]u8 = undefined;
    const sealed = try NullProvider.encrypt_record(@ptrCast(&endpoint), "hello", &output);
    var plaintext: [64]u8 = undefined;
    for (0..sealed.written) |cut| {
        const opened = try NullProvider.decrypt_record(@ptrCast(&endpoint), output[0..cut], &plaintext);
        try testing.expectEqual(tls.Content.incomplete, opened.content);
        try testing.expectEqual(0, opened.consumed);
    }
}

test "§4: the handshake message type decides what a post-handshake record holds" {
    NullProvider.install();
    var endpoint: NullProvider = .{};
    var output: [64]u8 = undefined;
    var plaintext: [64]u8 = undefined;
    const cases = [_]struct { HandshakeType, tls.Content }{
        .{ .new_session_ticket, .new_session_ticket },
        .{ .key_update, .key_update },
        .{ .certificate_request, .certificate_request },
    };
    for (cases) |case| {
        const body = [_]u8{@intFromEnum(case[0])};
        const written = try write_record(&output, .handshake, &body);
        const opened = try NullProvider.decrypt_record(@ptrCast(&endpoint), output[0..written], &plaintext);
        try testing.expectEqual(case[1], opened.content);
    }
}

test "the handshake completes after the scripted flights, and nothing is negotiated before" {
    NullProvider.install();
    var endpoint: NullProvider = .{ .flights_owed = 1, .flights_expected = 1 };
    const view = endpoint.provider();
    // RFC 7301 §3.1: in TLS 1.3 the selected protocol arrives in EncryptedExtensions, so there is
    // no answer before the handshake finishes.
    try testing.expect(!view.is_complete());
    try testing.expect(!view.speaks_h2());
    try testing.expectEqual(null, view.vtable.negotiated_parameters(view.context));
    var output: [64]u8 = undefined;
    const written = try view.vtable.handshake_write(view.context, &output, 0);
    try testing.expect(written > 0);
    try testing.expectEqual(written, try view.vtable.handshake_read(view.context, output[0..written], 0));
    try testing.expect(view.is_complete());
    try testing.expect(view.speaks_h2());
    try testing.expectEqual(
        tls.constants.version_tls_1_3,
        view.vtable.negotiated_parameters(view.context).?.version,
    );
}

test "§6.1: close_notify is written once and reports itself as the peer's alert" {
    NullProvider.install();
    var endpoint: NullProvider = .{};
    const view = endpoint.provider();
    var output: [64]u8 = undefined;
    const written = try view.vtable.send_close_notify(view.context, &output);
    try testing.expect(written > 0);
    // RFC 8446 §6.1: sending it twice is not required, and the second call writes nothing.
    try testing.expectEqual(0, try view.vtable.send_close_notify(view.context, &output));
    var plaintext: [64]u8 = undefined;
    const opened = try view.vtable.decrypt_record(view.context, output[0..written], &plaintext);
    try testing.expectEqual(tls.Content.alert, opened.content);
    try testing.expectEqual(@intFromEnum(tls.Alert.close_notify), plaintext[0]);
}

test "the exporter is the member a provider without one refuses" {
    NullProvider.install();
    var endpoint: NullProvider = .{};
    const view = endpoint.provider();
    var secret: [32]u8 = undefined;
    // RFC 8446 §7.5 standardises the interface without obliging a stack to offer it.
    try testing.expectEqual(
        error.Unsupported,
        view.vtable.export_keying_material(view.context, "label", null, &secret),
    );
}
