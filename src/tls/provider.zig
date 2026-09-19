//! The TLS provider vtable in record mode, which serves h2 (decision 8). No production
//! implementation is in this tree and none ever will be: colibri never links a TLS stack, never
//! holds a private key and never chooses a cipher suite (CLAUDE.md non-negotiable 2).
//!
//! The shape is a context pointer and a read-only table of function pointers. Two words per
//! connection, and the table sits in read-only data however many connections share it. The
//! alternative, a comptime interface parameterised on the implementation, was rejected: it would
//! make `h2.Connection` generic, and decision 35 requires one connection size to pin with a
//! comptime assert.
//!
//! Every member is mandatory, so colibri never compares a function pointer against null and
//! invariant 6's rule that no branch reads a pointer value stays intact. A provider without an
//! exporter supplies one that answers `error.Unsupported`.
//!
//! Every octet lives in a slice the caller owns. colibri declares no TLS buffer of its own and
//! names only the smallest sizes that never refuse (`constants.zig`). Both handshake members take
//! the instant as a parameter, because a certificate's validity period needs one and no source
//! file in this repository may read a clock (non-negotiable 3).
const std = @import("std");
const constants = @import("constants.zig");
const alert = @import("alert.zig");

const Alert = alert.Alert;
const AlertReport = alert.AlertReport;

/// Why a provider refused the peer's handshake octets. One error, because there is one recovery:
/// RFC 8446 §6 forbids sending or receiving data after an error alert, so colibri closes.
pub const HandshakeReadError = error{TlsFailed};

/// Why a provider did not write the handshake octets it owes.
pub const HandshakeWriteError = error{
    /// The provider gave up while producing its flight (RFC 8446 §6).
    TlsFailed,
    /// The output is shorter than `constants.record_write_len_min`. Nothing was written and no
    /// provider state moved.
    NoSpaceLeft,
};

/// Why a provider did not protect a record.
pub const SealError = error{
    TlsFailed,
    /// The output cannot hold a header, one octet of plaintext and the tag (RFC 8446 §5.2).
    NoSpaceLeft,
    /// There are no application traffic keys yet: RFC 8446 §7.1 derives them from the transcript
    /// through the Finished. colibri asserts `handshake_complete` before it calls, so a provider
    /// answering this is failing closed on a defect of colibri's.
    HandshakeIncomplete,
    /// RFC 8446 §5.5's usage limit for the AEAD is reached. The recovery is `initiate_key_update`
    /// and a retry, which is why it is not `TlsFailed`.
    KeyExhausted,
};

/// Why a provider did not open a record.
pub const OpenError = error{
    /// RFC 8446 §5.2: the record failed to decrypt or its length is past what §5.1 permits. The
    /// provider has raised the alert and `take_alert` names it.
    TlsFailed,
    /// The plaintext buffer cannot hold the record's fragment (RFC 8446 §5.1).
    NoSpaceLeft,
    /// A protected record arrived before the keys that open it exist (RFC 8446 §7.1).
    HandshakeIncomplete,
};

/// Why a provider did not write a `close_notify` (RFC 8446 §6.1).
pub const CloseError = error{NoSpaceLeft};

/// Why a provider did not update its keys (RFC 8446 §4.6.3).
pub const KeyUpdateError = error{
    TlsFailed,
    NoSpaceLeft,
    /// RFC 8446 §4.6.3 permits KeyUpdate only after the sender's Finished.
    HandshakeIncomplete,
    /// The provider does not offer key updates.
    Unsupported,
};

/// Why a provider did not export keying material (RFC 8446 §7.5).
pub const ExportError = error{
    /// The exporter derives from `exporter_master_secret`, which exists after the server's
    /// Finished (RFC 8446 §7.5).
    HandshakeIncomplete,
    /// RFC 8446 §7.5 standardises the interface without obliging a stack to offer it, and every
    /// member of this vtable is mandatory, so a provider without an exporter answers this.
    Unsupported,
    /// The output is longer than one HKDF-Expand produces, 255 hash lengths (RFC 5869 §2.3). The
    /// provider enforces it, because the negotiated hash is private to it.
    OutputTooLong,
};

/// What `encrypt_record` protected and wrote.
pub const Sealed = struct {
    /// Octets of the plaintext that went into records, at most
    /// `constants.record_plaintext_len_max` per record (RFC 8446 §5.1).
    consumed: usize,
    /// Octets of the output the records occupy.
    written: usize,
};

/// What one record held, which only the provider can see once the record is protected. This is
/// what makes RFC 9113 §9.2.3 enforceable without colibri owning any TLS.
pub const Content = enum {
    /// No whole record was present: nothing was consumed and nothing was written.
    incomplete,
    /// The h2 byte stream. colibri reads the plaintext only for this one.
    application_data,
    /// RFC 9113 §9.2.3 permits it after the handshake, and h2 does nothing with it.
    new_session_ticket,
    /// RFC 9113 §9.2.3 permits it. RFC 8446 §4.6.3 may require an answering KeyUpdate, which
    /// `handshake_write` carries.
    key_update,
    /// RFC 9113 §9.2.3: an HTTP/2 client MUST treat a post-handshake CertificateRequest as a
    /// connection error of type PROTOCOL_ERROR.
    certificate_request,
    /// `take_alert` names it. RFC 8446 §6 forbids data after an error alert.
    alert,
};

/// What `decrypt_record` opened.
pub const Opened = struct {
    /// Octets of the input the record occupied, its header and tag included. 0 when no whole
    /// record was present, and `content` is then `.incomplete`.
    consumed: usize,
    /// Octets written into the plaintext buffer.
    plaintext_len: usize,
    /// What the record held.
    content: Content,
};

/// Whether the peer is asked to update its own keys in turn (RFC 8446 §4.6.3). The values are
/// the RFC's.
pub const KeyUpdateRequest = enum(u8) {
    update_not_requested = 0,
    update_requested = 1,
};

/// The calls colibri makes on a TLS stack it does not own. Decision 8 fixes this list.
pub const VTable = struct {
    /// Gives the provider the peer's octets and returns how many it consumed. It consumes whole
    /// records only, so input holding no whole record returns 0, which is not an error.
    handshake_read: *const fn (context: *anyopaque, input: []const u8, now_ns: u64) HandshakeReadError!usize,

    /// Writes the handshake octets the provider owes and returns how many. 0 means it owes
    /// nothing. RFC 8446 §4.6.3 makes a peer's `update_requested` owe a KeyUpdate, so colibri
    /// calls this for the life of the connection and not only until the handshake completes.
    handshake_write: *const fn (context: *anyopaque, output: []u8, now_ns: u64) HandshakeWriteError!usize,

    /// Protects the plaintext as one or more records (RFC 8446 §5.2). Returning what it consumed
    /// as well as what it wrote lets colibri hand over a whole pass of output at once, which is
    /// one crossing of the boundary per pass rather than one per record.
    encrypt_record: *const fn (context: *anyopaque, plaintext: []const u8, output: []u8) SealError!Sealed,

    /// Opens one record. The input and the plaintext buffer never overlap, which colibri asserts
    /// at the call site.
    decrypt_record: *const fn (context: *anyopaque, input: []const u8, plaintext: []u8) OpenError!Opened,

    /// The protocol the handshake selected (RFC 7301 §3.1), or null before it has one. In TLS 1.3
    /// the selection arrives in EncryptedExtensions, so null is the correct answer until the
    /// provider has decrypted that message, not an error.
    negotiated_alpn: *const fn (context: *const anyopaque) ?[]const u8,

    /// Whether the handshake has completed. RFC 8446 Appendix E.5 requires that an application be
    /// able to tell.
    handshake_complete: *const fn (context: *const anyopaque) bool,

    /// The alert the provider raised or received, which the call clears, so a second call returns
    /// null. The optional is not a style choice: `close_notify` is description 0 and is the
    /// commonest alert on a healthy connection, so a zero sentinel would report every orderly
    /// close as no alert at all.
    take_alert: *const fn (context: *anyopaque) ?AlertReport,

    /// Writes the `close_notify` RFC 8446 §6.1 requires before closing the write side, and
    /// returns how many octets. A second call returns 0, which is unambiguous because a short
    /// buffer is an error and not a count.
    send_close_notify: *const fn (context: *anyopaque, output: []u8) CloseError!usize,

    /// Writes a KeyUpdate and switches the sending keys (RFC 8446 §4.6.3). colibri never starts
    /// one on its own: RFC 8446 §5.5 leaves the usage limits to the implementation and only the
    /// provider counts records, so a counter here would put a branch on the per-record path.
    initiate_key_update: *const fn (context: *anyopaque, request: KeyUpdateRequest, output: []u8) KeyUpdateError!usize,

    /// RFC 8446 §7.5's exporter. The output's length is the RFC's `key_length`, so there is no
    /// separate length parameter. The context value is optional because §7.5 keeps RFC 5705's
    /// interface, which distinguishes no context from an empty one.
    export_keying_material: *const fn (
        context: *anyopaque,
        label: []const u8,
        context_value: ?[]const u8,
        output: []u8,
    ) ExportError!void,
};

/// One TLS session, as colibri sees it: state colibri never reads, and the calls it makes on it.
pub const Provider = struct {
    /// The provider's own state. colibri passes it back unchanged on every call and never
    /// dereferences it.
    context: *anyopaque,
    /// Read-only, so one table serves every connection a provider holds.
    vtable: *const VTable,

    /// True when the handshake has selected exactly the "h2" identifier RFC 9113 §3.1 defines.
    /// Anything else, a missing selection included, is the same answer: h2 does not run here.
    pub fn speaks_h2(provider: Provider) bool {
        const selected = provider.vtable.negotiated_alpn(provider.context) orelse return false;
        // RFC 9113 §3.1: "h2" is the two-octet sequence 0x68, 0x32.
        return std.mem.eql(u8, selected, &constants.alpn_h2);
    }

    /// Whether the handshake has completed (RFC 8446 Appendix E.5).
    pub fn is_complete(provider: Provider) bool {
        return provider.vtable.handshake_complete(provider.context);
    }
};

test "a provider that selects h2 speaks h2, and every other answer does not" {
    const testing = std.testing;
    const Fake = struct {
        selected: ?[]const u8,
        complete: bool,

        fn alpn(context: *const anyopaque) ?[]const u8 {
            const self: *const @This() = @ptrCast(@alignCast(context));
            return self.selected;
        }
        fn done(context: *const anyopaque) bool {
            const self: *const @This() = @ptrCast(@alignCast(context));
            return self.complete;
        }
    };
    var state: Fake = .{ .selected = null, .complete = false };
    var table: VTable = undefined;
    table.negotiated_alpn = Fake.alpn;
    table.handshake_complete = Fake.done;
    const provider: Provider = .{ .context = @ptrCast(&state), .vtable = &table };
    // RFC 9113 §3.1: nothing is selected yet, so h2 does not run.
    try testing.expect(!provider.speaks_h2());
    try testing.expect(!provider.is_complete());
    state.selected = "http/1.1";
    try testing.expect(!provider.speaks_h2());
    // RFC 9113 §3.2: the "h2c" identifier is never selected.
    state.selected = "h2c";
    try testing.expect(!provider.speaks_h2());
    state.selected = &constants.alpn_h2;
    state.complete = true;
    try testing.expect(provider.speaks_h2());
    try testing.expect(provider.is_complete());
}
