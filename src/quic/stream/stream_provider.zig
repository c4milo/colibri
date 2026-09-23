//! The stream provider: the caller's octets, read back by offset (design §4.5). Part of design §8
//! step 9e.
//!
//! colibri retransmits stream data itself (RFC 9000 §13.3), so it must be able to read a stream's
//! octets again until the peer acknowledges them, and it holds no copy
//! ([decision 57](../../../docs/decisions.md)). The caller keeps the octets and colibri reads them
//! through this vtable, inside `send` alone, for new octets and for lost ones. It is a vtable and
//! not a callback at a time colibri chooses: colibri calls it only while the caller is in `send`,
//! as it calls the suite's `seal` (design §4).
const std = @import("std");
const assert = std.debug.assert;

pub const VTable = struct {
    /// Writes stream `stream_id`'s octets from `offset` into `output`, as many as fit, and returns
    /// how many. colibri asks only below the end the caller supplied, and never for a stream the
    /// caller has been told reached "Data Recvd" or was reset.
    ///
    /// Every call for the same offset must answer the same octets. RFC 9000 §2.2: "The data at a
    /// given offset MUST NOT change if it is sent multiple times". colibri holds no copy to check
    /// the answer against, so this is the provider's promise.
    ///
    /// Answering fewer octets than fit is allowed, and colibri frames what it was given.
    read: *const fn (context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize,
};

pub const StreamProvider = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub fn read(held: StreamProvider, stream_id: u64, offset: u64, output: []u8) usize {
        // A read with no room is colibri's defect: it sizes `output` from the packet's room and
        // has no reason to call without any.
        assert(output.len > 0);
        const written = held.vtable.read(held.context, stream_id, offset, output);
        assert(written <= output.len);
        return written;
    }

    /// The provider of a caller that sends no stream data. colibri reads a stream only after the
    /// caller supplied octets for it, so this one is never read; it answers nothing if it is.
    pub fn none() StreamProvider {
        return .{ .context = &none_context, .vtable = &none_vtable };
    }
};

var none_context: u8 = 0;

const none_vtable: VTable = .{ .read = read_nothing };

fn read_nothing(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    _ = offset;
    _ = output;
    return 0;
}
