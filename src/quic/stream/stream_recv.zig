//! The receiving part of a stream (RFC 9000 §3.2). Figure 3's states, and the final size rules
//! of §4.5 that go with them, because the final size is exactly what the "Size Known" state
//! knows.
//!
//! The states mirror only what a receiver can observe. There is no "Ready" here: §3.2 says the
//! receiving part tracks the delivery of data to the application, some of which the sender
//! cannot see, and does not track the sending states it cannot see either.
//!
//! §4.5's rules are enforced rather than reported, because they are about numbers this file
//! holds: a final size that changes, and data at or beyond one already known, are both
//! FINAL_SIZE_ERROR. §4.5 leaves generating them optional for closed streams, to spare an
//! endpoint the state; colibri holds the state while the stream exists and so answers.
const std = @import("std");
const assert = std.debug.assert;
const error_code = @import("../error_code.zig");

/// Figure 3's states (RFC 9000 §3.2).
pub const State = enum {
    recv,
    size_known,
    data_recvd,
    data_read,
    reset_recvd,
    reset_read,

    /// RFC 9000 §3.2: "Data Read" and "Reset Read" are terminal.
    pub fn is_terminal(state: State) bool {
        return state == .data_read or state == .reset_read;
    }
};

/// What happens to the receiving part of a stream.
pub const Event = enum {
    /// A STREAM or STREAM_DATA_BLOCKED frame arrived without the FIN bit.
    received_data,
    /// A STREAM frame carrying the FIN bit arrived, so the final size is known (§4.5).
    received_fin,
    /// Every octet up to the final size has arrived.
    all_data_received,
    /// The application read every octet.
    application_read_all,
    /// A RESET_STREAM frame arrived (§3.2, §4.5).
    received_reset,
    /// The application was told the stream was reset.
    application_read_reset,
};

pub const Transition = enum { taken, refused };

/// Why the final size rules refused something (RFC 9000 §4.5).
pub const FinalSizeError = error{
    /// A RESET_STREAM or STREAM frame gave a final size other than the one already known.
    FinalSizeChanged,
    /// Data arrived at or beyond a final size already known.
    DataBeyondFinalSize,
};

/// RFC 9000 §20.1: the code both refusals close the connection with.
pub fn connection_error_code(failure: FinalSizeError) u64 {
    return switch (failure) {
        error.FinalSizeChanged, error.DataBeyondFinalSize => error_code.final_size_error,
    };
}

pub const Receiving = struct {
    state: State,
    /// The final size, once the stream's end is known (RFC 9000 §4.5). Null in "Recv".
    final_size: ?u64,
    /// One past the largest offset received, which is what the final size must agree with.
    highest_offset: u64,

    /// RFC 9000 §3.2: the receiving part starts in "Recv".
    pub fn init() Receiving {
        return .{ .state = .recv, .final_size = null, .highest_offset = 0 };
    }

    pub fn on(receiving: *Receiving, event: Event) Transition {
        const next = receiving.next_state(event) orelse return .refused;
        receiving.state = next;
        return .taken;
    }

    fn next_state(receiving: *const Receiving, event: Event) ?State {
        return switch (event) {
            // RFC 9000 §3.2: in "Recv" the endpoint takes STREAM and STREAM_DATA_BLOCKED
            // frames; in "Size Known" it takes only retransmissions, which change no state.
            .received_data => switch (receiving.state) {
                .recv => .recv,
                .size_known => .size_known,
                else => null,
            },
            // RFC 9000 §3.2: the FIN makes the final size known.
            .received_fin => switch (receiving.state) {
                .recv => .size_known,
                // A retransmitted FIN says what is already known.
                .size_known => .size_known,
                else => null,
            },
            // RFC 9000 §3.2: once all data has arrived the part enters "Data Recvd". It may
            // happen on the same frame that made the size known.
            .all_data_received => switch (receiving.state) {
                .size_known => .data_recvd,
                else => null,
            },
            // RFC 9000 §3.2: "Data Recvd" persists until the application has the data.
            .application_read_all => switch (receiving.state) {
                .data_recvd => .data_read,
                else => null,
            },
            // RFC 9000 §3.2: a RESET_STREAM in any state that has not finished ends the part.
            // It is optional from "Data Recvd", where every octet already arrived.
            .received_reset => switch (receiving.state) {
                .recv, .size_known, .data_recvd => .reset_recvd,
                else => null,
            },
            .application_read_reset => switch (receiving.state) {
                .reset_recvd => .reset_read,
                else => null,
            },
        };
    }

    /// Takes a STREAM frame's offset and length against §4.5's rules, and records how far the
    /// stream now reaches. `fin` is the frame's FIN bit, which fixes the final size.
    pub fn on_stream_frame(receiving: *Receiving, offset: u64, len: u64, fin: bool) FinalSizeError!void {
        const reaches = offset + len;
        if (fin) {
            try receiving.set_final_size(reaches);
        } else if (receiving.final_size) |known| {
            // RFC 9000 §4.5: a receiver treats data at or beyond the final size as an error of
            // FINAL_SIZE_ERROR, even after the stream is closed.
            if (reaches > known) return error.DataBeyondFinalSize;
        }
        receiving.highest_offset = @max(receiving.highest_offset, reaches);
    }

    /// Takes a RESET_STREAM frame's Final Size against §4.5's rules. It records no offset:
    /// once a final size is known it is what §4.5 has the connection's flow controller account
    /// for, and nothing reads the highest offset again.
    pub fn on_reset(receiving: *Receiving, final_size: u64) FinalSizeError!void {
        try receiving.set_final_size(final_size);
    }

    fn set_final_size(receiving: *Receiving, final_size: u64) FinalSizeError!void {
        if (receiving.final_size) |known| {
            // RFC 9000 §4.5: once a final size is known it cannot change, and a frame
            // indicating a different one is an error of FINAL_SIZE_ERROR.
            if (final_size != known) return error.FinalSizeChanged;
            return;
        }
        // RFC 9000 §4.5: the final size accounts for every octet sent, so it cannot be below
        // what has already arrived.
        if (final_size < receiving.highest_offset) return error.FinalSizeChanged;
        receiving.final_size = final_size;
    }

    /// Whether the endpoint still offers flow control credit. RFC 9000 §3.2: in "Size Known" it
    /// no longer needs to send MAX_STREAM_DATA frames.
    /// Whether octets that arrive now are for the application: RFC 9000 §3.2 has "Recv" and
    /// "Size Known" take STREAM frames, and every later state has the octets already or wants none.
    pub fn accepts_data(receiving: *const Receiving) bool {
        return receiving.state == .recv or receiving.state == .size_known;
    }

    pub fn offers_credit(receiving: *const Receiving) bool {
        return receiving.state == .recv;
    }
};
