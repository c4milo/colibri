//! The sending part of a stream (RFC 9000 §3.1). Figure 2's states, and nothing else: what is
//! buffered, what is in flight and what the flow control limits are belong elsewhere, because
//! this file answers one question — may this endpoint send that, now.
//!
//! The states are the RFC's, and so are their names. `ready` accepts data from the application
//! but has sent none; `send` has sent some; `data_sent` has sent the FIN and only retransmits;
//! `data_recvd` is terminal and means every octet was acknowledged. `reset_sent` and
//! `reset_recvd` are the same pair for a stream abandoned with RESET_STREAM.
//!
//! An event that the current state does not admit is not an error here. RFC 9000 §3.3 decides
//! which frame types are a STREAM_STATE_ERROR and which are merely ignored, and it turns on what
//! sent the event — the application or the peer — so the caller reads `Transition` and acts.
const std = @import("std");
const assert = std.debug.assert;

/// Figure 2's states (RFC 9000 §3.1).
pub const State = enum {
    ready,
    send,
    data_sent,
    data_recvd,
    reset_sent,
    reset_recvd,

    /// RFC 9000 §3.1: "Data Recvd" and "Reset Recvd" are terminal.
    pub fn is_terminal(state: State) bool {
        return state == .data_recvd or state == .reset_recvd;
    }
};

/// What happens to the sending part of a stream.
pub const Event = enum {
    /// A STREAM or STREAM_DATA_BLOCKED frame went out (RFC 9000 §3.1).
    sent_data,
    /// A STREAM frame carrying the FIN bit went out.
    sent_fin,
    /// Every octet of the stream was acknowledged.
    all_data_acknowledged,
    /// The application abandoned the stream, or a STOP_SENDING frame arrived, so a
    /// RESET_STREAM frame went out (RFC 9000 §3.1, §3.5).
    sent_reset,
    /// The RESET_STREAM frame was acknowledged.
    reset_acknowledged,
};

/// What an event did.
pub const Transition = enum {
    /// The state moved, or the event was one the state already covers.
    taken,
    /// The state does not admit the event. RFC 9000 §3.3 decides whether that is an error, and
    /// the answer differs by what raised it, so this file reports and does not judge.
    refused,
};

pub const Sending = struct {
    state: State,

    /// RFC 9000 §3.1: the sending part starts in "Ready", opened by the application for a
    /// stream this endpoint initiates, and when the receiving part is created for a
    /// bidirectional stream the peer initiated.
    pub fn init() Sending {
        return .{ .state = .ready };
    }

    pub fn on(sending: *Sending, event: Event) Transition {
        const next = sending.next_state(event) orelse return .refused;
        sending.state = next;
        return .taken;
    }

    /// The state `event` leads to, or null when this state does not admit it.
    fn next_state(sending: *const Sending, event: Event) ?State {
        return switch (event) {
            // RFC 9000 §3.1: sending a STREAM or STREAM_DATA_BLOCKED frame enters "Send". In
            // "Send" more of them change nothing, and after the FIN none may be sent.
            .sent_data => switch (sending.state) {
                .ready, .send => .send,
                else => null,
            },
            // RFC 9000 §3.1: the FIN enters "Data Sent" from either state that may still send.
            .sent_fin => switch (sending.state) {
                .ready, .send => .data_sent,
                else => null,
            },
            // RFC 9000 §3.1: once all data is acknowledged the part enters "Data Recvd".
            .all_data_acknowledged => switch (sending.state) {
                .data_sent => .data_recvd,
                else => null,
            },
            // RFC 9000 §3.1: from "Ready", "Send" or "Data Sent" a RESET_STREAM abandons the
            // stream. A part already reset sends no second one.
            .sent_reset => switch (sending.state) {
                .ready, .send, .data_sent => .reset_sent,
                else => null,
            },
            // RFC 9000 §3.1: the acknowledgment of the RESET_STREAM enters "Reset Recvd".
            .reset_acknowledged => switch (sending.state) {
                .reset_sent => .reset_recvd,
                else => null,
            },
        };
    }

    /// Whether stream data may still be sent (RFC 9000 §3.1). "Data Sent" retransmits what was
    /// sent already and originates nothing.
    pub fn may_send_data(sending: *const Sending) bool {
        return sending.state == .ready or sending.state == .send;
    }

    /// Whether lost stream data is framed again. RFC 9000 §3.1: in "Send" and in "Data Sent" the
    /// endpoint "retransmits stream data as necessary", and §13.3 stops once a RESET_STREAM has
    /// gone out: "no further STREAM frames are needed".
    pub fn retransmits_data(sending: *const Sending) bool {
        return sending.state == .send or sending.state == .data_sent;
    }

    /// Whether flow control still applies. RFC 9000 §3.1: an endpoint in "Data Sent" need not
    /// check the limits or send STREAM_DATA_BLOCKED frames, because the final size is fixed.
    pub fn observes_flow_control(sending: *const Sending) bool {
        return sending.may_send_data();
    }
};
