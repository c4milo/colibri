//! The bounds colibri chose for h2, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const hpack = @import("hpack");
const wire = @import("wire");
const protocol = @import("constants_protocol.zig");

/// Most settings one SETTINGS frame colibri accepts can carry: the largest payload it accepts
/// (`frame_size_max`) over `setting_len`. The bound of the loop that walks a SETTINGS payload
/// (§6.5.3: values are processed in the order they appear).
pub const settings_per_frame_max: u32 = frame_size_max / protocol.setting_len;

// Limits colibri chooses (design §7).

/// Largest frame payload colibri accepts and the SETTINGS_MAX_FRAME_SIZE it advertises: the
/// RFC 9113 §4.2 floor, which every implementation must accept, and colibri never raises it.
pub const frame_size_max: u32 = protocol.max_frame_size_initial;

/// Most CONTINUATION frames one field block may span. RFC 9113 §6.10 sets no cap, so this is the
/// bound invariant 14 names; one past it is a connection error of ENHANCE_YOUR_CALM (§10.5).
pub const continuation_count_max: u32 = 32;

/// The longest representation of one field line the decoder accepts, in encoded octets. RFC 7541
/// §7.4 asks for limits on integers and on string literals, and colibri's are
/// `wire.constants.protocol.integer_len_max` and hpack's `name_len_max` and `value_len_max`, in decoded
/// octets. This is the longest line within all three:
///
/// - two size updates (§4.2), which count toward the block's first line;
/// - a literal with a literal name, whose first octet carries index 0 in its prefix and so has no
///   continuation octets (§5.1, §6.2). An indexed name is shorter: one integer replaces that octet,
///   the name's length and the name;
/// - the name's and the value's lengths;
/// - a name and a value at their limits, each octet at the longest Huffman code (Appendix B).
///
/// Every integer is at its longest, because §5.1 does not forbid continuation octets that carry
/// zeros. A line is measured from the end of the line before it. The measure does not depend on
/// where the fragments were cut, because RFC 9113 §4.3 makes a field block logically equivalent to
/// a single frame.
///
/// No line the decoder accepts is longer, so this refuses nothing the field-length limits admit. It
/// bounds the octets the field-block slot keeps of a line a fragment cut: a cut line whose octets
/// fed so far are longer is one the decoder would refuse once whole, and is a connection error of
/// COMPRESSION_ERROR.
pub const representation_len_max: u32 =
    hpack.constants.protocol.size_updates_per_block_max * wire.constants.protocol.integer_len_max +
    @sizeOf(u8) + 2 * wire.constants.protocol.integer_len_max +
    wire.huffman.encoded_len_max(hpack.constants.limits.name_len_max) +
    wire.huffman.encoded_len_max(hpack.constants.limits.value_len_max);

/// Octets of the field-block slot's buffer (decision 40, invariant 14): the octets kept from a line
/// the last fragment cut, at most `representation_len_max`, then the fragment being decoded, at
/// most `frame_size_max`.
pub const field_block_buffer_len: u32 = representation_len_max + frame_size_max;

/// The SETTINGS_MAX_CONCURRENT_STREAMS colibri advertises: the slot pool's capacity, so a peer that
/// honours the setting never finds the pool full (§5.1.2). colibri advertises it because the
/// initial value is unlimited.
pub const concurrent_streams_max: u32 = core.constants.limits.streams_per_connection_max;

/// The SETTINGS_MAX_HEADER_LIST_SIZE colibri advertises: the field section it can hold, measured
/// the way §6.5.2 measures it. Advisory to the peer (§10.5.1); colibri enforces it on the decoded
/// section and still decodes every octet (invariant 10).
pub const header_list_size_max: u32 = core.constants.limits.field_section_size_max;

/// Most SETTINGS frames colibri has sent and not yet seen acknowledged. A sender that could not
/// bound this would hold unbounded pending values (§6.5.3).
pub const settings_pending_max: u32 = 4;

/// Most PING frames colibri has sent and not yet seen answered.
pub const ping_pending_max: u32 = 4;

/// Most SETTINGS frames the peer has sent that colibri has not yet written an acknowledgment for
/// (§6.5.3). One past it, the connection stops reading until the caller writes what is pending.
pub const settings_ack_pending_max: u32 = 4;

/// Most PING frames the peer has sent that colibri has not yet answered (§6.7). Bounded for the
/// reason §10.5 gives: a peer that sends more of a frame than an endpoint answers costs memory.
pub const ping_ack_pending_max: u32 = 4;

/// The largest field block colibri sends, before it is cut into a HEADERS frame and the
/// CONTINUATION frames that follow it (§6.10). Policy: two frames' worth, so a section larger than
/// one frame is an ordinary case rather than a rare one. A caller that asks for more is refused,
/// never truncated. It holds every section colibri would accept, so what colibri can read it can
/// send.
pub const send_block_len_max: u32 = 2 * frame_size_max;

/// Most replies about single streams, a RST_STREAM (§6.4) or a WINDOW_UPDATE (§6.9), that colibri
/// holds unwritten for the frames it read. One past it, the connection stops reading until the
/// caller writes them. A RST_STREAM the caller asks for takes no slot: the stream's record owes it
/// (decision 113).
pub const stream_replies_max: u32 = 32;

comptime {
    assert(concurrent_streams_max > 0);
    assert(header_list_size_max >= core.constants.limits.field_name_len_max + core.constants.limits.field_value_len_max);
    assert(continuation_count_max > 0 and settings_pending_max > 0 and ping_pending_max > 0);
    assert(settings_ack_pending_max > 0 and ping_ack_pending_max > 0 and stream_replies_max > 0);
    assert(send_block_len_max >= core.constants.limits.field_section_size_max +
        hpack.constants.protocol.size_updates_per_block_max * wire.constants.protocol.integer_len_max);
    // The longest line fits in the most fragments one block may span, so the CONTINUATION count
    // refuses no line the field-length limits admit (§6.10).
    assert(representation_len_max <= (continuation_count_max + 1) * frame_size_max);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(2730, settings_per_frame_max);
    try expectEqual(16384, frame_size_max);
    try expectEqual(32, continuation_count_max);
    try expectEqual(31721, representation_len_max);
    try expectEqual(48105, field_block_buffer_len);
    try expectEqual(128, concurrent_streams_max);
    try expectEqual(16384, header_list_size_max);
    try expectEqual(4, settings_pending_max);
    try expectEqual(4, ping_pending_max);
    try expectEqual(4, settings_ack_pending_max);
    try expectEqual(4, ping_ack_pending_max);
    try expectEqual(32768, send_block_len_max);
    try expectEqual(32, stream_replies_max);
}
