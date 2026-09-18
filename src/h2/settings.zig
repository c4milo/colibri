//! The six settings of RFC 9113 §6.5.2 as (identifier, value) pairs: their initial values, what
//! colibri advertises, the checks on a value the peer sends, and the acknowledgment discipline of
//! §6.5.3. The SETTINGS frame that carries the pairs belongs to the frame codec; this file reads
//! and writes no octet.
//!
//! `apply` checks one of the peer's values in this order (invariant 7):
//!   1. the identifier. An unknown or unsupported one is ignored and nothing changes (§6.5.2).
//!   2. the value, against the rule §6.5.2 states for that identifier: ENABLE_PUSH is 0 or 1, or
//!      `error.EnablePushInvalid`; then, at a client, ENABLE_PUSH is not 1, or
//!      `error.EnablePushByServer`; INITIAL_WINDOW_SIZE is at most 2^31-1, or
//!      `error.InitialWindowSizeTooLarge`; MAX_FRAME_SIZE is between 2^14 and 2^24-1, or
//!      `error.MaxFrameSizeOutOfRange`. A refused value leaves the held values as they were.
//!   3. the value replaces the one held (§6.5), and `apply` names what the connection must act on.
//! The caller applies a frame's values in order with no other frame processing between them, and
//! sends the ACK once all are applied (§6.5.3).
//!
//! colibri never pushes (decision 17): a client advertises ENABLE_PUSH 0, because the initial
//! value is 1, so a client that sends nothing leaves push enabled; a server omits it (§6.5.2).
//!
//! `Pending` holds the SETTINGS frames colibri has sent and not yet seen acknowledged, oldest
//! first, because an ACK acknowledges the oldest (§6.5.3). Every instant it reads is a parameter
//! (CLAUDE.md non-negotiable 3): it computes the deadline and the caller honours it (design §4.2).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Role = @import("role.zig").Role;

/// One setting as the wire carries it: a 16-bit identifier and a 32-bit value (RFC 9113 §6.5.1).
pub const Setting = struct {
    id: u16,
    value: u32,
};

/// The value of each of the six settings (RFC 9113 §6.5.2) for one endpoint: the peer's, held
/// after `apply`, or colibri's own, from `advertised`. Null is the RFC's "unlimited", which
/// MAX_CONCURRENT_STREAMS and MAX_HEADER_LIST_SIZE start at.
pub const Values = struct {
    header_table_size: u32,
    enable_push: u32,
    max_concurrent_streams: ?u32,
    initial_window_size: u32,
    max_frame_size: u32,
    max_header_list_size: ?u32,
};

/// The initial values of RFC 9113 §6.5.2: what each endpoint holds for its peer before any
/// SETTINGS frame arrives.
pub const initial: Values = .{
    .header_table_size = constants.header_table_size_initial,
    .enable_push = constants.enable_push_initial,
    .max_concurrent_streams = null,
    .initial_window_size = constants.initial_window_size_initial,
    .max_frame_size = constants.max_frame_size_initial,
    .max_header_list_size = null,
};

/// True when every value is one `apply` would accept: the positive space of its checks, and the
/// contract every `Values` colibri holds or sends must meet.
fn is_well_formed(values: Values) bool {
    const push_legal = values.enable_push == constants.enable_push_disabled or
        values.enable_push == constants.enable_push_enabled;
    return push_legal and values.initial_window_size <= constants.window_max and
        values.max_frame_size >= constants.max_frame_size_min and
        values.max_frame_size <= constants.max_frame_size_max;
}

/// The values colibri sends in its preface (RFC 9113 §3.4), the same for both roles: ENABLE_PUSH 0
/// for both (decision 17; §6.5.2), and the two settings whose initial value is unlimited always
/// advertised, so both are bounded (design §6.1).
pub fn advertised(role: Role) Values {
    const values: Values = .{
        .header_table_size = constants.header_table_size_advertised,
        .enable_push = constants.enable_push_disabled,
        .max_concurrent_streams = constants.concurrent_streams_max,
        .initial_window_size = constants.window_initial,
        .max_frame_size = constants.frame_size_max,
        .max_header_list_size = constants.header_list_size_max,
    };
    // RFC 9113 §6.5.2: a server MUST NOT explicitly set ENABLE_PUSH to 1.
    assert(role == .client or values.enable_push != constants.enable_push_enabled);
    // Decision 17: a client sends 0, because the initial value is 1 and sending nothing leaves
    // push enabled.
    assert(role == .server or values.enable_push == constants.enable_push_disabled);
    assert(is_well_formed(values));
    return values;
}

/// The (identifier, value) pairs `values` puts in a SETTINGS frame, in identifier order, written
/// into `buffer`. A server omits ENABLE_PUSH (RFC 9113 §6.5.2 lets it; decision 17), and a value
/// of null is omitted because the peer already holds the unlimited initial value (§6.5.2).
pub fn entries(values: Values, role: Role, buffer: *[constants.settings_count]Setting) []Setting {
    // RFC 9113 §6.5.2: a server MUST NOT explicitly set ENABLE_PUSH to 1, and a client sends 0
    // (decision 17), so both roles list 0. A contract point: the values are colibri's own, never
    // the peer's.
    assert(values.enable_push == constants.enable_push_disabled and is_well_formed(values));
    var count: u32 = 0;
    append(buffer, &count, constants.setting_header_table_size, values.header_table_size);
    // RFC 9113 §6.5.2: a server MAY omit ENABLE_PUSH; colibri's server always does (decision 17).
    if (role == .client) append(buffer, &count, constants.setting_enable_push, values.enable_push);
    if (values.max_concurrent_streams) |value| {
        append(buffer, &count, constants.setting_max_concurrent_streams, value);
    }
    append(buffer, &count, constants.setting_initial_window_size, values.initial_window_size);
    append(buffer, &count, constants.setting_max_frame_size, values.max_frame_size);
    if (values.max_header_list_size) |value| {
        append(buffer, &count, constants.setting_max_header_list_size, value);
    }
    assert(count <= constants.settings_count);
    return buffer[0..count];
}

/// Writes one pair at `count` and advances it. Identifiers are written in ascending order.
fn append(buffer: *[constants.settings_count]Setting, count: *u32, id: u16, value: u32) void {
    assert(count.* < constants.settings_count);
    assert(count.* == 0 or buffer[count.* - 1].id < id);
    buffer[count.*] = .{ .id = id, .value = value };
    count.* += 1;
}

/// Why `apply` refused a value, each a connection error of the type RFC 9113 §6.5.2 names:
/// FLOW_CONTROL_ERROR for INITIAL_WINDOW_SIZE and PROTOCOL_ERROR for the other three.
pub const ApplyError = error{
    EnablePushInvalid,
    EnablePushByServer,
    InitialWindowSizeTooLarge,
    MaxFrameSizeOutOfRange,
};

/// The window size before and after a SETTINGS_INITIAL_WINDOW_SIZE change.
pub const WindowChange = struct {
    old: u32,
    new: u32,
};

/// What `apply` changed, for the two settings the connection acts on at once.
pub const Change = union(enum) {
    /// SETTINGS_INITIAL_WINDOW_SIZE: every stream's send window moves by `new - old`, which may
    /// be negative, and a change that makes any window exceed `window_max` is a connection error
    /// of FLOW_CONTROL_ERROR (RFC 9113 §6.9.2). The connection does both from `old` and `new`.
    initial_window_size: WindowChange,
    /// SETTINGS_HEADER_TABLE_SIZE: the limit the peer's decoder set on colibri's encoder, in force
    /// once colibri acknowledges the frame (RFC 9113 §4.3.1).
    header_table_size: u32,
    /// A setting the connection reads where it applies and need not act on now.
    other,
};

/// Applies one of the peer's settings to `values`, in the order the frame lists them (RFC 9113
/// §6.5.3). `role` is colibri's own. Returns null for an identifier colibri ignores, and
/// otherwise what changed. A refused value leaves `values` as they were.
pub fn apply(values: *Values, id: u16, value: u32, role: Role) ApplyError!?Change {
    assert(is_well_formed(values.*));
    defer assert(is_well_formed(values.*));
    switch (id) {
        constants.setting_header_table_size => {
            values.header_table_size = value;
            return .{ .header_table_size = value };
        },
        constants.setting_enable_push => return apply_enable_push(values, value, role),
        constants.setting_max_concurrent_streams => {
            // RFC 9113 §6.5.2: 0 SHOULD NOT be treated as special, so it is held like any value.
            values.max_concurrent_streams = value;
            return .other;
        },
        constants.setting_initial_window_size => return apply_initial_window_size(values, value),
        constants.setting_max_frame_size => return apply_max_frame_size(values, value),
        constants.setting_max_header_list_size => {
            // RFC 9113 §6.5.2: advisory, so no value is refused.
            values.max_header_list_size = value;
            return .other;
        },
        // RFC 9113 §6.5.2: an unknown or unsupported identifier MUST be ignored.
        else => return null,
    }
}

fn apply_enable_push(values: *Values, value: u32, role: Role) ApplyError!?Change {
    const legal = value == constants.enable_push_disabled or value == constants.enable_push_enabled;
    // RFC 9113 §6.5.2: any value other than 0 or 1 MUST be treated as a connection error of
    // PROTOCOL_ERROR.
    if (!legal) return error.EnablePushInvalid;
    // RFC 9113 §6.5.2: a client MUST treat receipt of ENABLE_PUSH set to 1 as a connection error
    // of PROTOCOL_ERROR, because a server MUST NOT set it.
    if (role == .client and value == constants.enable_push_enabled) return error.EnablePushByServer;
    values.enable_push = value;
    return .other;
}

fn apply_initial_window_size(values: *Values, value: u32) ApplyError!?Change {
    // RFC 9113 §6.5.2: values above the maximum flow-control window size of 2^31-1 MUST be
    // treated as a connection error of FLOW_CONTROL_ERROR.
    if (value > constants.window_max) return error.InitialWindowSizeTooLarge;
    const old = values.initial_window_size;
    values.initial_window_size = value;
    return .{ .initial_window_size = .{ .old = old, .new = value } };
}

fn apply_max_frame_size(values: *Values, value: u32) ApplyError!?Change {
    const in_range = value >= constants.max_frame_size_min and value <= constants.max_frame_size_max;
    // RFC 9113 §6.5.2: the value MUST be between the initial value (2^14) and the maximum allowed
    // frame size (2^24-1), inclusive; a value outside that range is a connection error of
    // PROTOCOL_ERROR.
    if (!in_range) return error.MaxFrameSizeOutOfRange;
    values.max_frame_size = value;
    return .other;
}

/// One SETTINGS frame sent and not yet acknowledged: the values it carried and when it was sent.
pub const Sent = struct {
    values: Values,
    sent_at_ns: u64,
};

/// The SETTINGS frames colibri has sent and not yet seen acknowledged, oldest first. An ACK
/// acknowledges the oldest (RFC 9113 §6.5.3), so this is a queue, held in a ring of
/// `settings_pending_max` slots inside a struct the caller owns (decision 35).
pub const Pending = struct {
    ring: [constants.settings_pending_max]Sent,
    /// The oldest frame's slot; the newest is `count - 1` slots after it, wrapping.
    first: u32,
    count: u32,

    /// Empties the queue. Every slot holds `initial`, so no slot is ever read uninitialised.
    pub fn init(pending: *Pending) void {
        pending.ring = @splat(.{ .values = initial, .sent_at_ns = 0 });
        pending.first = 0;
        pending.count = 0;
        assert(pending.len() == 0 and pending.deadline_ns() == null);
    }

    /// Frames sent and not yet acknowledged.
    pub fn len(pending: *const Pending) u32 {
        assert(pending.count <= constants.settings_pending_max);
        return pending.count;
    }

    /// Records a frame carrying `values`, sent at `now_ns`, as the newest. Instants do not go
    /// backwards, and stay far enough from the end of the range that the deadline is computable.
    pub fn push(pending: *Pending, values: Values, now_ns: u64) error{TooManyPending}!void {
        assert(pending.count <= constants.settings_pending_max and is_well_formed(values));
        assert(now_ns <= std.math.maxInt(u64) - constants.settings_timeout_ns);
        assert(pending.count == 0 or now_ns >= pending.newest().sent_at_ns);
        // RFC 9113 §6.5.3: on an ACK the sender "can rely on the values from the oldest
        // unacknowledged SETTINGS frame having been applied", so colibri holds each frame's values
        // until its ACK, and `settings_pending_max` bounds how many (design §7).
        if (pending.count == constants.settings_pending_max) return error.TooManyPending;
        const slot = (pending.first + pending.count) % constants.settings_pending_max;
        pending.ring[slot] = .{ .values = values, .sent_at_ns = now_ns };
        pending.count += 1;
    }

    /// Pops the oldest frame, whose values are in force from now on (RFC 9113 §6.5.3): the
    /// connection binds the peer's encoder to a reduced HEADER_TABLE_SIZE (§4.3.1) and moves every
    /// receive window by a changed INITIAL_WINDOW_SIZE (§6.9.2). Null when nothing is pending.
    pub fn acknowledge(pending: *Pending) ?Values {
        assert(pending.count <= constants.settings_pending_max);
        if (pending.count == 0) return null;
        const oldest = pending.ring[pending.first];
        pending.first = (pending.first + 1) % constants.settings_pending_max;
        pending.count -= 1;
        assert(is_well_formed(oldest.values));
        return oldest.values;
    }

    /// The oldest frame's instant plus `settings_timeout_ns`: when its acknowledgment is overdue
    /// and the caller calls back (design §4.2). Null when nothing is pending.
    pub fn deadline_ns(pending: *const Pending) ?u64 {
        assert(pending.count <= constants.settings_pending_max);
        if (pending.count == 0) return null;
        return pending.ring[pending.first].sent_at_ns + constants.settings_timeout_ns;
    }

    /// True from the deadline on. RFC 9113 §6.5.3 lets the sender issue a connection error of
    /// SETTINGS_TIMEOUT when no ACK arrives in a reasonable time; colibri takes the MAY.
    pub fn is_timed_out(pending: *const Pending, now_ns: u64) bool {
        const deadline = pending.deadline_ns() orelse return false;
        return now_ns >= deadline;
    }

    fn newest(pending: *const Pending) *const Sent {
        assert(pending.count > 0);
        return &pending.ring[(pending.first + pending.count - 1) % constants.settings_pending_max];
    }
};

// Tests.

const testing = std.testing;

/// An instant a test sends a frame at, in nanoseconds. Any value works: time is a parameter.
const test_sent_at_ns: u64 = 1_000_000_000;

/// colibri's own values with one field varied, so a test can tell frames apart.
fn test_values(header_table_size: u32) Values {
    var values = advertised(.client);
    values.header_table_size = header_table_size;
    return values;
}

test "the initial values are the ones RFC 9113 §6.5.2 gives" {
    try testing.expectEqual(4096, initial.header_table_size);
    try testing.expectEqual(1, initial.enable_push);
    try testing.expectEqual(null, initial.max_concurrent_streams);
    try testing.expectEqual(65_535, initial.initial_window_size);
    try testing.expectEqual(16_384, initial.max_frame_size);
    try testing.expectEqual(null, initial.max_header_list_size);
}

test "a client advertises all six settings in identifier order, ENABLE_PUSH 0 among them" {
    var buffer: [constants.settings_count]Setting = undefined;
    const listed = entries(advertised(.client), .client, &buffer);
    try testing.expectEqual(6, listed.len);
    for (listed, 1..) |setting, id| try testing.expectEqual(id, setting.id);
    try testing.expectEqual(constants.header_table_size_advertised, listed[0].value);
    try testing.expectEqual(0, listed[1].value);
    try testing.expectEqual(constants.concurrent_streams_max, listed[2].value);
    try testing.expectEqual(constants.window_initial, listed[3].value);
    try testing.expectEqual(constants.frame_size_max, listed[4].value);
    try testing.expectEqual(constants.header_list_size_max, listed[5].value);
}

test "a server advertises five settings and omits ENABLE_PUSH" {
    var buffer: [constants.settings_count]Setting = undefined;
    const listed = entries(advertised(.server), .server, &buffer);
    try testing.expectEqual(5, listed.len);
    const expected_ids = [_]u16{ 1, 3, 4, 5, 6 };
    for (listed, expected_ids) |setting, id| try testing.expectEqual(id, setting.id);
    try testing.expectEqual(0, advertised(.server).enable_push);
}

test "entries omits a setting whose value is unlimited" {
    var buffer: [constants.settings_count]Setting = undefined;
    var values = advertised(.client);
    values.max_concurrent_streams = null;
    values.max_header_list_size = null;
    const listed = entries(values, .client, &buffer);
    try testing.expectEqual(4, listed.len);
    const expected_ids = [_]u16{ 1, 2, 4, 5 };
    for (listed, expected_ids) |setting, id| try testing.expectEqual(id, setting.id);
}

test "apply holds each legal value in place of the one before" {
    var values = initial;
    _ = try apply(&values, 1, 0, .client);
    _ = try apply(&values, 2, 0, .server);
    _ = try apply(&values, 3, 0, .client);
    _ = try apply(&values, 4, 2_147_483_647, .client);
    _ = try apply(&values, 5, 16_777_215, .client);
    _ = try apply(&values, 6, 0, .client);
    try testing.expectEqual(0, values.header_table_size);
    try testing.expectEqual(0, values.enable_push);
    try testing.expectEqual(0, values.max_concurrent_streams);
    try testing.expectEqual(2_147_483_647, values.initial_window_size);
    try testing.expectEqual(16_777_215, values.max_frame_size);
    try testing.expectEqual(0, values.max_header_list_size);
}

test "apply holds 2^32-1 for the three settings RFC 9113 §6.5.2 leaves unbounded" {
    var values = initial;
    _ = try apply(&values, 1, 0xffff_ffff, .client);
    _ = try apply(&values, 3, 0xffff_ffff, .server);
    _ = try apply(&values, 6, 0xffff_ffff, .client);
    try testing.expectEqual(0xffff_ffff, values.header_table_size);
    try testing.expectEqual(0xffff_ffff, values.max_concurrent_streams);
    try testing.expectEqual(0xffff_ffff, values.max_header_list_size);
}

test "apply refuses ENABLE_PUSH other than 0 or 1 at either role" {
    var values = initial;
    try testing.expectError(error.EnablePushInvalid, apply(&values, 2, 2, .client));
    try testing.expectError(error.EnablePushInvalid, apply(&values, 2, 2, .server));
    try testing.expectError(error.EnablePushInvalid, apply(&values, 2, 0xffff_ffff, .server));
    try testing.expectEqual(initial, values);
}

test "a client refuses ENABLE_PUSH 1 from the server and a server accepts it from the client" {
    var values = initial;
    try testing.expectError(error.EnablePushByServer, apply(&values, 2, 1, .client));
    try testing.expectEqual(initial, values);
    try testing.expectEqual(Change.other, (try apply(&values, 2, 0, .client)).?);
    try testing.expectEqual(0, values.enable_push);
    try testing.expectEqual(Change.other, (try apply(&values, 2, 1, .server)).?);
    try testing.expectEqual(1, values.enable_push);
}

test "apply refuses INITIAL_WINDOW_SIZE above 2^31-1 and accepts 2^31-1" {
    var values = initial;
    try testing.expectError(error.InitialWindowSizeTooLarge, apply(&values, 4, 2_147_483_648, .client));
    try testing.expectError(error.InitialWindowSizeTooLarge, apply(&values, 4, 0xffff_ffff, .server));
    try testing.expectEqual(initial, values);
    const change = (try apply(&values, 4, 2_147_483_647, .client)).?;
    const expected: Change = .{ .initial_window_size = .{ .old = 65_535, .new = 2_147_483_647 } };
    try testing.expectEqual(expected, change);
    try testing.expectEqual(2_147_483_647, values.initial_window_size);
}

test "apply refuses MAX_FRAME_SIZE outside 2^14 to 2^24-1 and accepts both bounds" {
    var values = initial;
    try testing.expectError(error.MaxFrameSizeOutOfRange, apply(&values, 5, 16_383, .client));
    try testing.expectError(error.MaxFrameSizeOutOfRange, apply(&values, 5, 0, .client));
    try testing.expectError(error.MaxFrameSizeOutOfRange, apply(&values, 5, 16_777_216, .server));
    try testing.expectEqual(initial, values);
    try testing.expectEqual(Change.other, (try apply(&values, 5, 16_384, .client)).?);
    try testing.expectEqual(16_384, values.max_frame_size);
    try testing.expectEqual(Change.other, (try apply(&values, 5, 16_777_215, .server)).?);
    try testing.expectEqual(16_777_215, values.max_frame_size);
}

test "apply ignores an unknown identifier and changes nothing" {
    var values = initial;
    for ([_]u16{ 0, 7, 8, 0xffff }) |id| {
        try testing.expectEqual(null, try apply(&values, id, 0xffff_ffff, .client));
        try testing.expectEqual(null, try apply(&values, id, 0, .server));
    }
    try testing.expectEqual(initial, values);
}

test "apply names the two changes the connection acts on and .other for the rest" {
    var values = initial;
    try testing.expectEqual(Change{ .header_table_size = 0 }, (try apply(&values, 1, 0, .client)).?);
    try testing.expectEqual(Change{ .header_table_size = 8192 }, (try apply(&values, 1, 8192, .client)).?);
    const window: Change = .{ .initial_window_size = .{ .old = 65_535, .new = 0 } };
    try testing.expectEqual(window, (try apply(&values, 4, 0, .client)).?);
    const grown: Change = .{ .initial_window_size = .{ .old = 0, .new = 65_536 } };
    try testing.expectEqual(grown, (try apply(&values, 4, 65_536, .client)).?);
    try testing.expectEqual(Change.other, (try apply(&values, 3, 100, .client)).?);
    try testing.expectEqual(Change.other, (try apply(&values, 6, 100, .client)).?);
}

test "acknowledge pops the oldest pending frame first and null when none is pending" {
    var pending: Pending = undefined;
    pending.init();
    try testing.expectEqual(null, pending.acknowledge());
    try pending.push(test_values(1), test_sent_at_ns);
    try pending.push(test_values(2), test_sent_at_ns + 1);
    try pending.push(test_values(3), test_sent_at_ns + 2);
    try testing.expectEqual(3, pending.len());
    try testing.expectEqual(1, pending.acknowledge().?.header_table_size);
    try testing.expectEqual(2, pending.acknowledge().?.header_table_size);
    try testing.expectEqual(3, pending.acknowledge().?.header_table_size);
    try testing.expectEqual(null, pending.acknowledge());
    try testing.expectEqual(0, pending.len());
}

test "push refuses a frame past settings_pending_max and accepts one once an ACK frees a slot" {
    var pending: Pending = undefined;
    pending.init();
    for (0..constants.settings_pending_max) |index| {
        try pending.push(test_values(@intCast(index)), test_sent_at_ns);
    }
    try testing.expectEqual(constants.settings_pending_max, pending.len());
    try testing.expectError(error.TooManyPending, pending.push(test_values(99), test_sent_at_ns));
    try testing.expectEqual(0, pending.acknowledge().?.header_table_size);
    try pending.push(test_values(99), test_sent_at_ns);
    try testing.expectEqual(constants.settings_pending_max, pending.len());
}

test "the ring wraps: frames pushed after acknowledgments still pop oldest first" {
    var pending: Pending = undefined;
    pending.init();
    for (0..constants.settings_pending_max) |index| {
        try pending.push(test_values(@intCast(index)), test_sent_at_ns);
    }
    _ = pending.acknowledge();
    _ = pending.acknowledge();
    try pending.push(test_values(10), test_sent_at_ns);
    try pending.push(test_values(11), test_sent_at_ns);
    const expected = [_]u32{ 2, 3, 10, 11 };
    for (expected) |header_table_size| {
        try testing.expectEqual(header_table_size, pending.acknowledge().?.header_table_size);
    }
    try testing.expectEqual(null, pending.acknowledge());
}

test "the deadline is the oldest frame's instant plus settings_timeout_ns, and none when idle" {
    var pending: Pending = undefined;
    pending.init();
    try testing.expectEqual(null, pending.deadline_ns());
    try pending.push(advertised(.client), test_sent_at_ns);
    try pending.push(advertised(.client), test_sent_at_ns + 5);
    try testing.expectEqual(test_sent_at_ns + constants.settings_timeout_ns, pending.deadline_ns());
    _ = pending.acknowledge();
    try testing.expectEqual(test_sent_at_ns + 5 + constants.settings_timeout_ns, pending.deadline_ns());
    _ = pending.acknowledge();
    try testing.expectEqual(null, pending.deadline_ns());
}

test "is_timed_out turns true at the deadline instant and not one nanosecond before" {
    var pending: Pending = undefined;
    pending.init();
    try testing.expect(!pending.is_timed_out(test_sent_at_ns + constants.settings_timeout_ns));
    try pending.push(advertised(.server), test_sent_at_ns);
    const deadline = pending.deadline_ns().?;
    try testing.expect(!pending.is_timed_out(test_sent_at_ns));
    try testing.expect(!pending.is_timed_out(deadline - 1));
    try testing.expect(pending.is_timed_out(deadline));
    try testing.expect(pending.is_timed_out(deadline + 1));
    _ = pending.acknowledge();
    try testing.expect(!pending.is_timed_out(deadline + 1));
}
