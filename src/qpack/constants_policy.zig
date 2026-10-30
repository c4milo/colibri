//! The values colibri chose for qpack within what the RFCs allow, which size nothing.
//! Decision 137 groups them, and `constants.zig` exports this file as `policy`.

/// Decision 76: the encoder inserts an entry only when its size is at most the table capacity
/// over this, so that one line cannot evict every other entry.
pub const insert_size_divisor: u64 = 4;
