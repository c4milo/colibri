//! What the tests of the channel over TCP share (decision 124): the two channel types each of them
//! runs on, and the versions each type takes. Test-only.
const versions_module = @import("../versions.zig");
const channel_module = @import("channel.zig");

/// The channel of the default capacity, and one with no QUIC, which serves the same TCP
/// connections. Each test over TCP runs on both.
pub const channels = .{ channel_module.Channel, channel_module.ChannelOf(.{ .quic = false }) };

/// `versions` with h3 off for a channel with no QUIC, whose `init` refuses h3, and as given for
/// any other channel.
pub fn versions_for(channel: anytype, versions: versions_module.Versions) versions_module.Versions {
    var given = versions;
    if (!channel.capacity.quic) given.h3 = false;
    return given;
}
