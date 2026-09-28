//! What design §9's h11 and h2 endpoints offer through ALPN (decision 88). colibri's `server` and
//! `client` choose each connection's protocol from what ALPN selected.
const std = @import("std");
const tls_provider = @import("tls_provider");

pub const Protocol = enum { h2, h11 };

/// What an endpoint offers through ALPN, most preferred first: both protocols in decision 88's
/// order, or h11 alone when the command line asks for it (RFC 7301 §3.1).
pub const alpn_both = [_][]const u8{ &tls_provider.constants.alpn_h2, tls_provider.constants.alpn_http_1_1 };
pub const alpn_h11 = [_][]const u8{tls_provider.constants.alpn_http_1_1};
