//! The protocols design §9's h11 and h2 endpoints speak (decision 88). colibri's `server` and
//! `client` choose each connection's protocol from what ALPN selected.

pub const Protocol = enum { h2, h11 };
