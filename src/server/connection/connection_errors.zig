//! The errors of a server connection over TCP (decision 100), which `connection.zig` exports and
//! the QUIC connection shares.
/// Why `receive` stopped reading for good: the peer broke the protocol, or TLS failed (RFC 9846
/// §6). What the connection owes the peer, such as a GOAWAY, an error response or an alert, waits
/// for `send`, and the caller closes once `should_close` says so.
pub const Error = error{ConnectionFailed};

pub const StartError = error{
    /// chapulin refused the TLS configuration (`tls.record.Error.Refused`).
    TlsRefused,
    /// A limit of `Config.deadlines` is 0 or past `timeout_ns_max` (decision 110).
    DeadlineInvalid,
    /// `Config.versions` allows neither h11 nor h2, which leaves a TCP connection nothing to speak
    /// (RFC 9114 §3.1, decision 117). Or an endpoint has no TLS identity, or `versions` turns h3
    /// off, which leaves its QUIC connections nothing to speak.
    NoVersion,
    /// The endpoint's TLS identity: its key does not sign, or its signature does not verify (RFC
    /// 9846 §4.5.2).
    IdentityRefused,
    /// The endpoint's TLS identity holds a longer chain than `certificate_chain_len_max`, more
    /// suites than `cipher_suites_max`, or an order of suites a build without AES-GCM cannot keep
    /// (decision 97).
    TooManyCertificates,
    TooManySuites,
    SuitesUnavailable,
};

pub const SendError = error{
    /// `output` has no room for what the call writes: `send`, then call again.
    NoSpaceLeft,
    /// `write_body` wrote nothing: no room, h2's flow-control window is closed (RFC 9113 §6.9), or
    /// a coded response's ring is full. Or `write_trailers` found a coded response's octets not all
    /// written. `send`, `receive`, then call again.
    Blocked,
    /// No request with this id waits for this call: it never arrived, is answered, or is cancelled.
    RequestUnknown,
    /// The connection is closing and writes no more responses.
    ConnectionClosed,
    /// The status is not a code from 100 to 599 (RFC 9110 §15), or is 101, which colibri does not
    /// implement (RFC 9110 §15.2.2).
    StatusInvalid,
    /// A field line h11 or h2 refuses to send (RFC 9110 §5.1, §5.5, RFC 9113 §8.2).
    FieldLineInvalid,
    /// A response after the final one, content before it, or trailers before it (RFC 9110 §6.4.1,
    /// RFC 9113 §8.1).
    SectionOutOfOrder,
    /// More field lines than `field_count_max`, or a field section larger than the output holds
    /// when empty.
    SectionTooLarge,
    /// Trailers h11 cannot carry: on a response that is not chunked (RFC 9112 §7.1.2), or a field
    /// that frames or routes the message (RFC 9110 §6.5.1).
    TrailersRefused,
    /// Content that does not match the response's Content-Length (RFC 9110 §8.6).
    ContentLengthMismatch,
};
