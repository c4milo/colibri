# Decision 13: Correction to a premise: flow control is not shared

[All decisions](../decisions.md) · Section: [What is shared between h2 and h3](../decisions.md#what-is-shared-between-h2-and-h3)

The premise was one mechanism carried by different frames. The two mechanisms are not the same. h2's
flow control is a *credit* counter: 31-bit windows, an initial value of 65,535 (RFC 9113 §6.9.2),
`WINDOW_UPDATE` adding credit, DATA payloads alone consuming it, and a send window that must be a
*signed* quantity because a reduction in `SETTINGS_INITIAL_WINDOW_SIZE` can drive it negative and
RFC 9113 §6.9.2 requires tracking that. QUIC's flow control is a *high-water mark*: 62-bit absolute
offsets, `MAX_DATA` and `MAX_STREAM_DATA` naming the offset a peer may send up to rather than an
increment, every byte of stream data counting rather than one frame type's payload, and a final-size
rule with no h2 equivalent.

They are different algorithms with a common purpose. Cost: two implementations. Gain: no
accounting bug born of forcing a credit counter and an offset tracker through one interface. The
RFC 9113 §6.9.2 retroactive sweep — every stream's window adjusted on a settings change — is the
clearest evidence that the two cannot share one implementation; QUIC has no counterpart, because
an offset limit needs no retroactive adjustment.
