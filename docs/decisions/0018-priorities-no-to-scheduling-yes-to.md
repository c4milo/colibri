# Decision 18: Priorities: no to scheduling, yes to the mandatory parsing

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

RFC 9113 §5.3.2 deprecates RFC 7540's priority signalling but deliberately keeps the frame syntax
and some of its mandatory handling for interoperability, so colibri still owes all of: accept
`PRIORITY` (0x02) in every stream state including idle and closed; a stream error of
`FRAME_SIZE_ERROR` when its length is not exactly 5 bytes; a connection error of `PROTOCOL_ERROR`
when its stream identifier is 0x00; and skipping exactly 5 bytes when `HEADERS` carries the PRIORITY
flag 0x20, or the HPACK block starts at the wrong offset. Skipping the wrong number of bytes is the
bug this entry exists to prevent.

RFC 9218 is optional: §1 says servers "can ignore client priority signals and still successfully
serve HTTP responses", and §10 says expressing priority is only a suggestion. colibri ignores it
and applies the unknown-extension rules — discard `PRIORITY_UPDATE` as an unknown frame type,
and ignore the `SETTINGS_NO_RFC7540_PRIORITIES` identifier if a peer sends it. RFC 9218 §2.1
offers one cheap position, sending `SETTINGS_NO_RFC7540_PRIORITIES` with value 1 in the first
SETTINGS frame, immutable thereafter, to declare that 7540 signals are ignored; §2.1 permits
that without adopting 9218's scheme, and colibri does not send it today — its preface carries
the six settings of RFC 9113 §6.5.2 alone. §2.1 permits that without adopting 9218's scheme.
