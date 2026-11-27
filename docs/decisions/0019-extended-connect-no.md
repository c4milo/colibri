# Decision 19: Extended CONNECT: no

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

`SETTINGS_ENABLE_CONNECT_PROTOCOL` is identifier 0x08 with initial value 0 (RFC 8441 §9.1), and a
client may use extended CONNECT only on receipt of value 1 (§3). Refusing is pure omission. What a
non-supporting endpoint must still do is specified, and colibri needs no extra code for it: an
unexpected `:protocol` is an undefined pseudo-header, which RFC 9113 §8.3 makes the request
malformed, which is a *stream* error and not a connection error. The only way to get this wrong is
to close the connection, so this entry is about the pseudo-header validator's error class.

For h3, the RFCs colibri read say this: RFC 9114 defines base CONNECT only (§4.4), says
pseudo-header restrictions can be relaxed only by an extension (§4.3), and does not itself
define extended CONNECT. The document that does is outside the set colibri read, so this entry
cites no section for it and colibri's h3 side treats `:protocol` as undefined.
