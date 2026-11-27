# Decision 17: Server push: no

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

It is optional in both protocols. Cost of refusing, h2: a client must send `SETTINGS_ENABLE_PUSH`
(0x02) with value 0, because its initial value is 1 (RFC 9113 §6.5.2) and an endpoint that sends no
such setting permits push; and until the peer's SETTINGS ACK arrives a `PUSH_PROMISE` may legally
arrive, which cannot simply be dropped — it reserves a stream, its field block must still be
HPACK-decoded or the dynamic table desynchronises (§4.3), and the correct answer is decode, reserve,
`RST_STREAM` with `CANCEL` or `REFUSED_STREAM` (§8.4.2). After the ACK, a `PUSH_PROMISE` is a
connection error of `PROTOCOL_ERROR`. A colibri *server* has less to do: RFC 9113 §6.5.2 says a
server MUST NOT set the value to 1, so omitting the setting is already a refusal. Cost of refusing,
h3: never send `MAX_PUSH_ID`, whose value is unset at connection creation (RFC 9114 §7.2.7), and
answer a push stream or an oversized push id with `H3_ID_ERROR` (§4.6). One check.

**State the reason correctly.** RFC 9113 does not deprecate server push. §8.4 says it is
"difficult to use effectively"; Appendix B deprecates the RFC 7540 priority scheme and the
h2c Upgrade mechanism, not push. colibri's reason is "optional and unused", and writing
"deprecated" would be a citation nobody can check.
