# Decision 20: 0-RTT: no, in both protocols

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

Refusal is the specified default and is expressed by omission: a server omits the `early_data`
extension from its NewSessionTicket (RFC 9001 §4.6.1) and, mid-handshake, omits it from
EncryptedExtensions (§4.6.2). Two structural reasons make this more than a scope cut. RFC 9001 §5.6
says a client MUST NOT use 0-RTT for application data unless the application specifically requests
it and the application protocol supplies a 0-RTT profile — colibri owns no application semantics and
cannot supply one. And RFC 9000 §7.4.1 requires a 0-RTT client to remember every server transport
parameter it can process, apart from seven it must never reuse, and forbids a server accepting 0-RTT
from lowering seven named limits; that is persistent cross-connection state, which conflicts
directly with fixed storage the caller owns per connection (entry 35).

Saying no also deletes the stream-state rollback a client must perform when a server rejects
0-RTT (RFC 9001 §4.6.2), which is a path colibri would otherwise have to implement and test.
