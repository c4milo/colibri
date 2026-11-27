# Decision 108: QUIC version 2 beside version 1: each packet names its version, and a client switches once

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-29 for [#54](https://github.com/c4milo/colibri/issues/54). It amends
decision 48, and chapulin's decision 79 is its other half.

RFC 9369 §3 changes only printed inputs: the Version field, the four long header type codes,
the Initial salt, four HKDF labels, and the Retry key and nonce. The keys are chapulin's,
which derives both versions' since its `b640e98`. The wire is colibri's, and so is RFC 9368's
version_information transport parameter, which RFC 9369 §4 requires of every endpoint that
supports version 2.
- **The suite.** `Sealing` and `Opening` name the packet's version beside its level, as
  chapulin's `seal` and `open` take it. `retry_tag_valid` and `retry_tag_write` take the
  original version, the one RFC 9369 §4.1 has a Retry use. A thirteenth member,
  `switch_version`, performs the client's one switch: RFC 9369 §4.1 has the client learn the
  negotiated version from the first long header whose Version field differs from the
  original, and chapulin then derives that version's Initial keys from the same Destination
  Connection ID. It takes a version and returns no key, so invariant 23's list moves from
  twelve to thirteen when it lands.
- **The order.** First the client, and a server that accepts version 2 from the start: a
  chapulin pin with version 2, version 2's packets read and written, version_information
  sent, processed and validated (RFC 9368 §3 and §4), the client's switch, and a server whose
  negotiated version is the client's original one. Then a server that answers a version 1
  first flight in version 2, as the QUIC Interop Runner's `v2` case asks. That needs the
  callback chapulin's decision 79 names, through which a server's caller chooses the
  negotiated version, and colibri asked chapulin's session for it on 2026-09-29.

The alternatives refused:
- No new member: `install_initial_keys` takes a version, and a second call with the
  negotiated version is the switch. The list stays at twelve, but one member would both
  install keys and switch versions, and chapulin refuses the switch once the server's first
  CRYPTO byte has arrived.
- Wait for chapulin's callback and build version 2 whole. The client, and a server that
  accepts version 2 from the start, need nothing more from chapulin.
