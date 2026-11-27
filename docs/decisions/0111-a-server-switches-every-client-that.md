# Decision 111: A server switches every client that lists version 2, and a client resumes in its ticket's version

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-29 for [#54](https://github.com/c4milo/colibri/issues/54), after
design §8 step 19d. It completes decision 108.
- **The server's choice.** RFC 9368 §2.3 has a server select a version the client lists, that
  it supports, and that the client's Chosen Version is compatible with. colibri's server
  selects version 2 whenever the client lists it, and otherwise keeps the client's original
  version. chapulin asks for the choice once, through `choose_version`, when the client's
  transport parameters have arrived and before anything is sent (its decision 79). `quic`
  reads the client's version_information, moves the connection to version 2, and rewrites the
  server's own transport parameters, at the same length, so their Chosen Version names it
  (RFC 9368 §3). chapulin reads those bytes when it writes EncryptedExtensions, after the
  choice.
- **The option.** `quic.Connection`'s options and `server.QuicConfig` carry `switch_to`, the
  version a server switches a client to, version 2 by default. Null keeps every client in its
  original version. The QUIC Interop Runner requires one version on the wire in every case
  but `v2` (its `_check_version_and_files`), and colibri's client lists version 2, so a
  colibri server that switches it fails every other case. The runner's colibri endpoint
  therefore passes `no-switch` outside `v2`.
- **The ticket.** RFC 9369 §5 binds a ticket to the negotiated version of the connection that
  received it, and forbids a client to start a connection in the other version with it. A
  client offered a ticket starts in the ticket's version, unless its configuration names
  another. RFC 9368 §2.5 has a client pick the original version the server most likely
  parses, and a ticket from version 2 says that server ran version 2.

The alternatives refused:
- For the server: switching only when the server's configuration names a version, none by
  default, which is what ngtcp2's and neqo's servers do in the QUIC Interop Runner; and
  following the client's order of preference.
- For the runner: leaving colibri's server against colibri's client out of the matrix, and
  accepting that pair's failures in every case but `v2`.
- For the ticket: refusing a ticket of the other version, as step 19b left it, so the caller
  starts without it and runs a full handshake.
