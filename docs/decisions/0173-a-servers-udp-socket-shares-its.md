# Decision 173: A server's UDP socket shares its port with SO_REUSEPORT

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-25, for [#155](https://github.com/c4milo/colibri/issues/155). Amends
decision 150 ruling 7, which lets a program start more servers on one port. The listener of
`colibri.Server` shared its port, and its UDP socket for h3 did not. So a second server over TLS
failed at its UDP bind, and so did a server that started while the last run's socket still existed.
- Rotor's `DatagramOptions.reuse_port` sets SO_REUSEPORT before the bind (Rotor's decision 15
  as amended on 2026-11-25). A server's UDP socket asks for it. A client's does not, since its
  port is the system's choice.
- Linux hands each datagram to one socket of the group by a hash of its addresses and ports.
  A QUIC connection whose client address changes (RFC 9000 §9) can then reach a server that
  does not hold it. That server cannot read its packets, and the client opens a new
  connection. The owner accepted this for now. Datagrams steered by connection ID, as with
  SO_ATTACH_REUSEPORT_EBPF, are a later step.
- The alternatives refused: a configuration field that asks for the option, which keeps a
  lone server's bind exclusive; and Rotor's option alone, with colibri left as it was.
