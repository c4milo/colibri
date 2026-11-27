# Decision 168: A server keeps the 1-RTT packets that arrive before its handshake completes, and opens them once it completes

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-23, for [#153](https://github.com/c4milo/colibri/issues/153) (design
§8 step 71).
- RFC 9001 §5.7 forbids a server to process a 1-RTT packet before its handshake completes. It
  also says such packets "MAY be stored and later decrypted and used once the handshake is
  complete". colibri dropped them.
- In the QUIC Interop Runner's `handshakeloss` case of 2026-11-23, a quinn client's Finished
  was lost. The server dropped its request, and quinn's probes never carried it again
  ([quinn#2893](https://github.com/quinn-rs/quinn/issues/2893)).
- Each connection holds `early_packets`: at most `early_packets_max` packets, 12, and
  `early_packet_octets_max` bytes, 14,720. That is RFC 9002 §7.2's initial window. The owner
  ruled both limits, and the store in each connection.
- The walk names such a packet's discard `handshake_pending`, apart from `no_keys`, which
  now means RFC 9001 §4.9's absent or discarded keys. A server keeps a `handshake_pending`
  packet, and a client keeps none. A packet that finds no room is dropped, as before.
- When the handshake completes, each kept packet opens as a datagram of its own, in the order
  it arrived, after the datagram that completed it. It does not move the path.
- Its space records it at the instant it arrived. RFC 9000 §13.2.5 says the ACK Delay SHOULD
  include "buffering delays caused by unavailability of decryption keys". Everything else
  takes the instant it opened, the idle timer included.
- qlog writes quic-events §5.8's `packet_buffered` for a kept packet, and `packet_received`
  when it opens.
- The alternatives refused:
  - Listing the case in decision 112. That list holds cases a peer fails on its own side, and
    colibri's drop was part of the cause.
  - Waiting for quinn to fix its probes, or to send its 1-RTT packets with a copy of its
    Finished, as §5.7 suggests to a client.
  - A PING beside every ACK frame, so that a lost ACK arms a PTO. Decision 73 as amended
    refused it.
  - A store in the endpoint that the connections in their handshakes share. It takes less
    memory in all, but one peer can fill it for the others.
