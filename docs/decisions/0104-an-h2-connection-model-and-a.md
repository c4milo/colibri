# Decision 104: An h2 connection model, and a trace check of colibri's h2 against it

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-27, for [#75](https://github.com/c4milo/colibri/issues/75), after
c32cabe found that h2's `write_data` let a server send DATA before its response's head (RFC 9113
§8.1). It comes before design §8 step 17b.
- `spec/tla/h2_connection` models a colibri client and server over one connection. It holds
  each stream's state at both endpoints (RFC 9113 §5.1), each message's order in each
  direction (§8.1), RST_STREAM crossing frames in flight (§6.4) and GOAWAY (§6.8). Where §5.1
  leaves a choice, the model takes colibri's. Flow control stays `spec/tla/h2_flow_control`'s.
- Each rule colibri keeps is a constant, and a configuration that turns one off must find a
  violation. DATA before the final head is one of them.
- A simulator run acts out a seed's plan with colibri's h2 client and server, as decision 87
  has for h3. The plan draws write calls the connection must refuse as well as ones it takes,
  so a refusal colibri misses shows as a state the model cannot reach. The run logs the
  model's variables after each step, and TLC checks each seed's log is a behavior of the
  model. `tools/h2_trace.sh` runs it, and `tools/ci.sh` runs it where Java is installed.

The alternatives refused:
- Trace only the calls the model allows. A trace shows what colibri did, so a refusal it
  misses would never be drawn, and c32cabe's bug would have passed.
- Model h11's order and pipelining (RFC 9112 §9.3) in the same step. It would add assurance,
  and hold back design §8 step 17b longest.
- Model h2 after step 17b. Step 17a's server rests on h2, and 17b touches h3 and QUIC, not h2.

Cost: step 17b waits for the h2 check.
