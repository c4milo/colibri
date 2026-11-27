# Decision 42: A client accepts any number of interim responses, with no limit of colibri's own

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-18. RFC 9113 §8.1 lets a server send any number of interim responses
before the final one, and colibri holds none of them: each 1xx field section is decoded into the one
field-block slot, returned to the caller as an event, and the slot is reused. Nothing accumulates
per interim response, so there is no storage to exhaust.

The alternative lost is an `interim_responses_max` with a stream error past it. It was weighed
because non-negotiable 4 bounds every loop and queue, but this is neither: the sections arrive
across separate `receive` calls the caller drives, and the caller sees every one and may close
the connection. The §10.5 rate limit colibri does hold, `rst_stream_rate_max`, bounds the
RST_STREAM frames colibri sends and does not cover this. The ruling is "for now": a limit
remains available if a peer is ever seen to abuse it.
