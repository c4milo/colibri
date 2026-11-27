# Decision 143: BBRv3 is the default congestion controller of colibri's QUIC connections

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-01, for decision 134's third ruling and design §8 step 29c. It amends
decision 134's second ruling and decision 136's second, which made CUBIC the default.

The judge's `bulk` run 41267075258 measured both controllers over h3 at 20 Mbit/s and 25 ms,
with a queue of 1,000 packets. Its two jobs agree within a few percent:
- At 1% loss, BBRv3 got 14.5 Mbit/s from one connection, and CUBIC got 1.68.
- With no loss, the goodput was the same, and BBRv3 kept the queue short. The p99 of the GETs
  beside 4 downloads fell from 509 and 718 ms to 186 ms.
- Where the two shared one bottleneck with no loss, CUBIC filled the queue and took 0.82 of it
  from 4 connections each. At 1% loss, BBRv3 took 0.76.

The `network` run 41267079569 gave BBRv3 a p99 about 8 ms higher on `far` at 4,000 req/s, and
a p99 9 to 12% lower on `mobile`.

The rulings:
1. `quic.Connection`'s options, `server.Config` and `client.Config` each take
   `congestion_controller = .bbr` by default. A caller still chooses `.cubic`.
2. The test-only UDP server keeps CUBIC unless its command names `bbr`, so the judge's
   inputs measure the same server as before.

Alternatives that lost:
- CUBIC, RFC 9002's choice. Its goodput at 1% loss was half of quic-go's
  ([#123](https://github.com/c4milo/colibri/issues/123)), and about a ninth of BBRv3's.
- A decision after more runs. The two jobs agree within a few percent.

Cost: with no loss, a BBRv3 connection gets less of a deep queue than a CUBIC connection
that shares it.
