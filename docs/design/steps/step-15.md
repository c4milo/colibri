# Design §8 step 15: h11

[Design §8, the build plan](../../design.md#8-build-plan)

RFC 9112 as [decisions 88 and 91](../../decisions/0088-colibri-builds-http11-as-h11-client.md) rule it. The owner cut it into four
parts on 2026-09-25, in the order h2's steps 1 to 4 took: the parsers first, then the connection
over step 2's byte pipe, which already exists. Each part names its own check, and every
request-parsing check has a mutation (decision 88). *Large.*
