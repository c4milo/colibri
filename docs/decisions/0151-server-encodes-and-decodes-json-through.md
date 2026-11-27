# Decision 151: `server` encodes and decodes JSON through stdx's `json` module

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-04 (design §8 step 36), with decision 150. `server` gains an edge to
stdx's `json` module, which `qlog` already imports (decision 102).
1. `ResponseWriter.json(value)` encodes a value into the response body with stdx's encoder,
   with no allocator, and sets `content-type: application/json`.
2. A route can declare a JSON body type. The router decodes the request body into it with
   stdx's decoder, and answers 400 when the body is not that type.
3. The decoder's limits are named constants, and a program can lower them.

Alternatives that lost:
- Responses alone.
- No edge: programs use `std.json` or stdx themselves, as they do now.
