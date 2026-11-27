# Decision 118: Middleware: no. Reversed by decision 127

[All decisions](../decisions.md) · Section: [What colibri does not build](../decisions.md#what-colibri-does-not-build)

Reversed by decision 127, ruling 5, on 2026-10-21: a route table runs a compile-time chain of
middleware, global and for each route. colibri's two middleware for content codings,
`server.middleware.decode_request` and `encode_response`, are design §8 step
25.7, which waits for https://github.com/c4milo/stdx/issues/21. The ruling below is the record
of the first position. Ruled by the owner on 2026-10-04 in
[#96](https://github.com/c4milo/colibri/issues/96), beside decision 117. Middleware is a
chain of functions a library calls for each request, before or after the program's own
code. colibri calls no function of its program's: events are polled (decision 100), so the
program's own `switch` is where a check before a route, or a log line on `done`, goes.
colibri covers what middleware usually carries another way: content codings are
configuration (decision 101), deadlines and limits are configuration (decision 110), and
qlog is a provider (decision 102). A framework with handlers, middleware and its own loop
owns sockets and threads, which colibri does not (non-negotiable 1), so it belongs in a
package built on colibri.

Cost of refusing: nothing on the wire. A program writes in its own loop what it would have
put in middleware.
