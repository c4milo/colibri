# Decision 122: `server.routes` matches a method and a path through a table the program declares at compile time

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-13 in [#96](https://github.com/c4milo/colibri/issues/96); design §8
step 21e carries it.

Decision 117 ruling 6 asks for a router that matches a path and returns its parameters. The
router does nothing more. Decision 118 refuses middleware, so colibri calls no function of
the program's.

What [#96](https://github.com/c4milo/colibri/issues/96) and decision 117 already settle:
- `server.routes(Value, table)` returns a table that the compiler builds. Each entry has a
  method, a pattern and a value of any type that the program names: an enum, a function
  pointer or a struct.
- A pattern is a path of segments. A segment is a literal, a parameter (`:name`) or a last
  segment `*`, the wildcard.
- `match` reads the path as received, byte for byte and case-sensitive. It reads the
  path up to the first "?". A path that does not start with "/" matches nothing. A path with
  an empty segment other than the root's, or with a "." or ".." segment, matches nothing.
- At each node the walk tries the literal, then the parameter, then the wildcard. It backs
  up one level when a deeper level fails. The leaf that the walk stops at decides, and
  the table's order changes nothing. The walk reads each node once at most (INV-32).
- At the leaf the method decides: `found` with the route's value, or `method_not_allowed`
  with the leaf's Allow value. A walk that stops at no leaf gives `not_found`.
- `found` writes the parameters into a `server.PathParameters`, which the program places and
  reads with `get`. The values are slices of the path.
- A malformed table, or a table with a conflict, does not compile, and the message names the
  entry and the rule. `zig build routes-check` compiles each such table and requires the
  refusal.

The rulings:
1. HEAD finds the GET route at a leaf that names GET and no HEAD. The leaf's Allow value
   lists HEAD after GET. RFC 9110 §9.1 tells every general-purpose server to support GET and
   HEAD. The endpoint also writes no content in a response to HEAD, in h11, h2 and h3 alike
   (RFC 9110 §9.3.2, RFC 9113 §8.1.1, RFC 9114 §4.1.2). `write_body` takes the bytes and
   writes none. So a program writes the same answer for GET and for HEAD. Before this step,
   `write_body` on a response to HEAD returned `SectionOutOfOrder` over h11, and h2 and h3
   sent the content. The endpoint keeps the Content-Length field that the program writes,
   because a response to HEAD carries the fields of a response to GET (RFC 9110 §9.3.2).
2. `match` has a fourth result, `not_implemented`, for a method that no route of the table
   names (RFC 9110 §9.1, §15.6.2). `match` checks the method before the path, and HEAD
   counts as GET. So CONNECT gets 501. `OPTIONS *` gets 501 when no route names OPTIONS,
   and `not_found` when a route names it.
3. `server.routes` is exported under its own name. CLAUDE.md's rule "No public name repeats
   itself" gains one sentence: a function named after its file is exported under its own
   name too. Each call of `routes` returns a value of a type of its own. The type has no
   field and no name in the root. Its public declarations are `Match`, which `match`
   returns, and `match`. `server.PathParameters` joins the root, and its one public
   function is `get`. The server's root then exports 49 names.
4. An entry is a tuple: `.{ .get, "/users/:id", .user }`. Its method is an enum literal or a
   value of `http.method.Standard`, or the token of a method outside RFC 9110's eight.
   `http.method` exports `Standard` for it.
5. Two parameter names at one trie node do not compile: `GET /users/:id` beside
   `PUT /users/:user`. A parameter node has one name.
6. The wildcard matches one segment or more, the rest of the path. A program reads it with
   `get("*")`. So `/files/*` does not match `/files`.
7. A path that holds a "%" matches nothing (RFC 3986 §2.1). So no parameter holds a space, a
   "/" or a byte above 0x7F.
8. A path with a byte outside RFC 3986's `pchar` matches nothing (RFC 3986 §3.3). h11
   refuses such a target before the program reads it, so h2 and h3 route as h11 does.
9. `Request.method` stays text in this step, and `match` compares the text with the token of
   each entry. [#96](https://github.com/c4milo/colibri/issues/96) says that a `request`
   event carries its method as one of the eight or as the token.
   [#101](https://github.com/c4milo/colibri/issues/101) holds that change.
10. `server.constants.path_parameters_max` is 8. It counts the parameters of one pattern,
    the wildcard included. `PathParameters` then holds 264 bytes on a 64-bit target. A
    table that needs more does not compile, so the limit never fails at run time.
11. For a 405, `match` gives the leaf's Allow value. The build writes it: the leaf's
    standard methods in RFC 9110 §9.1's order, then its tokens ordered by bytes, joined
    by ", ". The program writes the 405 and its "allow" field (RFC 9110 §15.5.6). Each
    Allow value holds `core.constants.field_value_len_max` bytes at most, because a
    program sends it as a field value. A table with a longer one does not compile:
    `allow_too_long`.
12. A route that other routes hide does not compile. The owner read this ruling on
    2026-10-13, after eight examples: a route is refused in two cases, and in no other. A
    route names a method, and its pattern ends at a leaf of the trie.
    - `route_hidden`: a request that the route matches gets 405 from another leaf. The walk
      on a path that the route's pattern matches stops at another leaf, and that leaf does
      not serve the method. A leaf serves a method when it names the method, or when the
      method is HEAD and the leaf names GET (ruling 1).
    - `route_unreachable`: no request reaches the route. The walk on each path that the
      route's pattern matches stops at another leaf.

    The walk on a path of a route can stop at another leaf. When that leaf serves the
    route's method, the table compiles. The eight examples, with their verdicts:
    1. `GET /users/me`, `GET /users/:id`: compiles.
    2. `GET /users/:id`, `PUT /users/me`: `route_hidden`, because `GET /users/me` gets 405.
    3. `GET /users/me`, `GET /users/:id`, `PUT /users/:id`, `DELETE /users/:id`:
       `route_hidden`, because `PUT /users/me` gets 405.
    4. `GET /files/*`, `GET /files/:name`: compiles.
    5. `GET /files/*`, `POST /files/:name`: `route_hidden`, because `GET /files/a` gets 405.
    6. `GET /a/:x/c`, `GET /a/b/:y`: compiles.
    7. `GET /a/:x/c`, `PUT /a/b/:y`: `route_hidden`, because `GET /a/b/c` gets 405.
    8. `GET /a/*`, `GET /a/:x`, `GET /a/:x/*`: `route_unreachable`. The walk on each path
       of two segments stops at `/a/:x`, and on each longer path at `/a/:x/*`.

    The cost, which the owner saw: a literal names each method that the parameter beside it
    names. So `GET /users/me` and `PUT /users/:id` do not compile, because `PUT /users/me`
    gets 405. The check runs at compile time and adds nothing at run time. It runs the walk
    of `match` on a few canonical paths of each leaf. The doc comment of
    `src/server/routes/routes_hidden.zig` proves that these paths show each case. A test
    compares its verdict with a brute force on 2,838 small tables.
13. `server.constants.path_len_max` is the endpoint's own bound on a path:
    `@max(h11.constants.start_line_len_max, core.constants.field_value_len_max)`, 8192
    bytes today. A comptime assert pins it. `match` gives `not_found` for a longer path
    (INV-8). The check of the path reads each byte once, before the walk.

Adopted for this step, which the owner may overrule:
- A walk does not back up for a method. The leaf of a path is one resource, and RFC 9110
  §15.5.6 asks for the methods of that resource. Ruling 12 refuses each table in which a
  back-up for a method would find another route.
- `match` takes the method and the path, not a `server.Request`. A test of a table then
  needs no request, and the sketch of
  [#96](https://github.com/c4milo/colibri/issues/96) passes the two.
- The router is in `server`, not in `http`. Every protocol module imports `http`, and none
  of them routes.
- The path "/" has no segment, and the pattern "/" matches it. RFC 3986 §3.3 reads "/" as
  one empty segment, which the rule on empty segments refuses.
- A parameter name is `1*( ALPHA / DIGIT / "_" )`, and a parameter is a whole segment.
- A route's value has a type that exists at run time, because `match` reads the value at
  run time. A `type` or a bare `fn` type cannot be a route's value.

Not in this step:
- The typed method on the `request` event:
  [#101](https://github.com/c4milo/colibri/issues/101).
- The grammar of `:path` in h2 and h3, which check only its first byte:
  [#102](https://github.com/c4milo/colibri/issues/102). Until then ruling 8 makes the
  router match nothing for a path that h11 refuses.
- An absolute-form target with an empty path and a query, such as `GET http://a?x`. Its
  path is "?x", so it matches nothing where "/" has a route:
  [#103](https://github.com/c4milo/colibri/issues/103).

The alternatives refused:
- Ruling 1: a table that must name HEAD wherever it names GET. Every table then repeats its
  GET routes.
- Ruling 1: no rule, so HEAD gets 405 where the table names no HEAD route.
- Ruling 1: the fallback with no change to the endpoint. Each GET arm of a program then ends
  at the head for HEAD, and a program that forgets it sends content over h2 and h3.
- Ruling 2: three results, as the sketch of
  [#96](https://github.com/c4milo/colibri/issues/96) has. A method that no route names then
  gets 404 or 405, where RFC 9110 §9.1 asks for 501.
- Ruling 3: a file of another name, which makes the name `server.<file>.routes`. Decision
  117 ruling 6 names it `server.routes`.
- Ruling 3: `server.Routes(Value)`, a type that a program names. It adds a root name,
  follows a pointer for each array, and needs a limit on the segments of a pattern.
- Ruling 3: `Match` private. Decision 115 has a type export what its calls return.
- Ruling 4: named fields in an entry. The tuple of
  [#96](https://github.com/c4milo/colibri/issues/96) is the form agreed.
- Ruling 5: two names at one node, which each route keeps. One segment of one resource has
  one name.
- Ruling 6: a named wildcard, `*rest`, or a second function, `rest()`. `get("*")` needs
  neither, because no parameter name can be "*".
- Ruling 6: a wildcard that matches zero segments. Each other segment of a pattern matches
  one segment of the path, never none.
- Ruling 7: only an encoding of an unreserved byte matches nothing (RFC 3986 §2.3), and a
  parameter binds each other encoding as received. No result for a path without "%"
  depends on the choice, so a later step can relax the rule.
- Ruling 7: a path decoded, or its dot segments removed, before the match. A router that
  decoded `/users/%6De` could route it past a check written for `/users/me`.
- Ruling 8: a byte outside `pchar` read like any other. h2 and h3 then route a path that
  h11 refuses.
- Ruling 9: `Request.method` as a union of `Standard` and a token. It breaks each program
  that reads `request.method`, and it needs a step of its own.
- Ruling 9: a second field beside the text, which holds one fact in two fields.
- Ruling 10: 4 or 16.
- Ruling 11: the leaf's methods as a set, from which the program builds the value. Each
  program then writes RFC 9110 §5.6.1.1's list syntax.
- Ruling 11: an endpoint call that writes a 405. It adds a call to `Endpoint` for one
  status, and the program writes every other answer.
- Ruling 12: a hidden route allowed, with the rule in the guide. A program then gets 405,
  or no request, for a route that it declared, and the build does not tell it.
- Ruling 12: the second case alone. A request that a route matches can then get 405, as a
  GET of `/users/me` does in the second example.
- Ruling 12: a walk that backs up for a method. The Allow value of a 405 then joins the
  methods of several leaves at run time, the walk grows, and the first leaf no longer
  decides.
- Ruling 13: a comment that names the endpoint's bound, with no limit in the router.
  `match` is a public call that takes any slice, and INV-8 asks for a named constant.
- A table built at run time. It needs storage that the program sizes, and a malformed table
  fails when the server starts, not when it builds.

What this decision changes in [#96](https://github.com/c4milo/colibri/issues/96):
- The issue says that the work for one request depends on the table alone, never on what
  the peer sent. The check of the path reads each of its bytes once, up to `path_len_max`.
  So the work depends on the table and on the path's length, and `path_len_max` bounds it.
- The issue's typed method on the `request` event is not built (ruling 9).

Cost: two names in the server's root, one in `http.method`, and two limits in
`server.constants`. No name leaves a list. A response to HEAD changes: over h2 and h3 the
endpoint sends no content, and over h11 `write_body` returns no error. Each table costs
compile time, which `zig build routes-check` shows. A parameter's slice stays valid only
until the endpoint's next call, so a program that answers later copies it.

**Amended by the owner on 2026-10-14, for design §8 step 21e.** Two rulings, after the
first build of the check of hidden routes:
- The cross-check of `src/server/routes/routes_hidden_test.zig` runs in `zig build
  routes-hidden-check`, a test binary of its own, which `zig build test` runs. It added about
  a minute to each compile of `zig build test-server`. On an M1 Pro, that compile took 86 s
  with the cross-check and 27 s without it. `build/check_steps.zig` makes `zig build test`
  fail for each step whose name ends in `-check` that it does not run.
- Step 21e removes the quadratic compile-time work that the measured tables paid for. That
  work was the scans of siblings, the insertion sort, the pairwise check of parameter names,
  and the passes over large constants. `match` finds a literal edge by a binary search over the
  edges of a node, which the build sorts by length and then by bytes. Before, it read the
  edges in turn. The check of hidden routes walks the trie, and the build merges the trie
  once.
- The check of hidden routes stays quadratic in the leaves for some tables. Take the
  routes `GET /a_i/:x` and `GET /:y/b_j`, for i and j from 1 to n. The check walks
  n * (n + 1) canonical paths.
- The binary search changes the run-time code of `match`, so it carries a measurement.
  callgrind counted the instructions of a match on aarch64 Linux, at a root with 256 literal
  edges, with `bench/routes/run_time.sh`. The last edge took 17,642 before and 874 after.
  The first edge took 557 before and 937 after.
- Over the first edge, the middle edge, the last edge and a miss, the search costs less on
  average at each count of edges measured: 1, 2, 4, 8, 16, 64 and 256. So it has no
  threshold and no named limit.
- Compile time on the M1 Pro, in a Debug test binary, from `bench/routes/compile_time.sh`
  at a load average of 5 to 8. 512 literals beside `/:x` took 69.0 s and 69.3 s at e6a5c77,
  before 546d6b1. They took 4.1 s and 3.9 s at 1c3a4f2. The table of 256 routes in
  `routes_test.zig` took 17.5 s and 17.6 s, then 4.9 s and 5.0 s. One route takes about
  2 s. Design §8 step 21e gives each run.

The alternatives refused:
- The cross-check: a smaller family of tables in `zig build test-server`. It then proves
  less than the brute force on 2,838 tables.
- The cross-check: `zig build test-server` as it was, a minute slower to compile.
- Large tables: the compile time accepted, with an issue filed for a later step.

**Amended again by the owner on 2026-10-14: the router is `server.router`.** The owner
asked why the name was `server.routes` and not `server.router`, and ruled the rename. Nothing
pushed breaks, because `server.routes` exists only on the branch of step 21e.
- `server.routes` becomes `server.router`, and the server's root lists `router` in place of
  `routes`. The type that the call returns, `Match`, `match`, `PathParameters` and the names
  of the refusals keep their names. A route is still one entry of a table.
- `src/server/routes/` becomes `src/server/router/`, and each file `routes*.zig` in it
  becomes `router*.zig`. `src/server/routes_hidden_check.zig` becomes
  `router_hidden_check.zig`.
- `build/routes_check.zig` becomes `build/router_check.zig`,
  `tools/fixtures/routes_refused.zig` becomes `router_refused.zig`, and `bench/routes/`
  becomes `bench/router/`.
- `zig build routes-check` becomes `zig build router-check`, and `zig build
  routes-hidden-check` becomes `zig build router-hidden-check`.
- Each compile error of a table starts with "server.router:" in place of "server.routes:".
- The text of this decision before this amendment keeps the old names. Read each old name
  as its new name.

The alternative refused: keep `routes`, because the call returns the table of routes.

**Amended by the owner on 2026-10-17, for
[#103](https://github.com/c4milo/colibri/issues/103): a query alone is the root.** An h11
absolute-form target with an empty path and a query, such as `GET http://a?x`, gives the path
"?x" (`Request.path`). RFC 9110 §4.2.3 makes an empty path equal to "/". So `match` reads a
path that starts with "?" as the root with a query. The sentence "A path that does not start
with "/" matches nothing" keeps two cases: "*" and the "" of a CONNECT request. Only the h11
absolute-form gives a query alone: h2 and h3 refuse a `:path` without a first "/", and the
path of a CONNECT request is null.

The alternatives refused:
- Room for "/?x" in each h11 connection, so that `Request.path` always starts with "/". A
  request line holds up to 8,192 bytes, so each connection grows by that much, for a form
  that only a proxy sends (RFC 9112 §3.2.2).
- A `query` field beside `path`, with `path` holding "/" alone. Each program that reads
  `path` then reads the query apart, and the `:path` of h2 and h3 holds both.

**Amended by the owner on 2026-10-29: a pattern and a path may end in "/".** The route table
of Kubernetes holds 64 routes that end in "/", such as `GET /api/`. The rule on empty
segments refused each of them. RFC 3986 §6.2.4 counts "/a/" equal to "/a" only when the
server says so, as with a redirect. So "/a" and "/a/" are two resources, and a table may
name both. The owner ruled the two routes, and the empty segment as the last one alone.
- Only the last segment of a pattern may be empty. `segment_empty` refuses an empty segment
  elsewhere, as in "/a//b" and "//".
- Only the last segment of a path may be empty. A path with an empty segment elsewhere
  matches nothing.
- Only a pattern that ends in "/" matches a path that ends in "/". A parameter does not
  match an empty segment, and the wildcard does not match a path that ends in "/". This
  rule came with the amendment, and it is the narrower of the two that it could take.
- The pattern "/" is still the root, with no segment.
- The check of unreachable routes (ruling 12, as decision 128 amends it) stays sound. A path
  holds an empty segment only where its pattern holds one, so the empty segment acts as one
  more literal (claim 2 of `router_hidden.zig`).

The alternatives refused:
- Keep the rule. The Kubernetes table then loses its 64 routes, and no program serves
  "/api/".
- Refuse a table that names "/a" beside "/a/". The two are two resources, and a program may
  serve both.
- A 308 redirect from one form to the other, as httprouter does. colibri would then write a
  response that the program did not ask for.
- A wildcard that matches a path that ends in "/", so that "/files/*" matches "/files/a/".
  The wildcard would then match an empty segment, which no parameter matches. The check of
  unreachable routes would need a new claim. A later ruling can widen the rule.

**Amended by the owner on 2026-10-30, for
[#101](https://github.com/c4milo/colibri/issues/101): `Request.method` stays text.** Ruling 9
kept the typed method out of step 21e, and left the form open. The owner withdrew the sentence
of [#96](https://github.com/c4milo/colibri/issues/96) that gives the `request` event a method
"as one of the eight or the token".
- `server.Request.method` is the method's token as it arrived, in h11, h2 and h3.
- A program that needs the enum calls `http.method.standard(request.method)`, which the root of
  `http` exports. It returns one of RFC 9110 §9.1's eight methods, or null for another token.
- A program that routes does not call it, because `match` compares the method's token.
- No name is added or removed, and no program breaks.

The alternative refused: `Request.method` as a union of `Standard` and a token, in a step of
its own. It breaks each program that reads `request.method`. Each request then pays for a
comparison with the eight tokens, though most programs route or print the token and never
read the enum.
