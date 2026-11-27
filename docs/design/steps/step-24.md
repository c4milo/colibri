# Design §8 step 24: a request's query

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 127](../../decisions/0127-the-server-reads-a-requests-query.md) ruling 1: the server reads a query, after the WHATWG URL
Standard pinned in `docs/rfcs/whatwg/`. The owner approved the names on 2026-10-25.
- **Names.** `server.Request` gains `query`, the raw query after the `?`, or null, and its
  `path` holds the path alone. `http.QueryParameters` is new, with `read(query, storage)` and
  `get(name)`, and `http.constants.query_parameters_max` is 32. The owner ruled on 2026-10-25 that
  the URL code lives in `src/http/uri/`: `uri.zig`, `uri_percent.zig` and `uri_query.zig`, so the
  client reaches it too. The owner ruled the same day that `server` does not re-export it, so one
  type has one name. An absolute-form target with an empty path and a query gives the path `/`.
- **Rulings of 2026-10-25.** A `%` that two hex digits do not follow stays as written, as the URL
  Standard's percent-decode keeps it. colibri hands the decoded bytes back as they are, and
  checks no UTF-8. `get` returns the first value of a name, as URLSearchParams' `get` does.
- **The router.** `server.router` splits a path into segments, then percent-decodes each one
  (RFC 3986 §2.1). A literal compares with the decoded segment, and a parameter holds the
  decoded bytes, in memory the `PathParameters` holds. It no longer refuses a `%` (amends
  decision 122). A segment that encodes "/", "\\" or NUL matches nothing (RFC 3986 §7.3, the
  owner's ruling of 2026-10-25), so a decoded value cannot carry a path past the check of
  dot-segments.
- **Sub-steps.**
  - 24.1: this text and the tests that list the names.
  - 24.2: `Request.query`, in h11, h2 and h3.
  - 24.3: `QueryParameters`.
  - 24.4: the router's decoding.
  - 24.5: docs/usage.md and the server example.
  - 24.6: the refusal of an encoded "/", "\\" or NUL, and the fuzz tests of the query reader.
