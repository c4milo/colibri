# Decision 16: No caching, and the conformance bar for RFC 9111 is zero

[All decisions](../decisions.md) · Section: [What is shared between h2 and h3](../decisions.md#what-is-shared-between-h2-and-h3)

RFC 9111 §2 says caching is "an entirely OPTIONAL feature of HTTP", every normative requirement in
its §3 and §4 is scoped to the subject "a cache", and the single requirement binding a non-cache —
§5.2, pass cache directives through in forwarded messages — binds *proxies*. colibri is neither.
Cost: a consumer that wants a cache writes one. Gain: no revalidation, no freshness arithmetic, no
`Vary` matching, no stored-response state that would have to survive a connection.

The practical obligation, which is not a conformance requirement: pass `Cache-Control`, `Age`,
`Expires`, `Vary`, `Date`, `ETag` and `Last-Modified` to the caller byte-exact, so a
caller-built cache can itself be conformant. `Pragma` is deprecated (§5.4) and `Warning` is
obsolete (§5.5); colibri implements neither.
