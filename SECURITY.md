# Security policy

## How to report a vulnerability

Use GitHub's private vulnerability reporting: open the repository's
[Security tab](https://github.com/c4milo/colibri/security) and click "Report a vulnerability". The
report stays private, and the advisory and CVE, if one is warranted, come out of the same thread.

If you cannot use GitHub, email camilo.aguilar@gmail.com with the same details you would put in
the report.

Do not open a public issue for a vulnerability.

## What to expect

One maintainer runs this project. You get an acknowledgment within 7 days, and an assessment
within 30: confirmed, not a vulnerability, or more information needed. The fix date comes out of
the assessment.

## Scope

In scope: the eleven library modules under `src/`, which read a peer's octets and write the
octets colibri owes. A peer's input that makes colibri crash, trip an assertion, read or write
outside a buffer, loop without bound, or accept a message the RFCs require it to refuse is a
vulnerability. So is a parse that frames a message differently from what RFC 9112 states, which
is how request smuggling starts.

Out of scope, so triage stays fast:
- `src/testing/`, `src/sim/`, `src/golden/` and `tools/`, which are test-only and never packaged.
- Attacks that need a malicious caller: a wrong buffer, a wrong instant, a `tls.Provider` or
  `crypto.Suite` that lies. The caller is trusted; the peer and the network are not.
- Denial of service through the caller's own limits. colibri names every limit as a constant,
  and the caller owns its timeouts and its event loop.
- Weaknesses in chapulin itself. Report those to
  [chapulin](https://github.com/c4milo/chapulin/security).

[`docs/invariants.md`](docs/invariants.md) lists the rules colibri asserts at run time, and
[`docs/decisions.md`](docs/decisions.md) records what colibri refuses to build and why.
