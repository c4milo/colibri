# Decision 142: DNSSEC's signature checks are a module of their own, `dnssec`, and not a part of `tls`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-31, for cocuyo's DNSSEC Stage B
([#122](https://github.com/c4milo/colibri/issues/122)). chapulin checks DNSSEC signatures under its
build option DNSSEC=on (chapulin's decision 169), in the same TCP object that holds its TLS. A
program reaches chapulin only through the objects colibri builds, because a second copy of an object
fails the link.
- colibri adds a library module, `dnssec`, over the TCP object colibri already builds, which
  it then builds with DNSSEC=on. The module exports chapulin's hash and verify calls in
  colibri's names, and nothing of TLS.
- colibri builds it when cocuyo asks for Stage B, against the chapulin commit it needs then.
  cocuyo asked on 2026-10-31, and design §8 step 31 records the module, built over chapulin
  f59c7e3f on 2026-11-01. On a target chapulin builds no DNSSEC for, the module checks
  nothing, and says so.

The alternatives refused:
- The calls under `tls`. DNSSEC is not TLS, and a reader of `tls` would find a check of DNS
  records there.
- No DNSSEC in colibri's objects, with cocuyo building a chapulin object of its own. The
  program would then link chapulin's signature and hash code twice.

Cost: a module and an edge in the module graph, and a TCP object that grows by the DNSSEC
code in every program that links colibri.
