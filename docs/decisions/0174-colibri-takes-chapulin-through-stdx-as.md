# Decision 174: colibri takes chapulin through stdx, as `stdx.crypto`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-11-25, for v0.22.0. Amends decision 94, under which colibri pinned
chapulin and asked it for its objects itself. stdx at `5de7d89f` holds `stdx.crypto`, chapulin's one
module, and is the one package that asks chapulin for it (stdx's decision 87 as amended). A program
that links colibri and calls chapulin, as connect-zig's `oidc` does, then links one chapulin.
- colibri pins no chapulin. Its build gives stdx `.crypto = true`, and `tls` and `dnssec` read
  `@import("stdx").crypto.tls`, `.quic` and `.dnssec`. stdx's request is decision 172's, with
  `HASH` on a host target too.
- A program that names stdx beside colibri passes `.crypto = true` with colibri's other
  options. Zig puts a file in one module of a compile alone, so a second stdx fails the build.
- With the option on, each module that imports stdx carries chapulin's objects, and stdx's
  root references `stdx.crypto`, so chapulin's `ch_assert_fail` stays beside them in every
  program. A cleartext program links chapulin's objects, as one that imports `colibri`
  already did (decision 170).
- The test-only images over chapulin's `KEYLOG=on` objects take a second stdx, built with
  `crypto_keylog`. Each such image reads every part of stdx from it, so `build/modules_keylog.zig`
  makes `qlog`, `quic`, `h3`, `h11` and `tls` again over it, beside the instance of `server`
  the UDP endpoint already had.
- The alternatives refused: colibri's own chapulin pin beside stdx's, which links two
  chapulin modules into a program that calls both; and a key-log image that reads `tls` over
  the second stdx and the other modules over the first, which Zig refuses.
