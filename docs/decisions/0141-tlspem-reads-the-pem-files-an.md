# Decision 141: `tls.pem` reads the PEM files an operator holds

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-10-31, for https://github.com/c4milo/colibri/issues/97. chapulin decodes
the files (its decision 131) and takes Zig slices since
[chapulin#213](https://github.com/c4milo/chapulin/issues/213), so `tls` shapes nothing but colibri's
anchor type.
- `tls.pem.chain(file, der, room)`, `tls.pem.p256_key(cpu, file, leaf, &key)` and
  `tls.pem.anchors(file, der, room)`, and the type `tls.P256Key`. None reads a file, each
  fills rooms the program places, and each returns `error.Invalid` for a refused file.
- `p256_key` lets chapulin decode into the caller's `P256Key`, whose layout a comptime check
  holds equal to chapulin's, so no copy of the scalar is left to wipe.
- `tls.constants.limits.anchors_max` rises from 12 to 256, chapulin's own default, so a
  system bundle of about 150 roots reads whole. Each anchor costs four words in each client
  configuration and in each TLS session, about 7.8 KB at 256.
- A chain holds at most `certificate_chain_len_max`, 16, as a server identity does.
- Each call skips the text lines around its blocks, as RFC 7468 §2 permits and the owner
  ruled on 2026-10-31 ("Follow 7468"). chapulin c8cd8021 does so for chains and keys too
  (https://github.com/c4milo/chapulin/issues/214, its decision 170). A block of another label
  refuses the file.

The alternatives refused:
- Associated functions on the value types, such as `EcdsaP256Identity.from_pem`. A
  constructor of the identity would also have to own the key's storage.
- A reader in colibri. The owner ruled on 2026-10-12 that the decoding belongs in chapulin,
  under its proof rules.
- `anchors_max` kept at 12. A program could then read no system bundle.

Cost: every TLS session and client configuration grows by about 7.8 KB. The anchors are still
copied once, from chapulin's type of the object into `tls.Anchor`.
