# Design §8 step 31: DNSSEC's signature checks, the `dnssec` module

[Design §8, the build plan](../../design.md#8-build-plan)

[Decision 142](../../decisions/0142-dnssecs-signature-checks-are-a-module.md) puts chapulin's DNSSEC checks in a library module of their
own, for cocuyo's DNSSEC Stage B ([#122](https://github.com/c4milo/colibri/issues/122),
[cocuyo#56](https://github.com/c4milo/cocuyo/issues/56)). The owner reviewed the sketch of its
public API on 2026-10-31 ("That looks clean"), and it was built on 2026-11-01.
- **The build.** colibri pins chapulin f59c7e3f, past 54bad29b, whose CI passed, and builds the
  TCP object with DNSSEC=on. On a target that is not arm64 or x86-64, chapulin refuses
  DNSSEC=on, so there the object holds none, and `algorithm` and `digest_type` answer null. The QUIC object stays as it is. `src/dnssec/` is a library
  module, exported by name, whose one edge imports the TCP object's module. No other module
  imports it, and it imports no colibri module but `core`, for its tests' lists.
- **The public names,** each listed in a test beside the root before the code (decision 115):
  - `Algorithm`, an `enum(u8)` whose values are the DNS Security Algorithm Numbers: `rsasha256`
    8, `rsasha512` 10, `ecdsap256sha256` 13, `ecdsap384sha384` 14 and `ed25519` 15.
  - `DigestType`, an `enum(u8)` whose values are the DS digest types: `sha1` 1, `sha256` 2 and
    `sha384` 4. `sha1` also serves NSEC3's owner-name hash, whose algorithm 1 is SHA-1.
  - `algorithm(number: u8) ?Algorithm` and `digest_type(number: u8) ?DigestType`: what a record
    names, or null when it is a number colibri cannot check, such as 5, 7 or 16. This answers
    cocuyo's first ask, whether a record can be checked at all.
  - `Hash`, a struct the caller places, with `init(algorithm, key, signature) Error!Hash` for an
    RRSIG's signed data, `digest(digest_type) Hash` for a DS digest or one NSEC3 round,
    `update(hash, bytes)` for the data in pieces, and `final(hash, out) []const u8`, which wipes
    the state.
  - `verify(algorithm, key, digest, signature) Error!void`.
  - `Error`, `error{ Auth, Invalid }`: `Auth` for a signature the key does not verify, and
    `Invalid` for a key, a digest or a signature of the wrong form.
  - `constants.protocol.digest_len_max`, the room `final` writes into, 64 bytes.
- **The rules.** `key` is the DNSKEY's Public Key field as it arrives, RFC 3110's form for RSA,
  so neither side converts it. `init` takes the key and the signature because Ed25519 hashes R
  and the key before the data (RFC 8080). colibri sets no RSA floor: chapulin takes keys from
  512 bits, and cocuyo refuses those under 1024 itself. Nothing allocates, reads a clock or does
  I/O, and the caller holds every `Hash`.
- **The names are colibri's.** A program names nothing of chapulin, so a chapulin rename does not
  break it. The enum values are the registries' numbers, so a program converts a record's byte
  with `algorithm` or `digest_type` and no table of its own.
- **The checks.** The signed examples of RFC 5702 (8 and 10), RFC 6605 (13 and 14) and RFC 8080
  (15), and the DS examples of RFC 4509 and RFC 6605, each verified and then refused with one
  byte changed. `examples/` gains a program that checks one RRSIG and one DS, and docs/usage.md
  a section. Every RFC cited is copied into `docs/rfcs/` first.
- **The cost.** The TCP object grows by DNSSEC's code in every program that links colibri, which
  the memory table does not show, since it is code and not state. The release that carries the
  module is the owner's to tag.
- **What the build found.** RFC 8080 §6.1 prints its RRSIG without the Algorithm field, 15, and
  with 3 labels, though example.com has 2 (RFC 4034 §3.1.3). Its signature is over the 3 it
  prints, which the test states. The DS examples come from RFC 6605 §6 and RFC 8080 §6.1, so
  RFC 4509's has no test of its own.
- 8 mutations **CAUGHT**: `algorithm` and `digest_type` naming every number, each mapping onto
  chapulin's type fixed, `update` dropping its bytes, `final` cutting the digest, `verify`
  passing every signature, and `init` hiding a refusal.
