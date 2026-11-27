# Decision 97: The library's TLS module is `tls`, and the vtable it fills is `tls_provider`

[All decisions](../decisions.md) · Section: [The h2 connection](../decisions.md#the-h2-connection)

Ruled by the owner on 2026-09-26, for design §8 step 16b.
- The module a program imports for TLS and for QUIC's handshake and packet protection is
  `tls`, the name Go's `crypto/tls`, Node's `tls` and Zig's `std.crypto.tls` give theirs. It
  fills colibri's vtables from chapulin's sessions; step 16c's values are chapulin's, as
  entry 94's amendment rules, and `tls` passes them through.
- The provider vtable the module was named for until now becomes `tls_provider`. h2, h11,
  quic and sim import it, and a program imports it only to name the type. The HTTP modules do
  not import `tls`: a program makes a session there and hands its provider to the connection,
  so a cleartext program never links chapulin, and sim's null providers fill the same vtable.
- The TCP object carries `SUITE=aesgcm`, so a server that offers only AES-GCM connects; RFC
  9846 §9.1 makes TLS_AES_128_GCM_SHA256 mandatory to implement. The build picks `AES=hw`,
  with the builder's statement `CH_NATIVE_AES`, on a target whose features include the AES
  instructions, and `AES=soft` on any other.
- The TCP object sets chapulin's `TX_RECORD` to 16384, TLS's largest record plaintext (RFC
  9846 §5.1), once chapulin offers the option, so a large body takes a record per 16 KiB.

The alternatives refused:
- chapulin's adapter inside the vtable's module. Every program that imports h2, h11 or quic
  would link chapulin, a cleartext one included, and would have to define its two hooks.
- `ssl`, the Python, Erlang and Java name, for a module that speaks TLS 1.3 alone.
- `AES=hw` everywhere, which refuses to build for a target without the AES instructions.
- ChaCha20-Poly1305 alone on TCP, which a server offering only AES-GCM refuses.

**Amended by the owner on 2026-09-26.** chapulin's Zig API gives each object types of its own:
two instances of one dependency make two modules, and a type in one is not a type in the
other. So step 16c's values are colibri's, and `tls` no longer passes chapulin's through.
- `tls` defines the values once and converts them, once per object, into that object's
  chapulin values. They go into a configuration the caller owns, which every session of the
  object borrows.
- The lists are copied into arrays at chapulin's limits, `CH_WEBPKI_ANCHOR_MAX` and
  `CH_ALPN_MAX`. That is one copy per object at setup and none per connection. The same
  values then configure h11, h2 and h3, as 16c rules.
- A server identity types its keys. An ECDSA P-256 private key is `*const [32]u8` and its
  public key `*const [64]u8`, so a key of the wrong size fails to compile. An RSA-PSS private
  key stays `*const anyopaque`, because chapulin's `ch_rsa_priv` is a type of each object.

The alternative refused: `tls` re-exporting each object's chapulin module, so a program writes
one literal per object in chapulin's types. It copies nothing, but a program that speaks h2 and
h3 configures both, with C element types such as `ch_trust_anchor`.

**Confirmed by the owner on 2026-09-27**, for a constraint found in design §8 step 16b: an object
built for a target without the AES instructions carries `SUITE=chacha`, and holds
TLS_CHACHA20_POLY1305_SHA256 alone.
- chapulin refuses `SUITE=aesgcm` with `AES=soft`, whose S-box is indexed with the key (its
  `ct.h`, INV-26).
- ChaCha20-Poly1305 is also the faster AEAD in software. chapulin's `bench/aead.sh` timed a
  1200-byte seal on an AMD EPYC 7763 under Linux, built by gcc 13.3 at `-O2`: 6.04 ns per
  byte for ChaCha20-Poly1305, and 135 for AES-128-GCM over `AES=soft`. chapulin's
  `docs/quic.md` holds the run, under "What the AES axis costs in time, measured".

The alternative refused: AES-GCM in software on those targets. chapulin lets no software AES
hold a traffic key, and its table cipher sealed 17 to 23 times slower than ChaCha20-Poly1305
in that run.

Cost: on such a target, colibri connects to no server that offers AES-GCM alone.

**Amended by the owner on 2026-09-29.** Each object is built `CHACHA=vector` on a
little-endian target with SSE2 on x86 or NEON on Arm, which every x86-64 and arm64 CPU has,
and `CHACHA=portable` on any other, where chapulin refuses the vector path. The path computes
ChaCha20 four blocks at a time in 128-bit vectors (chapulin's entry 82, in the pinned commit
044a49c).
- chapulin timed one 16 KiB record on an Apple M1 Pro that ran other work, in its
  `docs/performance.md`. `rec_seal` took 67.3 µs with the portable loop and 47.6 with the
  vector path under macOS and Apple clang 21, 61.6 and 41.6 in a Linux VM under clang 18, and
  83.7 and 65.6 under gcc 13. chapulin calls these the filter's figures. No x86-64 figure
  exists, and colibri's judge, `bench/run.sh`, lands with design §8 step 13, so no number of
  colibri's admits the change yet.
- The path adds, rotates and exclusive-ors, and reads no table, so it runs in constant time as
  the portable loop does. CBMC cannot read its intrinsics, so chapulin holds it equal to the
  portable loop with tests, 30,771 cases and RFC 8439's vectors, where the loop has a proof.

Not taken with it: `WIDEMUL=native`, which takes the same record to about 27 µs but needs the
builder's statement that the target's widening multiply runs in constant time. It waits for a
ruling of its own.

**Amended by the owner on 2026-09-29, for design §8 step 16e.** On x86-64 and arm64 each
object is built `AES=runtime` (chapulin's entry 81), with `SUITE=aesgcm` and the builder's
statement `CH_NATIVE_AES`. It holds the AES instructions and a fallback, and each session runs
the one its caller's answer names. Any other architecture keeps the build target's choice.
- `values.Client` and `values.Server` require `aes_instructions`: whether the CPU has the AES
  instructions and the carry-less multiply. There is no default. With `absent` a session runs
  ChaCha20 alone, and chapulin refuses a suite order that names AES-GCM.
- colibri probes nothing, as it reads no clock (non-negotiables 1 and 5). A program asks its
  CPU once, at start, through stdx's `platform` module
  ([stdx#15](https://github.com/c4milo/stdx/issues/15)), which the owner exempts from stdx's
  syscall rule, and passes the answer down to each configuration. Until that module exists,
  colibri's tests and programs pass the build target's answer, since each runs where it was
  built.
- `CH_NATIVE_AES` now states that the instructions run in constant time on every x86-64 and
  arm64 part that has them, where it stated that for the build target alone.
- The multiply's timing takes the same shape once chapulin offers an answer for each session
  ([chapulin#186](https://github.com/c4milo/chapulin/issues/186)). Until then colibri keeps
  the decomposed multiply.

The alternatives refused:
- A default from the build target, which a caller that probes overrides.
- The build target's choice on x86-64 and arm64 too.
- A probe inside colibri, exempt from non-negotiable 1.
- For the multiply, `WIDEMUL=native` on every x86-64 and arm64 build, which neither
  architecture promises without Arm's DIT or Intel's DOITM.

**Amended by the owner on 2026-09-30.** stdx's `platform` module landed at stdx `fa53aa4`, and
colibri pins that commit. Each program of `src/testing/` asks its CPU once, through
`src/testing/cpu.zig`, and passes `present` only when `platform.probe()` answers `aes_clmul`
with `yes`; `no` and `not_known` pass `absent`. colibri's package exports `platform` beside
stdx's codecs (decision 101), so a program that depends on colibri reaches it without a
dependency of its own. The tests keep the build target's answer, since a test runs where it was
built.

The alternatives refused: a program that adds stdx as its own dependency to probe, and keeping
the build target's answer in the programs.

**Amended again by the owner on 2026-09-30.** colibri's package no longer exports `platform`,
and `values.Client` and `values.Server` take `cpu`, the `platform.Cpu` the program's one probe
returned, in place of `aes_instructions`. The caller runs the probe, so colibri takes its result
as it is. `tls` imports `platform` for the `Cpu` type alone and never calls `probe()`. A session
runs the AES instructions only when `aes_clmul` is `yes`, and `no` and `not_known` run ChaCha20
alone. The multiply's answer (https://github.com/c4milo/colibri/issues/84) will read `dit` from
the same value, with no second change to the values.
- A program depends on stdx itself, at the commit colibri pins and with the options colibri
  gives it, `.target` and `.release`. Zig then builds one stdx for both, so the program's
  `platform.Cpu` is the type `tls` names. Other options build a second stdx, whose `Cpu` is
  another type, and the program does not compile. `tools/consumer_check.sh` fetches stdx that
  way.

The alternatives refused: keeping the export, which the previous amendment ruled; and keeping
colibri's own `present` or `absent` answer, which each caller would translate from the probe.

**Amended by the owner on 2026-10-09, for chapulin 0.2.0**
(https://github.com/c4milo/colibri/issues/84). chapulin 0.2.0 builds a host object on x86-64
and arm64, which holds every fast path beside the portable code and takes no `AES`, `WIDEMUL` or
`CHACHA` value, and each session picks its paths from the CPU its caller describes (chapulin's
decision 89). Two of chapulin's claims state a timing: that the AES instructions, and the
widening multiply, run in data-independent time in the mode the session's thread runs in. That
mode is PSTATE.DIT on arm64 and DOITM on x86-64, which only the program knows, and which no
program can read on x86-64.
- `tls.Cpu` is the probe and a `tls.Timing`, `not_stated` or `data_independent`, which the
  program states. colibri claims constant-time AES under `data_independent` where the probe's
  `aes_clmul` is `yes`, and the constant-time multiply under `data_independent` alone. Without
  the AES claim a session holds ChaCha20 alone. colibri checks neither statement and sets no
  CPU mode.
- The test programs set PSTATE.DIT on their thread on arm64 where the core has FEAT_DIT, and
  then state the mode. On x86-64 they state it unchecked, so CI's x86-64 job runs the AES-GCM
  suites, which h3spec offers alone. The tests describe every combination.
- Any other target builds chapulin's device object, `SUITE=chacha` over its software AES.

The alternatives refused:
- chapulin's two claims as booleans in `tls.Cpu`, which each program would work out from its
  own probe and mode.
- colibri setting PSTATE.DIT on arm64 around each call into chapulin, which changes the
  thread's CPU mode inside a library call and still needs the program's word on x86-64.
- Test programs that state nothing on x86-64, which run ChaCha20 alone there, so h3spec could
  not pass in CI's x86-64 job.

**Amended again by the owner on 2026-10-09.** The judge's runner, a virtual Neoverse N2, most
likely hides FEAT_DIT from its guest. Its test server then stated no mode and held ChaCha20
alone, and the bench's h2load, which offers AES-256-GCM alone, got no answer on the TLS inputs.
The test programs now state the mode on every arm64 core too. They set PSTATE.DIT first where
the probe finds FEAT_DIT, and state it unchecked where it does not, as on x86-64. The test server
names the CPU it described when it starts in TLS mode, so a log shows what its sessions hold.

The alternatives refused: the bench offering ChaCha20 too, which measures another suite on that
runner than on the competitors and the recorded baselines; and a judge run that only confirms
the cause before the change.

**Amended by the owner on 2026-10-24, for the SHA instructions**
([stdx#19](https://github.com/c4milo/stdx/issues/19)). stdx's probe answers `sha256`, `sha512`
and `sha3` since stdx `f4c20dd`, which colibri pins.
[chapulin#188](https://github.com/c4milo/chapulin/issues/188) measured one TLS 1.3 server
handshake on GitHub's arm64 runner at 1,829,644 user instructions without chapulin's three SHA
claims, and at 1,307,477 with them.
- On arm64 colibri makes each SHA claim under `data_independent` where the probe answers `yes`,
  as it makes the AES claim. chapulin then hashes the transcript, derives the keys and runs
  ML-KEM's hashes on the instructions.
- On x86-64 colibri makes no SHA claim. chapulin refuses the SHA-512 and SHA-3 claims there,
  and its SHA-256 claim needs SSSE3 and SSE4.1 too, which the probe does not answer.

The alternative refused: the SHA-256 claim on x86-64 from the probe's `sha256` alone. A core
that hides SSE4.1 and shows the SHA extensions would fault, and no judge measures x86-64.
