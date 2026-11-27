# Design §8 step 33: CNSA 2.0 on the server

[Design §8, the build plan](../../design.md#8-build-plan)

The owner ruled on 2026-11-01 that colibri's server always holds CNSA 2.0's algorithms, and selects
them first when a client offers them ([#115](https://github.com/c4milo/colibri/issues/115)).
chapulin's `ROLE=both TRUST=webpki` object does the selection, so the step adds no build option. It
lands in four parts, as chapulin's commits land:
- **33a, ML-KEM-1024 first.** chapulin `7d8064dd` (its decisions 177 and 179) makes the server
  select ML-KEM-1024 (0x0202) whenever the client lists it, then its older order. colibri
  pins it. No colibri API changes: `tls_provider.Negotiated.group` already carries the code
  point. `tools/tls_openssl.sh` runs OpenSSL's s_client over TCP and over QUIC.
  - **Check met, 2026-11-02,** on macOS 26 on arm64 with OpenSSL 4.1.0. Over TCP and QUIC
    alike: `MLKEM1024` gets 0x0202 in one ServerHello; `X25519MLKEM768:MLKEM1024` gets a
    HelloRetryRequest for 0x0202 and then 0x0202; `X25519MLKEM768` gets 0x11ec; `x25519` gets
    0x001d. The suite was TLS_AES_256_GCM_SHA384 in each.
  - 1 mutation **CAUGHT**: the previous pin, chapulin `f59c7e3f`, refused the client that sent
    only an ML-KEM-1024 share.
- **33b, TLS_AES_256_GCM_SHA384 first.** chapulin's step 3 needed no code: a host object whose
  session sets `CH_CPU_CONSTANT_TIME_AES` prefers TLS_AES_256_GCM_SHA384, then AES-128-GCM, then
  ChaCha20 (its decision 80). colibri sets that bit where the program's probe finds the AES
  instructions and states their timing (decision 97 as amended). `tools/tls_openssl.sh` requires
  0x1302 for a client that lists TLS_AES_128_GCM_SHA256 first, and 0x1301 for one that lists it
  alone.
- **33c, one identity shape, and ML-DSA-87.** [Decision 147](../../decisions/0147-a-servers-identities-are-one-shape.md). chapulin
  `2b0c5c9e` (its decision 180) adds the `mldsa87` slot to every host server object.
  - **The public names of `tls`,** each listed in a test beside the root before the code
    (decision 115). A server that holds an ML-DSA-87 identity needs each one, as a server with
    a P-256 identity does:
    - `SignatureScheme`, an enum of RFC 9846 §4.3.3 code points: `ecdsa_secp256r1_sha256`,
      0x0403, and `mldsa87`, 0x0906 (draft-ietf-tls-mldsa-05 §3).
    - `Key`: `scheme`, `private_key` and `public_key`, in room for the largest key, and `wipe`.
    - `Identity`: `chain` and `key`.
    - `Server.identities`, in place of `Server.ecdsa_p256` and `Server.rsa_pss`.
    - `pem.key(cpu, file, leaf, key)`, in place of `pem.p256_key`.
    - `constants.protocol.mldsa87_public_key_len`, 2,592, and `mldsa87_private_key_len`, 4,896
      (RFC 9881 §4 and §6).
    - Removed: `EcdsaP256Identity`, `RsaPssIdentity`, `P256Key` and `pem.p256_key`.
  - **The rules.** One identity for each scheme. A second one of a scheme, or a scheme the
    object does not hold, refuses the configuration. RSA-PSS returns as a scheme once chapulin
    reads an RSA key from PEM.
  - **The checks.** `tls.pem.key` reads the P-256 and the ML-DSA-87 test keys, and refuses a key
    the leaf does not carry. `tools/tls_openssl.sh` requires ML-DSA-87 when OpenSSL offers it
    and ECDSA P-256 when it offers that alone, over TCP and QUIC.
  - **What the build found.** An ML-DSA-87 flight is about 20,000 bytes: two certificates of
    about 7,500 and a CertificateVerify of 4,631. `tls-accept` wrote its flight into a buffer of
    one record, 18 KiB, and failed with `OutputTooSmall`. Its output now holds
    `tls_flight_len_max`, whose rest grows from 4 KiB to 8 KiB.
  - **Check met, 2026-11-02,** on macOS 26 on arm64 with OpenSSL 4.1.0. `tools/tls_openssl.sh`
    ran 8 cases over TCP and 8 over QUIC against servers that hold both identities, and each
    printed what its case requires: groups 0x0202 for `MLKEM1024`, 0x0202 then 0x0202 for
    `X25519MLKEM768:MLKEM1024`, 0x11ec and 0x001d for the older groups; suite 0x1302 for
    `TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384` and 0x1301 for `TLS_AES_128_GCM_SHA256`;
    signature 0x0906 for `ecdsa_secp256r1_sha256:mldsa87` and 0x0403 for
    `ecdsa_secp256r1_sha256`.
  - **The cost.** chapulin `2b0c5c9e` grows each session: `tls.record.Server` from 49,160 to
    49,464 bytes, `tls.quic.Server` from 100,736 to 101,080, and `server.Endpoint` at its
    default capacity from 52,422,848 to 52,433,296. A `tls.Key` holds 7,488 bytes of keys.
  - 8 mutations **CAUGHT**: the ML-DSA-87 slot never set, a repeated P-256 identity allowed, a
    repeated ML-DSA-87 identity allowed (NOT CAUGHT first; its test was then added), an unfilled
    key taken as P-256, `pem.key` reading no ML-DSA-87 key, naming an ML-DSA-87 key P-256, or
    leaving a P-256 key's scheme unset, and `Key.wipe` leaving the secret.
- **33d, RSA-PSS from PEM.** [Decision 147](../../decisions/0147-a-servers-identities-are-one-shape.md) as amended on 2026-11-03. chapulin
  `965668d2` (its decision 184) adds `ch_rsa_key_from_pem`.
  - **The public names.** `SignatureScheme` gains `rsa_pss_rsae_sha256`, 0x0804 (RFC 9846
    §4.3.3). A server that presents an RSA certificate needs it. No other name changes.
  - **The rules.** `pem.key` tries P-256, then RSA, then ML-DSA-87. It copies chapulin's
    `ch_rsa_priv`, 2,312 bytes in a host object, into the start of `Key.private_key`, and the
    modulus into `Key.public_key`. The private room is aligned to a machine word, as
    `ch_rsa_priv` holds a `size_t`. chapulin signs with ML-DSA-87 first, then with ECDSA P-256,
    and with RSA-PSS when the client offers neither.
  - **The checks.** `tls.pem.key` reads the RSA-3072 test key of `src/testing/testdata/` and
    refuses it under the P-256 leaf. A server holds all three identities, chapulin's check signs
    with each, and a second RSA identity is refused. `tls-accept` and the UDP server take
    `rsa=<prefix>`. `tools/tls_openssl.sh` requires 0x0804 for `rsa_pss_rsae_sha256` alone and
    0x0403 for `rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256`.
  - **Check met, 2026-11-03,** on macOS 26 on arm64 with OpenSSL 4.1.0. `tools/tls_openssl.sh`
    ran 10 cases over TCP and 10 over QUIC against servers that hold the three identities, and
    each printed what its case requires. `zig build test-tls test-tls-keylog -Dcpu=generic`
    passed 172 of 172 tests.
  - **The cost.** None: `zig build bench-memory` prints the table of step 33c.
  - 8 mutations **CAUGHT**: `pem.key` reading no RSA key, naming an RSA key P-256, copying no
    modulus, or copying no private key; a repeated RSA identity allowed; the modulus cut short;
    the RSA slot never set; and `tls-accept` ignoring `rsa=`, which `tools/tls_openssl.sh`
    caught.
- **33e, the CRYPTO send window forgets only acknowledged bytes, 2026-11-06.** GitHub CI run
  42315963013 failed `tools/tls_openssl.sh` in its `checks` job, on GitHub's `ubuntu-26.04`
  x86-64 runner. Over QUIC, the case `X25519MLKEM768:MLKEM1024` with the ML-DSA-87 identity did
  not finish in 10 s. The UDP server stopped with `a deadline failed: CryptoForgotten`. In an
  Ubuntu 26.04 arm64 container on the development machine, this happened once in about 58 runs.
  - **The cause.** The ML-DSA-87 Handshake flight is about 20,000 bytes, which is more than
    `crypto_send_buffer_len`. When its window was full, `CryptoStream.send_room` forgot every
    byte already framed, whether the peer acknowledged it or not. A PTO before the client's
    first ACK then declared every Handshake packet lost (decision 64), the first one included.
    Its bytes were no longer in the window, so `on_lost` returned false and the connection
    closed. RFC 9000 §13.3 sends CRYPTO data again "until all data has been acknowledged".
  - **The change.** The entry of `fd97a12` above planned this change. When the
    window is full, `connection_crypto.write_crypto` finds the lowest Offset of a CRYPTO frame
    in a packet still in flight at the level. `CryptoStream.forget_acknowledged` forgets only
    bytes below that Offset and below `sent_len`, and asserts that no packet in flight holds a
    forgotten byte (INV-34). A flight longer than the window now waits for acknowledgments
    before its last bytes go out. `crypto_send_buffer_len` does not change.
  - **The checks.** `connection_crypto_window_test.zig` sends a 20,000-byte flight through
    `write_crypto`. A PTO before any ACK must send it again from offset 0, which failed with
    `CryptoForgotten` before the change. An ACK must free the window, so the rest of a
    40,000-byte flight goes out. A loss by the packet threshold must keep the bytes of a
    resend while older packets with higher Offsets are still in flight.
  - **Check met, 2026-11-06,** in an Ubuntu 26.04 arm64 container with OpenSSL 3.5.5: one UDP
    server took 300 runs of the case that failed, with 0 stalls and at most 831 ms a run.
    On the development machine, macOS 26.6.2 on arm64, `zig build test` passed 3878 of 3878
    tests. `zig build test-sim-run-quic` returned 0. `tools/tls_openssl.sh` with OpenSSL 3.5
    printed `tls_openssl: ok`, and `tools/quic_udp.sh` printed `quic_udp: ok`.
  - 8 mutations, each **CAUGHT** by `zig build test-quic`: the old window that forgot what it
    framed; `sent_len` ignored; no record read as CRYPTO; nothing forgotten with no packet in
    flight; nothing forgotten at all; bytes forgotten while the window has room; the highest
    Offset in flight in place of the lowest; and the Offset of the oldest packet in flight in
    place of the lowest, which a review found and the third test catches. `zig build
    test-sim-run-quic` caught none of the first seven, because the null provider's flights fit
    the window.
