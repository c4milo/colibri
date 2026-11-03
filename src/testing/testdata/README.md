# The test identity

The TLS identity the tests of `tls`, `tls_keylog`, `server` and `client` read, and the client
trace run of `sim_run`, through the `testdata` module (`testdata.zig`). It is a CA, a leaf for
`localhost`, and the leaf's key pair. Both certificates are valid from 2026-01-01T00:00:00Z to
2126-01-01T00:00:00Z, so a test may judge the chain at any instant in that range. The private key
is for tests alone.

| File | Holds |
| --- | --- |
| `identity.ca.der` | the CA's certificate, self-signed, as DER |
| `identity.leaf.der` | the leaf's certificate, for `localhost` and 127.0.0.1, signed by the CA, as DER |
| `identity.name` | the CA's Subject Name, as DER: the name a client's anchor holds |
| `identity.spki` | the CA's SubjectPublicKeyInfo, as DER: the key a client's anchor holds |
| `identity.priv` | the leaf's P-256 private scalar, 32 octets |
| `identity.pub` | the leaf's P-256 public point, X then Y, 64 octets, without the 0x04 prefix |
| `identity.chain.pem` | the leaf's and then the CA's certificate, as PEM (RFC 7468) |
| `identity.key.pem` | the leaf's key as a PKCS #8 `PRIVATE KEY` block (RFC 5958) |
| `identity.key.sec1.pem` | the leaf's key as a SEC 1 `EC PRIVATE KEY` block (RFC 5915) |
| `identity.bundle.pem` | the CA's certificate as a CA bundle, after two title lines as curl writes them |
| `identity.mldsa87.chain.pem` | an ML-DSA-87 leaf for `localhost` and 127.0.0.1, and the ML-DSA-87 CA that signed it, as PEM |
| `identity.mldsa87.key.pem` | that leaf's key as a PKCS #8 `PRIVATE KEY` block, seed and expanded key (RFC 9881 §6) |

The certificates have the profile `tools/h2_interop/tls_identity.go` mints, which chapulin's Web
PKI mode accepts:

- Both keys are P-256, and both certificates are signed with ecdsa-with-SHA256.
- The CA has serial 1, a critical keyUsage of digitalSignature and keyCertSign, a critical
  basicConstraints of `CA:TRUE`, and a subjectKeyIdentifier.
- The leaf has serial 2, a critical keyUsage of digitalSignature, an extendedKeyUsage of
  serverAuth, a critical basicConstraints of `CA:FALSE`, an authorityKeyIdentifier that names the
  CA's key, and a subjectAltName of `DNS:localhost` and `IP:127.0.0.1`.
- notBefore is a UTCTime and notAfter a GeneralizedTime. chapulin reads a year before 2050 only
  as a UTCTime, and a year from 2050 on only as a GeneralizedTime.

## How it was made

OpenSSL 3.6.4 made it on 2026-09-28, in an empty directory, with the commands below. The
`-not_before` and `-not_after` options need OpenSSL 3.4 or later. Only the six `identity.*` files
were copied here. `ca.key` and `leaf.key` are not kept: nothing needs the CA's key, and
`identity.priv` holds the leaf's.

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -config /dev/null -subj "/CN=colibri test CA" \
  -set_serial 1 -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=none" \
  -outform DER -out identity.ca.der
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -x509 -new -key leaf.key -sha256 -config /dev/null -subj "/CN=localhost" \
  -CA identity.ca.der -CAkey ca.key \
  -set_serial 2 -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "authorityKeyIdentifier=keyid" \
  -addext "subjectKeyIdentifier=none" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -outform DER -out identity.leaf.der
openssl asn1parse -inform DER -in identity.ca.der -strparse 90 -noout -out identity.name
openssl x509 -inform DER -in identity.ca.der -noout -pubkey |
  openssl pkey -pubin -outform DER -out identity.spki
openssl asn1parse -in leaf.key -strparse 5 -noout -out identity.priv
openssl x509 -inform DER -in identity.leaf.der -noout -pubkey |
  openssl pkey -pubin -outform DER | tail -c 64 > identity.pub
```

The second `openssl req` warns that it does not sign with `-key`. That is intended: it signs with
`-CAkey`, the CA's key, and `-key` names the leaf's key, which the certificate carries.

The last four commands copy raw octets out of the certificates and the leaf's key:

- Offset 90 of the CA's certificate is its subject: the fourth SEQUENCE of its TBSCertificate,
  after the signature algorithm, the issuer and the validity. `openssl asn1parse -inform DER -in
  identity.ca.der` lists each field's offset.
- Offset 5 of `leaf.key` is the OCTET STRING of its private scalar. `openssl asn1parse -in
  leaf.key` lists it.
- A P-256 SubjectPublicKeyInfo ends with the point, X then Y, so its last 64 octets are the point.

Nothing mints this identity again. `tools/h2_interop/tls_identity.go` mints a new one with the
same validity for each script under `tools/` that needs an identity, because those scripts also
need the PEM files that Go, nghttpd and h2o read.

## The PEM files

OpenSSL 4.1.0 made the four PEM files on 2026-10-31 from the files above, for
https://github.com/c4milo/colibri/issues/97. The key's SEC 1 DER is built from `identity.priv` and
`identity.pub`: version 1, the scalar, the prime256v1 OID and the point (RFC 5915 §3). openssl
then writes it as PEM under both labels.

```sh
python3 -I -c 'import sys
p = open("identity.priv", "rb").read(); q = open("identity.pub", "rb").read()
oid = bytes.fromhex("06082a8648ce3d030107")
b = bytes.fromhex("020101") + b"\x04\x20" + p + b"\xa0\x0a" + oid + b"\xa1\x44\x03\x42\x00\x04" + q
sys.stdout.buffer.write(b"\x30" + bytes([len(b)]) + b)' > sec1.der
openssl ec -inform DER -in sec1.der -out identity.key.sec1.pem
openssl pkcs8 -topk8 -nocrypt -in identity.key.sec1.pem -out identity.key.pem
openssl x509 -inform DER -in identity.leaf.der -out leaf.pem
openssl x509 -inform DER -in identity.ca.der -out ca.pem
cat leaf.pem ca.pem > identity.chain.pem
{ printf 'colibri test CA\n===============\n'; cat ca.pem; } > identity.bundle.pem
```

## The ML-DSA-87 identity

OpenSSL 4.1.0 made it on 2026-11-02, in an empty directory, with the commands below (decision 147).
The profile is the P-256 one's, with ML-DSA-87 keys and signatures. Only the two
`identity.mldsa87.*` files were copied here.

```sh
openssl genpkey -algorithm ML-DSA-87 -out ca.key
openssl req -x509 -new -key ca.key -config /dev/null -subj "/CN=colibri test ML-DSA-87 CA" \
  -set_serial 1 -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=none" \
  -out ca.pem
openssl genpkey -algorithm ML-DSA-87 -out identity.mldsa87.key.pem
openssl req -x509 -new -key identity.mldsa87.key.pem -config /dev/null -subj "/CN=localhost" \
  -CA ca.pem -CAkey ca.key \
  -set_serial 2 -not_before 20260101000000Z -not_after 21260101000000Z \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "authorityKeyIdentifier=keyid" \
  -addext "subjectKeyIdentifier=none" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -out leaf.pem
cat leaf.pem ca.pem > identity.mldsa87.chain.pem
```

The leaf's DER is 7,498 octets and the CA's 7,466.
