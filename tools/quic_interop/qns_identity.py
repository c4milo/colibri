"""Converts the QUIC Interop Runner's /certs into the files colibri's quic-udp endpoint reads.

    qns_identity.py <certs-directory> <prefix>

The runner writes PEM (its certs.sh): cert.pem holds the end-entity certificate and the
intermediates above it, ca.pem the root, and priv.key the end-entity's P-256 key in SEC 1 form.
The endpoint reads raw octets, the form tools/h2_interop/tls_identity.go writes, because chapulin
parses no container:

    <prefix>.chain.<i>.der  each certificate of cert.pem, the end-entity first
    <prefix>.priv           the 32-octet private scalar
    <prefix>.pub            the 64-octet public point X||Y
    <prefix>.name           the root's Subject Name DER, which a client pins
    <prefix>.spki           the root's SubjectPublicKeyInfo DER, likewise

It uses the standard library alone, and reads DER as RFC 5280 §4.1 and SEC 1 §C.4 lay it out.
"""
import base64
import sys

SEQUENCE = 0x30
OCTET_STRING = 0x04
BIT_STRING = 0x03
CONTEXT_0 = 0xA0
CONTEXT_1 = 0xA1
UNCOMPRESSED_POINT = 0x04
SCALAR_LEN = 32


def pem_blocks(text, label):
    """The DER of every PEM block of type `label`, in order."""
    blocks, inside, lines = [], False, []
    for line in text.splitlines():
        if line.strip() == f"-----BEGIN {label}-----":
            inside, lines = True, []
        elif line.strip() == f"-----END {label}-----":
            blocks.append(base64.b64decode("".join(lines)))
            inside = False
        elif inside:
            lines.append(line.strip())
    return blocks


def tlv(der, at):
    """The tag at `at`, where its contents start, and where the element ends."""
    tag, length_octet = der[at], der[at + 1]
    if length_octet < 0x80:
        return tag, at + 2, at + 2 + length_octet
    count = length_octet & 0x7F
    length = int.from_bytes(der[at + 2 : at + 2 + count], "big")
    start = at + 2 + count
    return tag, start, start + length


def children(der, at):
    """The (tag, element start, content start, end) of each element inside the one at `at`."""
    _, start, end = tlv(der, at)
    found, position = [], start
    while position < end:
        tag, content, element_end = tlv(der, position)
        found.append((tag, position, content, element_end))
        position = element_end
    return found


def root_name_and_spki(certificate):
    """RFC 5280 §4.1: the subject is the TBSCertificate's sixth field and the key its seventh,
    counting the optional [0] version as the first."""
    tbs = children(certificate, 0)[0]
    fields = children(certificate, tbs[1])
    if fields[0][0] != CONTEXT_0:
        fields = [None] + fields
    subject, spki = fields[5], fields[6]
    return certificate[subject[1] : subject[3]], certificate[spki[1] : spki[3]]


def scalar_and_point(key):
    """SEC 1 §C.4: ECPrivateKey is version, the private key, [0] the curve, [1] the public key."""
    fields = children(key, 0)
    private = next(key[f[2] : f[3]] for f in fields if f[0] == OCTET_STRING)
    public_field = next(f for f in fields if f[0] == CONTEXT_1)
    bit_string = children(key, public_field[1])[0]
    point = key[bit_string[2] + 1 : bit_string[3]]  # past the unused-bits octet
    if point[0] != UNCOMPRESSED_POINT:
        raise ValueError("the public key is not an uncompressed point")
    return private.rjust(SCALAR_LEN, b"\0")[-SCALAR_LEN:], point[1:]


def main():
    certs, prefix = sys.argv[1], sys.argv[2]
    chain = pem_blocks(open(f"{certs}/cert.pem").read(), "CERTIFICATE")
    for index, certificate in enumerate(chain):
        open(f"{prefix}.chain.{index}.der", "wb").write(certificate)
    root = pem_blocks(open(f"{certs}/ca.pem").read(), "CERTIFICATE")[0]
    name, spki = root_name_and_spki(root)
    open(f"{prefix}.name", "wb").write(name)
    open(f"{prefix}.spki", "wb").write(spki)
    key = pem_blocks(open(f"{certs}/priv.key").read(), "EC PRIVATE KEY")[0]
    scalar, point = scalar_and_point(key)
    open(f"{prefix}.priv", "wb").write(scalar)
    open(f"{prefix}.pub", "wb").write(point)
    print(f"qns_identity: {len(chain)} certificates, root pinned")


if __name__ == "__main__":
    main()
