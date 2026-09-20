// Mints the signing identity colibri's TLS server hands chapulin, for tools/h2spec.sh's TLS mode.
//
//	go run tools/h2_interop/tls_identity.go <prefix>
//
// A chapulin server provisions one identity per signature scheme. This writes the
// ecdsa_secp256r1_sha256 one, which srv_cfg.h describes as a 32-byte big-endian private scalar
// and a 64-byte uncompressed public point, with the end-entity certificate first in the chain.
//
// Five files, all raw DER or raw octets, never PEM, because chapulin reads bytes and parses no
// container:
//
//	<prefix>.leaf.der   the end-entity certificate
//	<prefix>.ca.der     the root that signed it, second in the chain
//	<prefix>.priv       the 32-byte private scalar
//	<prefix>.pub        the 64-byte uncompressed point X||Y
//	<prefix>.name       the root's Subject Name DER, for a client that pins it
//	<prefix>.spki       the root's SubjectPublicKeyInfo DER, likewise
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// What srv_cfg.h fixes for the ecdsa_p256 slot.
const (
	privLen = 32
	pubLen  = 64
)

const validity = 24 * time.Hour
const hostname = "localhost"

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: tls_identity <prefix>")
	}
	prefix := os.Args[1]

	caKey, caDER := mint(nil, nil, "colibri test CA", true)
	leafKey, leafDER := mint(caKey, caDER, hostname, false)

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// The private scalar, left-padded to 32 octets. FillBytes does the padding, which matters
	// because a scalar with leading zero bytes is shorter than the fixed length chapulin reads.
	priv := make([]byte, privLen)
	leafKey.D.FillBytes(priv)

	// The uncompressed point without its 0x04 prefix: chapulin reads X||Y and nothing else.
	pub := make([]byte, pubLen)
	leafKey.X.FillBytes(pub[:privLen])
	leafKey.Y.FillBytes(pub[privLen:])

	write(prefix+".leaf.der", leafDER)
	write(prefix+".ca.der", caDER)
	write(prefix+".priv", priv)
	write(prefix+".pub", pub)
	write(prefix+".name", caCert.RawSubject)
	write(prefix+".spki", spki)
}

// Mints one certificate. With no parent it is a self-signed root.
func mint(parentKey *ecdsa.PrivateKey, parentDER []byte, name string, isCA bool) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial := big.NewInt(1)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		BasicConstraintsValid: true,
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		template.SerialNumber = big.NewInt(2)
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{hostname}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	parent, signer := template, key
	if parentDER != nil {
		parsed, err := x509.ParseCertificate(parentDER)
		if err != nil {
			log.Fatal(err)
		}
		parent, signer = parsed, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		log.Fatal(err)
	}
	return key, der
}

func write(path string, octets []byte) {
	if err := os.WriteFile(path, octets, 0o600); err != nil {
		log.Fatal(err)
	}
}
