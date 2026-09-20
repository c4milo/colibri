// The TLS peer of tools/tls_handshake.sh: an h2 server over TLS 1.3 on net/http, standard
// library alone. It mints its own CA and a leaf signed by it, serves the chain, and writes the
// CA's SubjectPublicKeyInfo where colibri can read it as a trust anchor.
//
// Nothing here is colibri's code, which is the point: the run says whether colibri's client and
// Go's server complete a TLS 1.3 handshake and agree on ALPN.
//
//	go run tools/h2_interop/tls_server.go <port> <anchor-prefix>
//
// It writes two files: <anchor-prefix>.name, the CA's Subject Name DER, and <anchor-prefix>.spki,
// its SubjectPublicKeyInfo DER. A chapulin trust anchor carries both.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

// The modulus size of both keys. RFC 8446 admits more, and chapulin's default RSA bound is 384
// octets, so 2048 bits stays inside it.
const modulusBits = 2048

// How long the two certificates are valid. Long enough that a run never straddles the edge.
const validity = 24 * time.Hour

// The name the leaf carries and the client asks for.
const hostname = "localhost"

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: tls_server <port> <anchor-prefix>")
	}
	port, prefix := os.Args[1], os.Args[2]

	caKey, caDER := mintCA()
	leafCert := mintLeaf(caKey, caDER)

	// The anchor colibri pins. A chapulin trust anchor is the root's Subject Name DER and its
	// SubjectPublicKeyInfo DER, each the whole TLV. Both are written before the listener opens,
	// so the client never races the files.
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(prefix+".name", caCert.RawSubject, 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(prefix+".spki", spki, 0o600); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "colibri\n")
	})
	server := &http.Server{
		Addr:    "127.0.0.1:" + port,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{leafCert},
			// RFC 9113 §3.1: h2 over TLS is selected by ALPN, and this server offers it alone,
			// so a client that cannot negotiate it fails the handshake rather than the request.
			NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS13,
		},
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ready")
	os.Stdout.Sync()
	log.Fatal(server.ServeTLS(listener, "", ""))
}

// Mints the root the client will trust.
func mintCA() (*rsa.PrivateKey, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, modulusBits)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "colibri test CA"},
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return key, der
}

// Mints the leaf the server presents, signed by the CA.
func mintLeaf(caKey *rsa.PrivateKey, caDER []byte) tls.Certificate {
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, modulusBits)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-validity),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	// The chain the server sends: the leaf, then the CA that signed it.
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}
