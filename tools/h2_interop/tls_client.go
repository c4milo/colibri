// The TLS peer of tools/tls_accept.sh: a TLS 1.3 client on the standard library alone, which
// connects to colibri's chapulin-backed server, pins the one root the run minted, and reports what
// the handshake negotiated. It then sends one record and reads the echo back, so the run exercises
// the record phase and not only the handshake.
//
// Nothing here is colibri's code, which is the point: the run says whether colibri's server and
// Go's client complete a TLS 1.3 handshake, agree on ALPN, and move application data.
//
//	go run tools/h2_interop/tls_client.go <port> <identity-prefix> <hostname>
//
// It reads <identity-prefix>.ca.der, the raw DER of the root tls_identity.go minted, and trusts
// that root and no other.
//
// One environment note: GOFIPS140=on drops TLS_CHACHA20_POLY1305_SHA256 from the client's offer,
// and that is the one suite a chapulin server has, so the handshake would fail with no suite in
// common. The check needs FIPS mode off, which is Go's default.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

// What the client sends and expects back. The server echoes the octets it opened.
var probe = []byte("colibri record phase\n")

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: tls_client <port> <identity-prefix> <hostname>")
	}
	port, prefix, hostname := os.Args[1], os.Args[2], os.Args[3]

	// The root the run minted, as raw DER. tls_identity.go writes DER and never PEM, so this
	// parses the certificate rather than calling AppendCertsFromPEM.
	caDER, err := os.ReadFile(prefix + ".ca.der")
	if err != nil {
		log.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	config := &tls.Config{
		RootCAs:    pool,
		ServerName: hostname,
		// RFC 9113 §3.1: h2 over TLS is selected by ALPN, and this client offers it alone.
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// Go prefers the X25519MLKEM768 hybrid and sends a fallback X25519 share beside it, which
		// a chapulin server can use. Pinning X25519 keeps the ClientHello small enough that the
		// server's receive buffer is never the thing under test.
		CurvePreferences: []tls.CurveID{tls.X25519},
	}

	connection, err := tls.Dial("tcp", "127.0.0.1:"+port, config)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	defer connection.Close()

	state := connection.ConnectionState()
	fmt.Printf("tls_client: complete alpn=%s version=0x%04x suite=0x%04x\n",
		state.NegotiatedProtocol, state.Version, state.CipherSuite)
	// A completed handshake is not proof of ALPN: Go's client does not fail when the server
	// selects no protocol, so the check asserts it here.
	if state.NegotiatedProtocol != "h2" {
		log.Fatalf("the server selected %q, not h2", state.NegotiatedProtocol)
	}
	if state.Version != tls.VersionTLS13 {
		log.Fatalf("the server negotiated 0x%04x, not TLS 1.3", state.Version)
	}

	// One record each way, which is what proves the server's record phase rather than its
	// handshake. The server echoes what it opened.
	if _, err := connection.Write(probe); err != nil {
		log.Fatalf("write failed: %v", err)
	}
	echoed := make([]byte, len(probe))
	if _, err := readFull(connection, echoed); err != nil {
		log.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(echoed, probe) {
		log.Fatalf("the server echoed %q, not %q", echoed, probe)
	}
	fmt.Println("tls_client: the server echoed the record")

	// RFC 9846 §6.1: each party sends close_notify before closing its write side. This is what
	// the server must report as the end of the peer's data rather than as a failure.
	if err := connection.CloseWrite(); err != nil {
		log.Fatalf("close_notify failed: %v", err)
	}
	fmt.Println("tls_client: ok")
}

// Reads until the buffer is full. One record may arrive as several reads.
func readFull(connection *tls.Conn, into []byte) (int, error) {
	read := 0
	for read < len(into) {
		n, err := connection.Read(into[read:])
		if n > 0 {
			read += n
		}
		if err != nil {
			return read, err
		}
	}
	return read, nil
}
