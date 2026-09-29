// The Go peer that sends colibri a record that does not authenticate once a TLS 1.3 handshake is
// complete, and prints what colibri answers. RFC 9846 §5.2 has a receiver whose decryption fails
// end the connection with a "bad_record_mac" alert, and the scripts that run this require Go to
// read that alert rather than an EOF. Nothing here is colibri's code, which is the point.
//
//	go run tools/h2_interop/forged_record.go client <port> <identity-prefix> <alpn>
//	go run tools/h2_interop/forged_record.go server <port> <identity-prefix> <alpn>
//
// As a client it trusts the root tools/h2_interop/tls_identity.go wrote at the prefix and no
// other. As a server it presents the chain and key written there, to one connection, and prints
// "ready" once it listens: a script waits for that line, because a probe of the port would be the
// one connection it takes. Either way it offers <alpn> alone, "h2" or "http/1.1", so the record
// goes to the protocol the script names.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// A TLSCiphertext (RFC 9846 §5.2): the application_data type, legacy_record_version 0x0303, a
// two-octet length, and that many octets. Thirty-two octets hold a content type and the 16-octet
// tag every TLS 1.3 AEAD appends, so the record is long enough to open. No key sealed it, so it
// never authenticates.
var forged = append([]byte{23, 3, 3, 0, 32}, make([]byte, 32)...)

// The name the leaf tls_identity.go mints carries, which the client asks for.
const hostname = "localhost"

// How long it waits for colibri's answer before it reports none.
const answerWait = 10 * time.Second

func main() {
	if len(os.Args) != 5 || (os.Args[1] != "client" && os.Args[1] != "server") {
		log.Fatal("usage: forged_record client|server <port> <identity-prefix> <alpn>")
	}
	role, port, prefix, alpn := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	config := &tls.Config{
		NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS13,
		// As in tls_client.go: X25519 alone keeps the ClientHello small.
		CurvePreferences: []tls.CurveID{tls.X25519},
	}
	var raw net.Conn
	var connection *tls.Conn
	if role == "client" {
		raw, connection = dial(port, prefix, config)
	} else {
		raw, connection = accept(port, prefix, config)
	}
	defer raw.Close()
	if err := connection.Handshake(); err != nil {
		log.Fatalf("handshake failed: %v", err)
	}
	if selected := connection.ConnectionState().NegotiatedProtocol; selected != alpn {
		log.Fatalf("the handshake selected %q, not %q", selected, alpn)
	}
	// Written to the socket under the TLS layer, so no key seals it.
	if _, err := raw.Write(forged); err != nil {
		log.Fatalf("write failed: %v", err)
	}
	fmt.Printf("forged_record: %s %s: %v\n", role, alpn, answer(connection))
}

// Connects to colibri's server, trusting the one root the run minted.
func dial(port, prefix string, config *tls.Config) (net.Conn, *tls.Conn) {
	// tls_identity.go writes the root as raw DER and never PEM.
	caDER, err := os.ReadFile(prefix + ".ca.der")
	if err != nil {
		log.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	config.RootCAs = x509.NewCertPool()
	config.RootCAs.AddCert(ca)
	config.ServerName = hostname
	raw, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal(err)
	}
	return raw, tls.Client(raw, config)
}

// Takes one connection from colibri's client, presenting the chain the run minted.
func accept(port, prefix string, config *tls.Config) (net.Conn, *tls.Conn) {
	identity, err := tls.LoadX509KeyPair(prefix+".chain.pem", prefix+".key.pem")
	if err != nil {
		log.Fatal(err)
	}
	config.Certificates = []tls.Certificate{identity}
	// No ticket follows the handshake (RFC 9846 §4.6.1), so the forged record is the first record
	// the client opens.
	config.SessionTicketsDisabled = true
	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Println("ready")
	os.Stdout.Sync()
	raw, err := listener.Accept()
	if err != nil {
		log.Fatal(err)
	}
	return raw, tls.Server(raw, config)
}

// Reads what colibri sends until a read fails, and returns that failure. Go names an alert it
// read "remote error", and a connection closed with no alert is an EOF.
func answer(connection *tls.Conn) error {
	if err := connection.SetReadDeadline(time.Now().Add(answerWait)); err != nil {
		return err
	}
	buffer := make([]byte, 16384)
	for {
		if _, err := connection.Read(buffer); err != nil {
			return err
		}
	}
}
