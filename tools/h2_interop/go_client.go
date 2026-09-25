// The Go peer of tools/h2_server_interop.sh: an h2 client on net/http, standard library alone, in
// cleartext or over TLS 1.3, run against colibri's test-only h2 server. Nothing here is colibri's
// code, which is the point: the run says whether Go's client and colibri's server read RFC 9113
// the same way.
//
//	go run tools/h2_interop/go_client.go <address:port> [<identity-prefix>]
//
// With a prefix it speaks TLS, trusts the root in <identity-prefix>.chain.pem, which
// tools/h2_interop/tls_identity.go wrote, and asks for the name the leaf carries.
//
// It sends every request of its plan at once on one connection: GETs, and a POST whose content is
// past the 65,535-octet window a stream starts with (RFC 9113 §6.9.2), so it finishes only if the
// server sends WINDOW_UPDATE frames. colibri's server answers every request with 200 and
// "colibri\n", and the run requires exactly that of each.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// What colibri's server answers every request with (src/testing/constants.zig).
const expectedBody = "colibri\n"

// The GETs sent at once, fewer than the 100 concurrent streams RFC 9113 §6.5.2 recommends a peer
// allow at least.
const gets = 64

// Octets of the POST's content, whose octet i is i % 251.
const contentLen = 300000
const period = 251

// The name the leaf carries (tools/h2_interop/tls_identity.go).
const hostname = "localhost"

// How long the whole plan may take.
const deadline = 60 * time.Second

func main() {
	if len(os.Args) != 2 && len(os.Args) != 3 {
		log.Fatal("usage: go_client <address:port> [<identity-prefix>]")
	}
	address := os.Args[1]
	client, base := newClient(address)
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	content := make([]byte, contentLen)
	for i := range content {
		content[i] = byte(i % period)
	}
	var wait sync.WaitGroup
	failures := make(chan error, gets+1)
	for i := 0; i < gets; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			failures <- exchange(ctx, client, http.MethodGet, fmt.Sprintf("%s/get/%d", base, i), nil)
		}(i)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		failures <- exchange(ctx, client, http.MethodPost, base+"/post", content)
	}()
	wait.Wait()
	close(failures)
	failed := 0
	for failure := range failures {
		if failure != nil {
			fmt.Println("go_client:", failure)
			failed++
		}
	}
	fmt.Printf("go_client: requests=%d failed=%d\n", gets+1, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// Builds the client for the mode the command line asked for, and the base of every URI.
func newClient(address string) (*http.Client, string) {
	protocols := new(http.Protocols)
	transport := &http.Transport{Protocols: protocols}
	if len(os.Args) == 2 {
		// RFC 9113 §3.3: cleartext h2 with prior knowledge.
		protocols.SetUnencryptedHTTP2(true)
		return &http.Client{Transport: transport}, "http://" + address
	}
	// RFC 9113 §3.2: h2 over TLS, selected by ALPN, which this client offers alone.
	protocols.SetHTTP2(true)
	pem, err := os.ReadFile(os.Args[2] + ".chain.pem")
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		log.Fatal("no certificate in the chain file")
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS13}
	// The URI names the certificate's host, and the dial goes to the address the run gave.
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		log.Fatal(err)
	}
	return &http.Client{Transport: transport}, "https://" + net.JoinHostPort(hostname, port)
}

// Sends one request and requires h2, status 200 and the body colibri's server always sends.
func exchange(ctx context.Context, client *http.Client, method, uri string, content []byte) error {
	var body io.Reader
	if content != nil {
		body = bytes.NewReader(content)
	}
	request, err := http.NewRequestWithContext(ctx, method, uri, body)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, uri, err)
	}
	defer response.Body.Close()
	received, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("%s %s: reading the body: %w", method, uri, err)
	}
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || string(received) != expectedBody {
		return fmt.Errorf("%s %s: %s %d %q", method, uri, response.Proto, response.StatusCode, received)
	}
	return nil
}
