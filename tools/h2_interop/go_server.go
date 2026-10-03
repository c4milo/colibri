// The Go peer of tools/h2_interop.sh and tools/h11_interop.sh: an h2 server on net/http, or with
// -h11 an HTTP/1.1 one, standard library alone, in cleartext or over TLS 1.3. It serves what the
// client's plan asks for, and nothing here is colibri's code, which is the point: the run says
// whether colibri's client and Go's server read RFC 9113 and RFC 9112 the same way.
//
//	go run tools/h2_interop/go_server.go [-h11] [-gzip] <port> [<identity-prefix>]
//
// With a prefix it serves TLS with the chain and key tools/h2_interop/tls_identity.go wrote there.
// With -h11 over TLS it offers ALPN "http/1.1" alone, so it selects that when a client offers
// "h2" too. With -gzip it codes each answer in gzip when the request accepts it (RFC 9110
// §12.5.3), for colibri's client to decode (decision 101).
package main

import (
	"compress/gzip"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

// Octets /large answers with: sixteen times the 65,535-octet window a stream starts with
// (RFC 9113 §6.9.2), so the response finishes only if the client sends WINDOW_UPDATE frames.
const largeLen = 1 << 20

// The period of the content /large answers with, the same prime the client's requests use.
const period = 251

func main() {
	h11 := flag.Bool("h11", false, "serve HTTP/1.1 alone (RFC 9112) instead of h2")
	coded := flag.Bool("gzip", false, "code each answer in gzip when the request accepts it")
	flag.Parse()
	arguments := flag.Args()
	if len(arguments) != 1 && len(arguments) != 2 {
		log.Fatal("usage: go_server [-h11] <port> [<identity-prefix>]")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "colibri\n")
	})
	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		content := make([]byte, largeLen)
		for i := range content {
			content[i] = byte(i % period)
		}
		w.Header().Set("Content-Length", fmt.Sprint(largeLen))
		w.Write(content)
	})
	// Echoes the request content while it is still arriving, so both directions' flow control
	// windows are in use at once (RFC 9113 §5.2).
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).EnableFullDuplex()
		w.WriteHeader(http.StatusOK)
		io.Copy(w, r.Body)
	})
	// An interim response before the final one (RFC 9110 §15.2, RFC 9113 §8.1).
	mux.HandleFunc("/interim", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		fmt.Fprint(w, "colibri\n")
	})
	// A trailer section after the content (RFC 9110 §6.5, RFC 9113 §8.1).
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checked")
		fmt.Fprint(w, "colibri\n")
		w.Header().Set("X-Checked", "yes")
	})
	mux.HandleFunc("/missing", http.NotFound)

	var handler http.Handler = mux
	if *coded {
		handler = gzipped(mux)
	}
	protocols := new(http.Protocols)
	server := &http.Server{Addr: "127.0.0.1:" + arguments[0], Handler: handler, Protocols: protocols}
	if *h11 {
		// RFC 9112, in cleartext, and over TLS selected by ALPN, which this server offers alone.
		protocols.SetHTTP1(true)
	} else if len(arguments) == 1 {
		// RFC 9113 §3.3: cleartext h2 with prior knowledge.
		protocols.SetUnencryptedHTTP2(true)
	} else {
		// RFC 9113 §3.2: h2 over TLS, selected by ALPN, which this server offers alone.
		protocols.SetHTTP2(true)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
	// A script reads the port from this line and connects once it is out. With a port of 0 the
	// kernel chose it (https://github.com/c4milo/colibri/issues/94).
	fmt.Printf("go_server: listening on port %d\n", listener.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()
	if len(arguments) == 1 {
		log.Fatal(server.Serve(listener))
	}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	prefix := arguments[1]
	log.Fatal(server.ServeTLS(listener, prefix+".chain.pem", prefix+".key.pem"))
}

// Codes each answer in gzip when its request's Accept-Encoding names gzip, which net/http leaves
// to the handler. The coded content has a length no handler knows, so a Content-Length a handler
// set goes (RFC 9110 §8.6), and Vary names the field that chose the coding (§12.5.5).
func gzipped(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		coder := gzip.NewWriter(w)
		defer coder.Close()
		next.ServeHTTP(&gzipWriter{ResponseWriter: w, coder: coder}, r)
	})
}

type gzipWriter struct {
	http.ResponseWriter
	coder *gzip.Writer
}

func (writer *gzipWriter) WriteHeader(status int) {
	writer.Header().Del("Content-Length")
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *gzipWriter) Write(content []byte) (int, error) {
	writer.Header().Del("Content-Length")
	return writer.coder.Write(content)
}
