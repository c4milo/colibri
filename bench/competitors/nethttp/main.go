// Go's own net/http server, one of the competitors of bench/run.sh --competitors (design §8 step
// 13o), as nginx, h2o and hyper are. It answers every request with 200 and "colibri\n", which
// colibri's test-only server answers too, with GOMAXPROCS=1, since the judge pins it to one core.
// It serves h11, and h2 in cleartext with prior knowledge, on one port. With --tls it serves h2
// over TLS, and h11 to a client that offers no h2 in ALPN, over the identity whose
// <prefix>.chain.pem and <prefix>.key.pem --tls names.
//
//	colibri-bench-nethttp --port <port> [--tls <prefix>]
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"runtime"
)

var answer = []byte("colibri\n")

func colibri(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "8")
	w.Write(answer)
}

func main() {
	port := flag.Int("port", 0, "the port to listen on")
	tls := flag.String("tls", "", "the prefix of the TLS identity to serve over")
	flag.Parse()
	runtime.GOMAXPROCS(1)
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		panic(err)
	}
	fmt.Printf("listening on port %d\n", listener.Addr().(*net.TCPAddr).Port)
	server := &http.Server{Handler: http.HandlerFunc(colibri)}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	protocols.SetHTTP2(true)
	server.Protocols = &protocols
	if *tls != "" {
		err = server.ServeTLS(listener, *tls+".chain.pem", *tls+".key.pem")
	} else {
		err = server.Serve(listener)
	}
	if err != nil {
		panic(err)
	}
}
