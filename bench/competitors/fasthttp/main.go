// fasthttp, Go's fastest h11 server outside the standard library, one of the competitors of
// bench/run.sh --competitors (design §8 step 13o). It answers every request with 200 and
// "colibri\n", which colibri's test-only server answers too, with GOMAXPROCS=1, since the judge
// pins it to one core. It speaks h11 alone, in cleartext, and with --tls over the identity whose
// <prefix>.chain.pem and <prefix>.key.pem --tls names.
//
//	colibri-bench-fasthttp --port <port> [--tls <prefix>]
package main

import (
	"flag"
	"fmt"
	"net"
	"runtime"

	"github.com/valyala/fasthttp"
)

var answer = []byte("colibri\n")

func colibri(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("text/plain; charset=utf-8")
	ctx.SetBody(answer)
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
	server := &fasthttp.Server{Handler: colibri, Name: "fasthttp"}
	if *tls != "" {
		err = server.ServeTLS(listener, *tls+".chain.pem", *tls+".key.pem")
	} else {
		err = server.Serve(listener)
	}
	if err != nil {
		panic(err)
	}
}
