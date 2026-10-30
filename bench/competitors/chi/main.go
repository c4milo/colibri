// Go's net/http with chi, one of the servers of colibri's request benchmark (design §8 step 13f),
// as bench/run.sh --latency starts it: GOMAXPROCS=1, the routes of --routes registered with chi,
// and every route answered with 200 and "ok\n". It serves h11, and h2 in cleartext with prior
// knowledge, on one port. With --h3 it serves h3 instead, on UDP, through quic-go's http3.Server,
// over the TLS identity whose <prefix>.chain.pem and <prefix>.key.pem --tls names. With --tls
// alone it serves h2 over TLS on TCP, and h11 to a client that offers no h2 in ALPN. With --www in
// place of --routes it serves the files of a directory instead, for the bulk downloads of
// bench/run_bulk.sh (design §8 step 13k).
//
//	colibri-bench-chi --port <port> (--routes <routes file> | --www <directory>) [--h3] [--tls <prefix>]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/quic-go/quic-go/http3"
)

var answer = []byte("ok\n")

func ok(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", "3")
	w.Write(answer)
}

// braces writes a pattern's ":name" segments as "{name}", which chi reads.
func braces(path string) string {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		if strings.HasPrefix(s, ":") {
			segments[i] = "{" + s[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

// register registers each route of the routes file with `mux`, answered by ok.
func register(mux *chi.Mux, routes string) {
	file, err := os.Open(routes)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		mux.MethodFunc(parts[0], braces(parts[1]), ok)
	}
	file.Close()
}

func main() {
	port := flag.Int("port", 0, "the port to listen on")
	routes := flag.String("routes", "", "the routes file, one \"METHOD /path\" on each line")
	h3 := flag.Bool("h3", false, "serve h3 on UDP instead of h11 and h2 on TCP")
	tls := flag.String("tls", "", "the prefix of the TLS identity to serve over")
	www := flag.String("www", "", "the directory to serve files from, in place of the routes")
	flag.Parse()
	runtime.GOMAXPROCS(1)
	mux := chi.NewRouter()
	if *www != "" {
		mux.Handle("/*", http.FileServer(http.Dir(*www)))
	} else {
		register(mux, *routes)
	}
	if *h3 {
		serveH3(*port, *tls, mux)
		return
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		panic(err)
	}
	fmt.Printf("listening on port %d\n", listener.Addr().(*net.TCPAddr).Port)
	server := &http.Server{Handler: mux}
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

// serveH3 serves h3 on UDP port `port` through quic-go, until the process is stopped.
func serveH3(port int, prefix string, handler http.Handler) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		panic(err)
	}
	fmt.Printf("listening on port %d\n", conn.LocalAddr().(*net.UDPAddr).Port)
	server := &http3.Server{Handler: handler}
	if err := server.ServeListener(listenerOf(conn, prefix)); err != nil {
		panic(err)
	}
}
