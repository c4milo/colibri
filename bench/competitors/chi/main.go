// Go's net/http with chi, one of the servers of colibri's request benchmark (design §8 step 13f),
// as bench/run.sh --latency starts it: GOMAXPROCS=1, the routes of --routes registered with chi,
// and every route answered with 200 and "ok\n". It serves h11, and h2 in cleartext with prior
// knowledge, on one port.
//
//	colibri-bench-chi --port <port> --routes <routes file>
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

func main() {
	port := flag.Int("port", 0, "the port to listen on")
	routes := flag.String("routes", "", "the routes file, one \"METHOD /path\" on each line")
	flag.Parse()
	runtime.GOMAXPROCS(1)
	file, err := os.Open(*routes)
	if err != nil {
		panic(err)
	}
	mux := chi.NewRouter()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		mux.MethodFunc(parts[0], braces(parts[1]), ok)
	}
	file.Close()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		panic(err)
	}
	fmt.Printf("listening on port %d\n", listener.Addr().(*net.TCPAddr).Port)
	server := &http.Server{Handler: mux}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server.Protocols = &protocols
	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
